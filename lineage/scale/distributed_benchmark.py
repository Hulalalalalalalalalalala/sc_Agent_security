"""20+ Node Distributed Scale & Decentralized Audit Benchmark (`distributed_benchmark.py`).

Empirically evaluates Platform v2 across `N in {4, 12, 24}` live peer HTTP/Sidecar nodes
spanning 4 autonomous trust domains (`org-alpha.io`, `org-beta.io`, `org-gamma.io`,
`org-delta.io`) with:
- 1 Untrusted Public Yellow Pages (`AgentDirectoryService(registry_mode='centralized')`)
  holding ONLY signed `AgentCard`s (zero private keys, zero auth state, zero audit logs);
- 0 Centralized `AuditCollectorService` — every peer Sidecar and Domain CA stores signed,
  hash-chained `AuditEntry` records strictly in its own `LocalAuditStore`;
- Side-by-side multi-hop workflow comparison:
  `oauth_centralized` vs. `oauth_federated` vs. `lct`;
- Full `N`-node cross-domain cascading revocation convergence measurement;
- Stateless on-demand `DistributedAuditor` BFS pull latency & `100.0%` DAG reconstruction!
"""

from __future__ import annotations

import argparse
import concurrent.futures
from dataclasses import dataclass
import json
import math
from pathlib import Path
import secrets
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
import uuid

import httpx

from lineage.audit import (
    AuditEventType,
    AuditStreamEmitter,
    DistributedAuditor,
)
from lineage.common.crypto import redact_sensitive
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.identity import TrustBundleResolver, TrustDomainCA, WorkloadIdentity
from lineage.oauth_sts import (
    OIDCTokenVerifier,
    OAuthSTSService,
    OAuthTokenExchangeClient,
    spiffe_id_to_oauth_client_id,
)
from lineage.protocol import (
    PermissionLattice,
    compute_branch_idempotency_key,
    create_dpop_proof,
    mint_root_token,
)
from lineage.registry import AgentCard, AgentDirectoryClient, AgentDirectoryService
from lineage.revocation import RevocationReplicaClient, RevocationService
from lineage.sidecar import LineageSidecar
from lineage.verifier import VerificationMode
from lineage.workspace_agents.peer_apps import IdempotencyLedger, WorkspaceSidecarClient

BENCH_DOMAINS: Tuple[str, ...] = (
    "org-alpha.io",
    "org-beta.io",
    "org-gamma.io",
    "org-delta.io",
)


def _percentile(sorted_vals: Sequence[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return round(float(sorted_vals[0]), 2)
    rank = (pct / 100.0) * (len(sorted_vals) - 1)
    lo = int(math.floor(rank))
    hi = int(math.ceil(rank))
    if lo == hi:
        return round(float(sorted_vals[lo]), 2)
    frac = rank - lo
    return round(float(sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac), 2)


def _count_oauth_rpcs(node: Any) -> Tuple[int, float]:
    rpcs = 0
    rtt = 0.0
    if isinstance(node, Mapping):
        if "oauth_telemetry" in node and isinstance(node["oauth_telemetry"], Mapping):
            t = node["oauth_telemetry"]
            rpcs += int(t.get("sts_exchanges", 1))
            rtt += float(t.get("sts_rtt_ms", 0.0))
        for k, v in node.items():
            if k != "oauth_telemetry":
                c_r, c_ms = _count_oauth_rpcs(v)
                rpcs += c_r
                rtt += c_ms
    elif isinstance(node, list):
        for item in node:
            c_r, c_ms = _count_oauth_rpcs(item)
            rpcs += c_r
            rtt += c_ms
    return rpcs, round(rtt, 2)


@dataclass
class _ScalePeerNode:
    index: int
    name: str
    trust_domain: str
    skill: str
    identity: WorkloadIdentity
    rev_replica: RevocationReplicaClient
    sidecar: LineageSidecar
    app_http: ManagedHTTPService
    inbound_url: str
    outbound_url: str
    card: AgentCard


class _ScaleMeshHarness:
    """Self-contained live HTTP mesh of `N` peers across 4 autonomous trust domains."""

    def __init__(self, peer_count: int) -> None:
        if peer_count < 4:
            raise ValueError("peer_count must be >= 4")
        self.peer_count = int(peer_count)
        self.resolver = TrustBundleResolver()
        self.cas: Dict[str, TrustDomainCA] = {}
        self.ca_audit_emitters: Dict[str, AuditStreamEmitter] = {}
        self.ca_audit_http: Dict[str, ManagedHTTPService] = {}
        self.ca_audit_urls: Dict[str, str] = {}
        self.rev_services: Dict[str, RevocationService] = {}
        self.rev_urls: Dict[str, str] = {}
        self.sts_services: Dict[str, OAuthSTSService] = {}
        self.sts_urls: Dict[str, str] = {}
        self.yellow_pages: Optional[AgentDirectoryService] = None
        self.yellow_pages_url: str = ""
        self.peers: List[_ScalePeerNode] = []
        self.vault_ledger = IdempotencyLedger(max_entries=10_000)
        self.gateway_id: Optional[WorkloadIdentity] = None
        self.auditor_id: Optional[WorkloadIdentity] = None
        self.oauth_client_secrets: Dict[str, str] = {
            "lct-gateway": f"sec-{secrets.token_urlsafe(18)}",
        }
        self.oauth_users: Dict[str, str] = {
            "alice": f"pw-{secrets.token_urlsafe(18)}",
        }

    def start(self) -> None:
        # 1. Four autonomous domain CAs + decentralized CA LocalAuditStore HTTP endpoints
        for td in BENCH_DOMAINS:
            ca = TrustDomainCA(td, alg="ES256")
            self.cas[td] = ca
            self.resolver.register_domain_ca(ca)

        self.gateway_id = self.cas["org-alpha.io"].issue_workload(
            "/ns/lineage-alpha/sa/e2e-user-gateway", ttl_seconds=1800.0
        )
        self.auditor_id = self.cas["org-alpha.io"].issue_workload(
            "/ns/sys/sa/auditor", ttl_seconds=1800.0
        )

        for td in BENCH_DOMAINS:
            ca = self.cas[td]
            em = AuditStreamEmitter(
                ca,
                collector_client=None,
                stream_id=f"spiffe://{td}/authority/root",
                authorized_auditors=[self.auditor_id.spiffe_id, self.gateway_id.spiffe_id],
            )
            self.ca_audit_emitters[td] = em

            def _make_ca_disp(ca_obj: TrustDomainCA, em_obj: AuditStreamEmitter):
                def _disp(req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
                    if req.method == "GET" and req.path == "/healthz":
                        return 200, {"status": "ok", "trust_domain": ca_obj.trust_domain}, {}
                    if req.method == "GET" and req.path == "/v1/audit/local":
                        return em_obj.local_store.serve_http_query(
                            req,
                            self.resolver,
                            node_spiffe_id=ca_obj.root_authority_spiffe_id,
                            require_task_id=True,
                        )
                    return 404, {"error": "not_found"}, {}

                return _disp

            srv = ManagedHTTPService(
                service_name=f"scale-ca-audit-{td}",
                dispatcher=_make_ca_disp(ca, em),
                host="127.0.0.1",
                port=0,
            )
            self.ca_audit_urls[td] = srv.start()
            self.ca_audit_http[td] = srv

        # 2. Federated per-domain RevocationServices
        for td in BENCH_DOMAINS:
            rev_id = self.cas[td].issue_workload("/ns/sys/sa/revocation", ttl_seconds=1800.0)
            rev_svc = RevocationService(
                rev_id,
                self.resolver,
                host="127.0.0.1",
                port=0,
                strict_domain_isolation=True,
            )
            self.rev_urls[td] = rev_svc.start()
            self.rev_services[td] = rev_svc
        for td, rev_svc in self.rev_services.items():
            rev_svc.peer_revocation_urls = {
                other_td: u for other_td, u in self.rev_urls.items() if other_td != td
            }
            rev_svc.start_federation_sync(interval_sec=0.5)

        # 3. Single Untrusted Public Yellow Pages (`registry_mode="centralized"`)
        self.yellow_pages = AgentDirectoryService(
            self.resolver,
            host="127.0.0.1",
            port=0,
            registry_mode="centralized",
            allowed_locator_cidrs=("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"),
        )
        self.yellow_pages_url = self.yellow_pages.start()

        # 4. Pre-allocate peer identities so OAuth confidential client table includes all peers
        peer_specs: List[Tuple[int, str, str, str, WorkloadIdentity]] = []
        branch_width = 1 if self.peer_count == 4 else (3 if self.peer_count <= 12 else 4)
        for idx in range(self.peer_count):
            td = BENCH_DOMAINS[idx % len(BENCH_DOMAINS)]
            if idx == 0:
                name = "peer-00-alice"
                skill = "scale.entry"
            elif idx == self.peer_count - 1:
                name = f"peer-{idx:02d}-vault"
                skill = "scale.vault"
            elif 1 <= idx <= branch_width:
                name = f"peer-{idx:02d}-tier1-b{idx}"
                skill = f"scale.tier1.b{idx}"
            elif self.peer_count > 4 and branch_width < idx <= 2 * branch_width:
                b_num = idx - branch_width
                name = f"peer-{idx:02d}-tier2-b{b_num}"
                skill = f"scale.tier2.b{b_num}"
            else:
                name = f"peer-{idx:02d}-worker"
                skill = f"scale.worker.w{idx}"
            w_id = self.cas[td].issue_workload(f"/ns/scale/sa/{name}", ttl_seconds=1800.0)
            cid = spiffe_id_to_oauth_client_id(w_id.spiffe_id)
            self.oauth_client_secrets[cid] = f"sec-{secrets.token_urlsafe(18)}"
            peer_specs.append((idx, name, td, skill, w_id))

        # 5. Four RS256 OAuth 2.0 RFC 8693 STS services (`alpha` acts as central STS in oauth_centralized;
        #    all 4 act as per-org federated STS in oauth_federated!)
        for td in BENCH_DOMAINS:
            sts = OAuthSTSService(
                trust_domain=td,
                realm="lct",
                host="127.0.0.1",
                port=0,
                client_secrets=self.oauth_client_secrets,
                user_passwords=self.oauth_users if td == "org-alpha.io" else {},
                spiffe_trust_resolver=self.resolver,
            )
            u_sts = sts.start()
            sts.issuer_origin = u_sts
            self.sts_services[td] = sts
            self.sts_urls[td] = u_sts

        all_issuers = [f"{u}/realms/lct" for u in self.sts_urls.values()]
        for td, sts in self.sts_services.items():
            peer_jwks_urls = [
                f"{other_u}/realms/lct/protocol/openid-connect/certs"
                for other_td, other_u in self.sts_urls.items()
                if other_td != td
            ]
            sts._peer_sts_jwks_urls_provider = lambda urls=peer_jwks_urls: list(urls)

        central_verifier = OIDCTokenVerifier(
            jwks_urls=[f"{self.sts_urls['org-alpha.io']}/realms/lct/protocol/openid-connect/certs"],
            expected_issuer=f"{self.sts_urls['org-alpha.io']}/realms/lct",
        )
        local_verifiers = {
            td: OIDCTokenVerifier(
                jwks_urls=[f"{self.sts_urls[td]}/realms/lct/protocol/openid-connect/certs"],
                allowed_issuers=all_issuers,
            )
            for td in BENCH_DOMAINS
        }

        # 6. Spawn all `N` real peer HTTP App + LineageSidecar pairs (zero central audit collector!)
        dir_cidrs = ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        for idx, name, td, skill, w_id in peer_specs:
            loop_sec = secrets.token_urlsafe(24)
            rev_rep = RevocationReplicaClient(self.rev_urls[td], self.resolver)
            rev_rep.start_background_sync(wait_ms=150)
            dir_cli = AgentDirectoryClient(
                self.yellow_pages_url,
                self.resolver,
                allowed_locator_cidrs=dir_cidrs,
            )
            oauth_ex = OAuthTokenExchangeClient(
                realm="lct",
                client_secrets=self.oauth_client_secrets,
            )
            em_peer = AuditStreamEmitter(
                w_id,
                collector_client=None,
                stream_id=f"{w_id.spiffe_id}#node-{idx:02d}",
                authorized_auditors=[self.auditor_id.spiffe_id, self.gateway_id.spiffe_id],
            )
            box_sc: Dict[str, WorkspaceSidecarClient] = {}

            def _make_peer_app(
                p_idx: int,
                p_name: str,
                p_skill: str,
                l_sec: str,
                b_width: int,
                has_tier2: bool,
                sc_ref: Dict[str, WorkspaceSidecarClient],
            ):
                def _app_disp(req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
                    if req.method == "GET" and req.path == "/healthz":
                        return 200, {"status": "ok", "peer": p_name}, {}
                    if req.header("X-LCT-Loopback-Auth") != l_sec:
                        return 403, {"error": "loopback_denied"}, {}
                    req_id = req.header("X-LCT-Request-Id") or ""
                    task_id = req.header("X-LCT-Task-Id") or ""
                    sub = req.header("X-LCT-Sub") or ""
                    idem = req.header("X-LCT-Idempotency-Key") or ""
                    sc = sc_ref["cli"]

                    if req.method == "POST" and req.path == "/mcp":
                        body = req.json()
                        rpc_id = body.get("id", 1)
                        params = body.get("params") or {}
                        t_name = str(params.get("name") or "")
                        args = params.get("arguments") or {}
                        amt = float(args.get("amount", 100.0))
                        proj = str(args.get("project_code", "PRJ-SCALE"))
                        rec, replayed = self.vault_ledger.execute_once(
                            sub=sub,
                            idempotency_key=idem or str(args.get("idempotency_key") or ""),
                            operation=t_name,
                            project_code=proj,
                            amount_usd=amt,
                            builder_fn=lambda rid: {
                                "operation": t_name,
                                "project_code": proj,
                                "charged_usd": amt,
                                "task_id": task_id,
                            },
                        )
                        return 200, {"jsonrpc": "2.0", "id": rpc_id, "result": {"data": rec, "idempotent_replay": replayed}}, {}

                    if req.method == "POST" and req.path == "/a2a/task":
                        body = req.json()
                        proj = str(body.get("project_code", "PRJ-SCALE"))

                        # Entry peer (`peer-00-alice`): fan-out across `b_width` Tier-1 peers + trigger Vault convergence!
                        if p_skill == "scale.entry":
                            perms_branch = PermissionLattice.create(
                                tools=["reserve_cloud_budget", "lock_joint_project"],
                                max_amount=300.0,
                                allowed_targets=["cloud-infra-escrow"],
                                param_whitelist={"project_code": [proj]},
                                max_calls=8,
                            )

                            def _call_b(bi: int) -> Tuple[int, Dict[str, Any]]:
                                sk_t1 = f"scale.tier1.b{bi}"
                                return sc.delegate_peer(
                                    request_id=req_id,
                                    permissions=perms_branch,
                                    payload={"project_code": proj, "branch_idx": bi},
                                    required_skill=sk_t1,
                                    hop_segment=f"Tier1B{bi}",
                                    logical_branch_id=f"Tier1B{bi}",
                                    use_prune_and_graft=False,
                                    timeout=15.0,
                                )

                            b_outs: List[Dict[str, Any]] = []
                            with concurrent.futures.ThreadPoolExecutor(max_workers=b_width) as pool:
                                futs = [pool.submit(_call_b, bi) for bi in range(1, b_width + 1)]
                                for f in futs:
                                    st_b, o_b = f.result()
                                    if st_b != 200:
                                        return st_b, {"error": "tier1_failed", "detail": o_b}, {}
                                    b_outs.append(o_b)

                            st_v, out_v = sc.delegate_peer(
                                request_id=req_id,
                                permissions=perms_branch,
                                payload={"project_code": proj, "op": "finalize_converged"},
                                required_skill="scale.vault",
                                hop_segment="VaultTrigger",
                                logical_branch_id="VaultTrigger",
                                use_prune_and_graft=False,
                                timeout=15.0,
                            )
                            return st_v, {"branches": b_outs, "vault": out_v}, {}

                        # Tier-1 peer: either relay to Tier-2 (`N >= 12`) or directly invoke Vault MCP + converge
                        if p_skill.startswith("scale.tier1.b"):
                            b_idx = int(p_skill.rsplit("b", 1)[1])
                            perms_sub = PermissionLattice.create(
                                tools=["reserve_cloud_budget", "lock_joint_project"],
                                max_amount=200.0,
                                allowed_targets=["cloud-infra-escrow"],
                                param_whitelist={"project_code": [proj]},
                                max_calls=6,
                            )
                            if has_tier2:
                                st_t2, out_t2 = sc.delegate_peer(
                                    request_id=req_id,
                                    permissions=perms_sub,
                                    payload={"project_code": proj, "branch_idx": b_idx},
                                    required_skill=f"scale.tier2.b{b_idx}",
                                    hop_segment=f"Tier2B{b_idx}",
                                    logical_branch_id=f"Tier2B{b_idx}",
                                    use_prune_and_graft=False,
                                    timeout=15.0,
                                )
                                return st_t2, {"tier2": out_t2}, {}

                            idem_k = compute_branch_idempotency_key(task_id, f"b{b_idx}")
                            st_m, out_m = sc.call_mcp_tool(
                                req_id,
                                "skill://scale.vault.mcp",
                                "reserve_cloud_budget",
                                {"project_code": proj, "amount": 120.0, "target": "cloud-infra-escrow"},
                                idempotency_key=idem_k,
                            )
                            if st_m != 200:
                                return st_m, out_m, {}
                            st_c, out_c = sc.submit_converged_branch(
                                request_id=req_id,
                                permissions=perms_sub,
                                branch_name=f"branch_{b_idx}",
                                branch_data={"branch_idx": b_idx, "amount": 120.0},
                                required_skill="scale.vault",
                                hop_segment=f"ConvB{b_idx}",
                            )
                            return st_c, {"mcp": out_m, "converge": out_c}, {}

                        # Tier-2 peer (`N in {12, 24}`): invoke Vault MCP + submit N->1 converged branch
                        if p_skill.startswith("scale.tier2.b"):
                            b_idx = int(p_skill.rsplit("b", 1)[1])
                            perms_leaf = PermissionLattice.create(
                                tools=["reserve_cloud_budget", "lock_joint_project"],
                                max_amount=180.0,
                                allowed_targets=["cloud-infra-escrow"],
                                param_whitelist={"project_code": [proj]},
                                max_calls=4,
                            )
                            idem_k = compute_branch_idempotency_key(task_id, f"b{b_idx}")
                            st_m, out_m = sc.call_mcp_tool(
                                req_id,
                                "skill://scale.vault.mcp",
                                "reserve_cloud_budget",
                                {"project_code": proj, "amount": 120.0, "target": "cloud-infra-escrow"},
                                idempotency_key=idem_k,
                            )
                            if st_m != 200:
                                return st_m, out_m, {}
                            st_c, out_c = sc.submit_converged_branch(
                                request_id=req_id,
                                permissions=perms_leaf,
                                branch_name=f"branch_{b_idx}",
                                branch_data={"branch_idx": b_idx, "amount": 120.0},
                                required_skill="scale.vault",
                                hop_segment=f"ConvB{b_idx}",
                            )
                            return st_c, {"mcp": out_m, "converge": out_c}, {}

                        # Vault peer (`peer-{N-1}-vault`): execute converged MultiParent lock_joint_project!
                        if p_skill == "scale.vault":
                            idem_lk = compute_branch_idempotency_key(task_id, "final-lock")
                            st_lk, out_lk = sc.call_mcp_tool_converged(
                                task_id=task_id,
                                sub=sub,
                                mcp_target="skill://scale.vault.mcp",
                                tool_name="lock_joint_project",
                                arguments={"project_code": proj, "amount": 150.0, "target": "cloud-infra-escrow"},
                                idempotency_key=idem_lk,
                            )
                            return st_lk, {"locked": out_lk}, {}

                        return 200, {"peer": p_name, "idle_worker": True}, {}

                    return 404, {"error": "not_found"}, {}

                return _app_disp

            app_srv = ManagedHTTPService(
                service_name=f"scale-app-{name}",
                dispatcher=_make_peer_app(
                    idx,
                    name,
                    skill,
                    loop_sec,
                    branch_width,
                    self.peer_count > 4,
                    box_sc,
                ),
                host="127.0.0.1",
                port=0,
            )
            app_url = app_srv.start()
            sc_obj = LineageSidecar(
                identity=w_id,
                trust_resolver=self.resolver,
                app_upstream_url=app_url,
                loopback_secret=loop_sec,
                mode=VerificationMode.ADAPTIVE_RISK_ANCHORED,
                revocation_replica=rev_rep,
                directory_client=dir_cli,
                audit_emitter=em_peer,
                is_tool_server=False,
                inbound_host="127.0.0.1",
                inbound_port=0,
                outbound_port=0,
                delegation_mode="dual",
                oauth_central_verifier=central_verifier,
                oauth_local_verifier=local_verifiers[td],
                oauth_exchange_client=oauth_ex,
                oauth_central_sts_origins_provider=lambda: [self.sts_urls["org-alpha.io"]],
                oauth_domain_sts_origins_provider=lambda target_td: [
                    self.sts_urls.get(target_td, self.sts_urls["org-alpha.io"])
                ],
            )
            in_url, out_url = sc_obj.start()
            box_sc["cli"] = WorkspaceSidecarClient(out_url, loop_sec)

            card_skills = [skill, "scale.vault.mcp"] if skill == "scale.vault" else [skill]
            card = AgentCard.sign_and_create(
                identity=w_id,
                name=name,
                endpoint=in_url,
                skills=card_skills,
                priority=10,
            )
            sc_obj.agent_card = card
            dir_cli.register(card)
            self.peers.append(
                _ScalePeerNode(
                    index=idx,
                    name=name,
                    trust_domain=td,
                    skill=skill,
                    identity=w_id,
                    rev_replica=rev_rep,
                    sidecar=sc_obj,
                    app_http=app_srv,
                    inbound_url=in_url,
                    outbound_url=out_url,
                    card=card,
                )
            )

    def stop(self) -> None:
        for p in self.peers:
            p.sidecar.stop()
            p.app_http.stop()
        if self.yellow_pages is not None:
            self.yellow_pages.stop()
        for sts in self.sts_services.values():
            sts.stop()
        for rev in self.rev_services.values():
            rev.stop()
        for srv in self.ca_audit_http.values():
            srv.stop()

    def measure_tier(self, iterations: int = 8) -> Dict[str, Any]:
        assert self.gateway_id is not None and self.auditor_id is not None
        entry_peer = self.peers[0]
        oauth_cli = OAuthTokenExchangeClient(
            realm="lct",
            client_secrets=self.oauth_client_secrets,
        )
        login = oauth_cli.login_user_password(
            sts_origins=[self.sts_urls["org-alpha.io"]],
            username="alice",
            password=self.oauth_users["alice"],
            client_id="lct-gateway",
        )
        user_bearer = str(login["access_token"])

        proto_metrics: Dict[str, Any] = {}
        last_lct_task_id = ""
        branch_width = 1 if self.peer_count == 4 else (3 if self.peer_count <= 12 else 4)
        logical_hops = 1 + branch_width * (2 if self.peer_count > 4 else 1) + branch_width + 2

        for mode in ("oauth_centralized", "oauth_federated", "lct"):
            latencies_ms: List[float] = []
            rpc_counts: List[int] = []
            sts_rtts: List[float] = []

            for it in range(iterations):
                tid = f"task-scale-n{self.peer_count}-{mode.replace('_', '-')}-{it}-{uuid.uuid4().hex[:6]}"
                proj = "PRJ-SCALE"
                t0 = time.perf_counter()
                if mode in ("oauth_centralized", "oauth_federated"):
                    ex0 = oauth_cli.exchange_token(
                        sts_origins=[self.sts_urls["org-alpha.io"]],
                        subject_token=user_bearer,
                        target_audience=entry_peer.identity.spiffe_id,
                        caller_spiffe_id=self.gateway_id.spiffe_id,
                        caller_workload_svid=self.gateway_id.workload_svid,
                        client_id="lct-gateway",
                    )
                    resp = httpx.post(
                        f"{entry_peer.inbound_url}/a2a/task",
                        json={"project_code": proj},
                        headers={
                            "Authorization": f"Bearer {ex0.access_token}",
                            "X-LCT-Delegation-Mode": mode,
                            "X-LCT-Task-Id": tid,
                        },
                        timeout=30.0,
                        trust_env=False,
                    )
                    elapsed_ms = (time.perf_counter() - t0) * 1000.0
                    if resp.status_code != 200:
                        raise RuntimeError(
                            f"Scale benchmark {mode} N={self.peer_count} failed ({resp.status_code}): {resp.text}"
                        )
                    sub_rpcs, sub_rtt = _count_oauth_rpcs(resp.json())
                    latencies_ms.append(elapsed_ms)
                    rpc_counts.append(1 + sub_rpcs)
                    sts_rtts.append(round(ex0.rtt_ms + sub_rtt, 2))
                else:
                    perms_root = PermissionLattice.create(
                        tools=["reserve_cloud_budget", "lock_joint_project"],
                        max_amount=1000.0,
                        allowed_targets=["cloud-infra-escrow"],
                        param_whitelist={"project_code": [proj]},
                        max_calls=24,
                    )
                    root_tok = mint_root_token(
                        self.cas["org-alpha.io"],
                        task_id=tid,
                        sub="user:alice@org-alpha.io",
                        sender_jkt=self.gateway_id.jkt,
                        first_hop_spiffe_id=entry_peer.identity.spiffe_id,
                        first_hop_jkt=entry_peer.identity.jkt,
                        permissions=perms_root,
                        max_depth=8,
                        hop_segment="Peer00Alice",
                    )
                    self.ca_audit_emitters["org-alpha.io"].emit(
                        event_type=AuditEventType.ROOT_MINT,
                        task_id=tid,
                        sub="user:alice@org-alpha.io",
                        lineage_path=root_tok.lineage_path,
                        hop_index=0,
                        epoch=0,
                        root_block_hash=root_tok.root_block_hash,
                        current_block_hash=root_tok.leaf_block_hash,
                        decision="ALLOW",
                        permissions_summary=perms_root.to_dict(),
                        action_detail={"first_hop_spiffe_id": entry_peer.identity.spiffe_id},
                    )
                    compact_root = root_tok.encode_compact()
                    target_u = f"{entry_peer.inbound_url}/a2a/task"
                    dpop = create_dpop_proof(self.gateway_id, "POST", target_u, compact_root)
                    resp = httpx.post(
                        target_u,
                        json={"project_code": proj},
                        headers={"Authorization": f"DPoP {compact_root}", "DPoP": dpop},
                        timeout=30.0,
                        trust_env=False,
                    )
                    elapsed_ms = (time.perf_counter() - t0) * 1000.0
                    if resp.status_code != 200:
                        raise RuntimeError(
                            f"Scale benchmark LCT N={self.peer_count} failed ({resp.status_code}): {resp.text}"
                        )
                    latencies_ms.append(elapsed_ms)
                    rpc_counts.append(0)
                    sts_rtts.append(0.0)
                    last_lct_task_id = tid

            sorted_lat = sorted(latencies_ms)
            p50 = _percentile(sorted_lat, 50.0)
            proto_metrics[mode] = {
                "iterations": iterations,
                "logical_hops_per_workflow": logical_hops,
                "e2e_p50_ms": p50,
                "e2e_p95_ms": _percentile(sorted_lat, 95.0),
                "e2e_p99_ms": _percentile(sorted_lat, 99.0),
                "per_hop_p50_ms": round(p50 / max(1, logical_hops), 2),
                "online_sts_rpcs_per_workflow": rpc_counts[0] if rpc_counts else 0,
                "avg_sts_rtt_ms": round(sum(sts_rtts) / max(1, len(sts_rtts)), 2),
            }

        # 2. Measure decentralized `DistributedAuditor` BFS pull on `last_lct_task_id`
        dir_cli = AgentDirectoryClient(
            self.yellow_pages_url,
            self.resolver,
            allowed_locator_cidrs=("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"),
        )
        dist_auditor = DistributedAuditor(
            trust_resolver=self.resolver,
            signer=self.auditor_id,
            directory_client=dir_cli,
            domain_ca_urls={td: [u] for td, u in self.ca_audit_urls.items()},
            trusted_revocation_spiffe_ids=[
                f"spiffe://{td}/ns/sys/sa/revocation" for td in BENCH_DOMAINS
            ],
        )
        audit_res = dist_auditor.pull_and_reconstruct(
            task_id=last_lct_task_id,
            entry_spiffe_ids=[entry_peer.identity.spiffe_id],
            seed_domains=["org-alpha.io"],
        )
        if not audit_res.reconstructed_complete:
            raise RuntimeError(
                f"DistributedAuditor failed reconstruction at N={self.peer_count}: {audit_res.to_dict()}"
            )

        # 3. Measure full `N`-node cross-domain cascading revocation convergence!
        rev_tid = f"task-rev-n{self.peer_count}-{uuid.uuid4().hex[:6]}"
        rev_prefix = f"/{rev_tid}/Peer00Alice"
        t_rev0 = time.perf_counter()
        self.rev_services["org-alpha.io"].revoke_prefix_direct(
            prefix=rev_prefix,
            requested_by="spiffe://org-alpha.io/authority/root",
            reason="scale_cascade_benchmark",
            trust_domain="org-alpha.io",
        )
        self.rev_services["org-alpha.io"]._notify_federation_peers()
        for p in self.peers:
            p.rev_replica.sync_now()
        converged_nodes = sum(
            1
            for p in self.peers
            if p.rev_replica.trie.check_lineage_path(rev_prefix, trust_domain="org-alpha.io")
            is not None
        )
        rev_conv_ms = round((time.perf_counter() - t_rev0) * 1000.0, 2)
        if converged_nodes != self.peer_count:
            raise RuntimeError(
                f"Revocation did not converge across all {self.peer_count} peers ({converged_nodes}/{self.peer_count})"
            )

        return {
            "peer_nodes": self.peer_count,
            "trust_domains": len(BENCH_DOMAINS),
            "yellow_pages_instances": 1,
            "central_audit_collectors": 0,
            "protocols": proto_metrics,
            "cascading_revocation": {
                "converged_peers": converged_nodes,
                "total_peers": self.peer_count,
                "convergence_ms": rev_conv_ms,
            },
            "decentralized_audit": {
                "task_id": last_lct_task_id,
                "nodes_queried": len(audit_res.nodes_queried),
                "total_mesh_nodes": self.peer_count + len(BENCH_DOMAINS),
                "non_participating_peers_skipped": max(
                    0, (self.peer_count + len(BENCH_DOMAINS)) - len(audit_res.nodes_queried)
                ),
                "total_signed_entries": audit_res.total_entries,
                "pull_and_reconstruct_ms": round(audit_res.pull_latency_ms, 2),
                "reconstructed_complete": audit_res.reconstructed_complete,
                "reconstruction_accuracy_pct": 100.0 if audit_res.reconstructed_complete else 0.0,
                "anomalies_count": len(audit_res.anomalies),
            },
        }


def format_scale_benchmark_markdown(report: Mapping[str, Any]) -> str:
    lines = [
        "# Platform v2 Distributed Peer-to-Peer Scale & Decentralized Audit Benchmark",
        "",
        "- **Registry Topology**: `1` Untrusted Public Yellow Pages (`AgentCard` JWS + CA SVID verified; `0` private keys, `0` auth state, `0` audit logs)",
        "- **Audit Topology**: **`0` Central Audit Collectors** (`LocalAuditStore` per peer + stateless on-demand `DistributedAuditor` BFS pull)",
        f"- **Autonomous Trust Domains**: `{', '.join(BENCH_DOMAINS)}`",
        "",
        "## 1. Multi-Hop Workflow Latency & Online STS RPC Scaling (`N in {4, 12, 24}`)",
        "",
        "| Peer Mesh Size (`N`) | Logical Hops | `oauth_centralized` P50 / P95 (`ms`, STS RPCs) | `oauth_federated` P50 / P95 (`ms`, STS RPCs) | `lct` P50 / P95 (`ms`, STS RPCs) |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for tier in report.get("tiers") or ():
        n = tier["peer_nodes"]
        pr = tier["protocols"]
        c = pr["oauth_centralized"]
        f = pr["oauth_federated"]
        l = pr["lct"]
        lines.append(
            f"| **`{n}` Peers** | `{l['logical_hops_per_workflow']}` | "
            f"`{c['e2e_p50_ms']} / {c['e2e_p95_ms']} ms` (`{c['online_sts_rpcs_per_workflow']}` RPCs) | "
            f"`{f['e2e_p50_ms']} / {f['e2e_p95_ms']} ms` (`{f['online_sts_rpcs_per_workflow']}` RPCs) | "
            f"**`{l['e2e_p50_ms']} / {l['e2e_p95_ms']} ms` (`{l['online_sts_rpcs_per_workflow']}` RPCs)** |"
        )

    lines.extend(
        [
            "",
            "## 2. Cascading Revocation & Decentralized On-Demand `DistributedAuditor` Scaling",
            "",
            "| Peer Mesh Size (`N`) | Revocation Convergence | `DistributedAuditor` Nodes Queried (Targeted BFS) | Signed Entries Pulled | BFS Pull + Verify Latency | Causal DAG Accuracy |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
    )
    for tier in report.get("tiers") or ():
        n = tier["peer_nodes"]
        rv = tier["cascading_revocation"]
        da = tier["decentralized_audit"]
        lines.append(
            f"| **`{n}` Peers** | `{rv['converged_peers']}/{rv['total_peers']}` in `{rv['convergence_ms']} ms` | "
            f"`{da['nodes_queried']}/{da['total_mesh_nodes']}` (`{da['non_participating_peers_skipped']}` idle peers skipped) | "
            f"`{da['total_signed_entries']}` | `{da['pull_and_reconstruct_ms']} ms` | **`{da['reconstruction_accuracy_pct']}%` (`{da['anomalies_count']}` anomalies)** |"
        )
    return "\n".join(lines)


def run_distributed_scale_benchmark(
    tiers: Sequence[int] = (4, 12, 24),
    iterations: int = 8,
    output_dir: Optional[str | Path] = None,
) -> Dict[str, Any]:
    tier_results: List[Dict[str, Any]] = []
    for n_peers in tiers:
        harness = _ScaleMeshHarness(peer_count=int(n_peers))
        harness.start()
        try:
            res = harness.measure_tier(iterations=iterations)
            tier_results.append(res)
        finally:
            harness.stop()

    report = redact_sensitive(
        {
            "benchmark": "platform_v2_distributed_peer_scale_and_decentralized_audit",
            "generated_at": time.time(),
            "tiers": tier_results,
        }
    )
    md = format_scale_benchmark_markdown(report)

    scale_pkg_dir = Path(__file__).resolve().parent
    (scale_pkg_dir / "latest_scale_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (scale_pkg_dir / "latest_scale_report.md").write_text(
        md + "\n",
        encoding="utf-8",
    )
    if output_dir is not None:
        out_p = Path(output_dir).expanduser().resolve()
        out_p.mkdir(parents=True, exist_ok=True)
        (out_p / "scale_report.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        (out_p / "scale_report.md").write_text(md + "\n", encoding="utf-8")

    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="20+ Node Distributed Peer-to-Peer Scale & Decentralized Audit Benchmark"
    )
    parser.add_argument(
        "--tiers",
        default="4,12,24",
        help="Comma-separated peer node counts to benchmark (default: 4,12,24)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=8,
        help="Iterations per protocol per tier (default: 8)",
    )
    parser.add_argument(
        "--output-dir",
        default="",
        help="Optional directory to write scale_report.json & scale_report.md",
    )
    args = parser.parse_args()
    tiers_list = [int(x.strip()) for x in args.tiers.split(",") if x.strip()]
    rep = run_distributed_scale_benchmark(
        tiers=tiers_list,
        iterations=max(1, args.iterations),
        output_dir=(args.output_dir.strip() or None),
    )
    print(format_scale_benchmark_markdown(rep))


if __name__ == "__main__":
    main()
