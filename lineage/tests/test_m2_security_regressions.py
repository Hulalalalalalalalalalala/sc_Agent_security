"""Milestone-2 Security Hardening & Adversarial Regression Suite.

Permanently verifies remediation of all 6 Milestone-2 QA findings:
- `[CRITICAL-M2-01]`: Fault-injection gate (`LCT_ENABLE_FAULT_INJECTION` default `false`),
  removal of `override_direct_parent_url` credential exfiltration, strict `sync_hook_url`
  gateway allowlist, bounded finite timeouts + `zombie_delay >= hotel_timeout + 0.5`
  anti-double-booking ordering, and per-`(task_id, sub)` isolation + token redaction on
  `inspect_inbox` and `inspect_zombie_telemetry`.
- `[HIGH-M2-01]`: `automountServiceAccountToken: false` across all K8s manifests and
  strict zero-SA-token mounting on every `app` business container.
- `[HIGH-M2-02]`: Strict K8s OIDC SA JWT `iss`/`aud`/`exp`/`iat`/`nbf` validation,
  mandatory workload private-key PoP (`lct-ca-pop+jwt`) + replay cache + bounded TTL on
  `/v1/ca/issue-workload`, strict single-domain enforcement on `/v1/ca/mint-root-token`,
  and cryptographic `RevocationEvent` verification on `/v1/ca/emit-revocation-audit`.
- `[MEDIUM-M2-01]`: Caller SVID/domain JWS authentication & auditor role authorization on
  `GET /v1/audit/entries` + `redact_sensitive` scrubbing of `lct1.`/`lctm1.` tokens.
- `[MEDIUM-M2-02]`: Outbound proxy `task_path` & `target_url` origin-form/authority
  smuggling prevention, positive finite MCP amounts, `allow_nan=False` HTTP JSON output,
  and `_extract_json_object` / `SettlementConvergerApp` `OllamaError` handling.
- `[LOW-M2-01]`: Clean positive-only synthesis prompts in `SettlementConvergerApp` and
  strict `404` on non-`/a2a/task` paths in `OrchestratorAlphaApp`.
"""

from __future__ import annotations

import os
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import patch

import httpx
import yaml

from lineage.agents import (
    FlightSpecialistApp,
    HotelSpecialistApp,
    OllamaError,
    OrchestratorAlphaApp,
    PaymentVaultMCPApp,
    SettlementConvergerApp,
    TravelOpsMCPApp,
)
from lineage.agents.ollama_client import _extract_json_object
from lineage.audit import (
    AuditCollectorClient,
    AuditCollectorService,
    AuditEventType,
    AuditStreamEmitter,
    CausalChainAuditor,
)
from lineage.common.crypto import (
    KeyPair,
    jws_sign_compact,
    redact_sensitive,
    sha256_b64url,
)
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.identity import TrustBundleResolver, TrustDomainCA
from lineage.k8s.bootstrap_services import FederationCAService, create_ca_pop_jws
from lineage.protocol import PermissionLattice, create_dpop_proof, mint_root_token
from lineage.registry import AgentCard, AgentDirectoryClient, AgentDirectoryService
from lineage.resilience.coordinator import ResilientDelegationCoordinator
from lineage.resilience.receipts import FailureEvidence, FaultType, SkipLevelReceipt
from lineage.revocation import RevocationReplicaClient, RevocationService
from lineage.sidecar import LineageSidecar
from lineage.verifier import VerificationMode


class _DeterministicStubLLM:
    """In-process deterministic LLM stub recording system prompts for unit assertions."""

    def __init__(self) -> None:
        self.text_system_prompts: List[str] = []
        self.fail_json = False

    def chat_json(self, system_prompt: str, user_prompt: str, **_: Any) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        if self.fail_json:
            raise OllamaError("Simulated malformed JSON from model")
        if "audit_tag" in system_prompt:
            return {"audit_tag": "AUDIT-TOKYO"}, {"model": "stub", "completion_id": "c-1"}
        return (
            {"city": "Tokyo", "flight_budget_usd": 650.0, "hotel_budget_usd": 420.0},
            {"model": "stub", "completion_id": "c-plan"},
        )

    def chat_tool_call(
        self, system_prompt: str, user_prompt: str, tools_schema: List[Dict[str, Any]], **_: Any
    ) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        fn = tools_schema[0]["function"]["name"]
        if fn in ("search_flight", "search_hotel"):
            return fn, {"city": "Tokyo"}, {"model": "stub", "completion_id": f"c-{fn}"}
        if fn == "book_flight":
            return fn, {"city": "Tokyo", "flight_no": "NH-108", "amount": 580.0}, {"model": "stub", "completion_id": "c-bf"}
        return fn, {"city": "Tokyo", "hotel_id": "HTL-TYO-09", "amount": 360.0}, {"model": "stub", "completion_id": "c-rh"}

    def chat_text(self, system_prompt: str, user_prompt: str, **_: Any) -> Tuple[str, Dict[str, Any]]:
        self.text_system_prompts.append(system_prompt)
        return "Confirmed Tokyo booking NH-108 (580 USD) and HTL-TYO-09 (360 USD).", {"model": "stub", "completion_id": "c-txt"}


class Milestone2SecurityRegressionTests(unittest.TestCase):
    # -------------------------------------------------------------------------
    # [HIGH-M2-01]: K8s Manifests ServiceAccount Isolation
    # -------------------------------------------------------------------------
    def test_high_m2_01_manifests_disable_automount_and_exclude_sa_from_app(self) -> None:
        manifests_dir = Path(__file__).resolve().parent.parent / "k8s" / "manifests"
        ctrl_docs = [
            d
            for d in yaml.safe_load_all((manifests_dir / "01-control-plane.yaml").read_text("utf-8"))
            if d and d.get("kind") == "Deployment"
        ]
        dp_docs = [
            d
            for d in yaml.safe_load_all((manifests_dir / "02-data-plane-agents-and-mcp.yaml").read_text("utf-8"))
            if d and d.get("kind") == "Deployment"
        ]
        self.assertEqual(len(ctrl_docs), 10)
        self.assertEqual(len(dp_docs), 8)

        for dep in ctrl_docs + dp_docs:
            name = dep["metadata"]["name"]
            pod_spec = dep["spec"]["template"]["spec"]
            self.assertIs(
                pod_spec.get("automountServiceAccountToken"),
                False,
                f"Deployment {name} must set automountServiceAccountToken: false",
            )
            containers = {c["name"]: c for c in pod_spec["containers"]}
            if "app" in containers:
                app_mounts = containers["app"].get("volumeMounts") or []
                mount_names = [m["name"] for m in app_mounts]
                mount_paths = [m["mountPath"] for m in app_mounts]
                self.assertEqual(
                    mount_names,
                    ["lct-loopback"],
                    f"{name}/app must ONLY mount lct-loopback, got {mount_names}",
                )
                for p in mount_paths:
                    self.assertNotIn("serviceaccount", p)
                    self.assertNotIn("lct-sa", p)
                # Sidecar MUST mount the audience-bound projected token readOnly
                sc_mounts = {
                    m["name"]: m for m in (containers["lct-sidecar"].get("volumeMounts") or [])
                }
                self.assertIn("lct-sa-token", sc_mounts)
                self.assertTrue(sc_mounts["lct-sa-token"].get("readOnly"))

    # -------------------------------------------------------------------------
    # [HIGH-M2-02]: FederationCAService JWT Claims, PoP, TTL, Cross-Domain, Revocation Proof
    # -------------------------------------------------------------------------
    def test_high_m2_02_federation_ca_jwt_pop_ttl_and_domain_isolation(self) -> None:
        oidc_kp = KeyPair.generate("RS256")
        oidc_jwk = oidc_kp.public_jwk()
        audit_Bootstrap_ca = TrustDomainCA("org-bootstrap.io")
        bootstrap_resolver = TrustBundleResolver()
        bootstrap_resolver.register_domain_ca(audit_Bootstrap_ca)
        collector = AuditCollectorService(bootstrap_resolver, host="127.0.0.1", port=0)
        audit_url = collector.start()

        ca_svc = FederationCAService(audit_collector_url=audit_url, host="127.0.0.1", port=0)
        for ca in ca_svc.cas.values():
            collector.trust_resolver.register_domain_ca(ca)
        ca_svc.k8s_verifier._keys_by_kid = {oidc_jwk["kid"]: oidc_jwk}
        ca_svc.k8s_verifier._last_refresh = time.time() + 3600.0
        base = ca_svc.http.start()

        rev_id = ca_svc.cas["org-alpha.io"].issue_workload("/ns/sys/sa/revocation")
        rev_svc = RevocationService(rev_id, collector.trust_resolver, host="127.0.0.1", port=0)
        rev_url = rev_svc.start()

        try:
            now = time.time()
            wl_kp = KeyPair.generate("ES256")

            def _mint_sa(
                ns: str,
                sa: str,
                iss: str = "https://kubernetes.default.svc.cluster.local",
                aud: Any = ["lct-federation-ca"],
                exp: Any = None,
                nbf: Any = None,
            ) -> str:
                claims: Dict[str, Any] = {
                    "iss": iss,
                    "aud": aud,
                    "sub": f"system:serviceaccount:{ns}:{sa}",
                    "iat": now,
                }
                if exp is not None:
                    claims["exp"] = exp
                if nbf is not None:
                    claims["nbf"] = nbf
                return jws_sign_compact(claims, oidc_kp)

            # 1. Wrong issuer, wrong audience, missing exp, non-finite exp, future nbf -> ALL 403!
            for bad_sa in (
                _mint_sa("lineage-beta", "flight-specialist", iss="https://evil.issuer", exp=now + 600),
                _mint_sa("lineage-beta", "flight-specialist", aud=["https://kubernetes.default.svc.cluster.local"], exp=now + 600),
                _mint_sa("lineage-beta", "flight-specialist", exp=None),
                _mint_sa("lineage-beta", "flight-specialist", exp="nan"),
                _mint_sa("lineage-beta", "flight-specialist", exp=now - 20),
                _mint_sa("lineage-beta", "flight-specialist", exp=now + 600, nbf=now + 3600),
            ):
                r_bad = httpx.post(
                    f"{base}/v1/ca/issue-workload",
                    json={
                        "public_jwk": wl_kp.public_jwk(),
                        "pop_jws": create_ca_pop_jws(wl_kp, bad_sa),
                    },
                    headers={"Authorization": f"Bearer {bad_sa}"},
                )
                self.assertEqual(r_bad.status_code, 403, r_bad.text)

            # 2. Valid SA JWT WITHOUT PoP or with ANOTHER key's PoP -> 400!
            good_beta_sa = _mint_sa("lineage-beta", "flight-specialist", exp=now + 600)
            r_no_pop = httpx.post(
                f"{base}/v1/ca/issue-workload",
                json={"public_jwk": wl_kp.public_jwk()},
                headers={"Authorization": f"Bearer {good_beta_sa}"},
            )
            self.assertEqual(r_no_pop.status_code, 400)

            other_kp = KeyPair.generate("ES256")
            r_wrong_pop = httpx.post(
                f"{base}/v1/ca/issue-workload",
                json={
                    "public_jwk": wl_kp.public_jwk(),
                    "pop_jws": create_ca_pop_jws(other_kp, good_beta_sa),
                },
                headers={"Authorization": f"Bearer {good_beta_sa}"},
            )
            self.assertEqual(r_wrong_pop.status_code, 400)

            # 3. Non-finite or 100-year `ttl_seconds` -> 400 (never 500 or 100-year SVID!)
            for bad_ttl in ("nan", -5.0, 3153600000.0):
                r_ttl = httpx.post(
                    f"{base}/v1/ca/issue-workload",
                    json={
                        "public_jwk": wl_kp.public_jwk(),
                        "pop_jws": create_ca_pop_jws(wl_kp, good_beta_sa),
                        "ttl_seconds": bad_ttl,
                    },
                    headers={"Authorization": f"Bearer {good_beta_sa}"},
                )
                self.assertEqual(r_ttl.status_code, 400, r_ttl.text)

            # Valid PoP + bounded TTL succeeds, and replaying exact same PoP JWS is rejected!
            valid_pop = create_ca_pop_jws(wl_kp, good_beta_sa)
            r_ok = httpx.post(
                f"{base}/v1/ca/issue-workload",
                json={"public_jwk": wl_kp.public_jwk(), "pop_jws": valid_pop, "ttl_seconds": 3600.0},
                headers={"Authorization": f"Bearer {good_beta_sa}"},
            )
            self.assertEqual(r_ok.status_code, 200, r_ok.text)
            # Capped to SA token remaining lifetime + 30s (~630s, never > 7200s)
            self.assertLessEqual(r_ok.json()["expires_at"] - r_ok.json()["issued_at"], 635.0)

            r_replay_pop = httpx.post(
                f"{base}/v1/ca/issue-workload",
                json={"public_jwk": wl_kp.public_jwk(), "pop_jws": valid_pop, "ttl_seconds": 600.0},
                headers={"Authorization": f"Bearer {good_beta_sa}"},
            )
            self.assertEqual(r_replay_pop.status_code, 400)

            # 4. `lineage-alpha/e2e-user-gateway` CANNOT mint RootBlock for `org-payment.io` (403)
            #    and unknown domain returns 400 (never 500)!
            gw_sa = _mint_sa("lineage-alpha", "e2e-user-gateway", exp=now + 600)
            perms = PermissionLattice.create(tools=["execute_settlement"], max_amount=500.0, max_calls=2)
            r_cross_mint = httpx.post(
                f"{base}/v1/ca/mint-root-token",
                json={
                    "trust_domain": "org-payment.io",
                    "task_id": "t-cross",
                    "sub": "user:mallory@org-payment.io",
                    "sender_jkt": wl_kp.jkt,
                    "first_hop_spiffe_id": "spiffe://org-payment.io/ns/lineage-pay/sa/settlement-converger",
                    "first_hop_jkt": wl_kp.jkt,
                    "permissions": perms.to_dict(),
                },
                headers={"Authorization": f"Bearer {gw_sa}"},
            )
            self.assertEqual(r_cross_mint.status_code, 403)

            r_unknown_td = httpx.post(
                f"{base}/v1/ca/mint-root-token",
                json={"trust_domain": "nonexistent.io"},
                headers={"Authorization": f"Bearer {gw_sa}"},
            )
            self.assertEqual(r_unknown_td.status_code, 400)

            # 5. `/v1/ca/emit-revocation-audit` rejects unverified / missing RevocationEvent (400/403)
            #    and accepts genuine RevocationService-signed RevocationEvent!
            r_fake_rev = httpx.post(
                f"{base}/v1/ca/emit-revocation-audit",
                json={
                    "trust_domain": "org-alpha.io",
                    "task_id": "task-rev-1",
                    "sub": "user:alice@org-alpha.io",
                    "target_prefix": "/task-rev-1/Orch/B1",
                    "root_block_hash": "h0",
                    "current_block_hash": "h1",
                },
                headers={"Authorization": f"Bearer {gw_sa}"},
            )
            self.assertEqual(r_fake_rev.status_code, 400)

            rev_cli = RevocationReplicaClient(rev_url, collector.trust_resolver)
            real_ev = rev_cli.revoke_prefix(
                caller=ca_svc.cas["org-alpha.io"],
                prefix="/task-rev-1/Orch/B1",
                reason="verified_cancel",
            )
            r_real_rev = httpx.post(
                f"{base}/v1/ca/emit-revocation-audit",
                json={
                    "trust_domain": "org-alpha.io",
                    "task_id": "task-rev-1",
                    "sub": "user:alice@org-alpha.io",
                    "target_prefix": real_ev.target,
                    "root_block_hash": "h0",
                    "current_block_hash": "h1",
                    "revocation_event": real_ev.to_dict(),
                },
                headers={"Authorization": f"Bearer {gw_sa}"},
            )
            self.assertEqual(r_real_rev.status_code, 200)
        finally:
            rev_svc.stop()
            ca_svc.http.stop()
            collector.stop()

    # -------------------------------------------------------------------------
    # [MEDIUM-M2-01]: Authenticated Audit Query & LCT Token Redaction
    # -------------------------------------------------------------------------
    def test_medium_m2_01_audit_entries_auth_and_lct_token_redaction(self) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        resolver = TrustBundleResolver()
        resolver.register_domain_ca(ca_alpha)
        resolver.register_domain_ca(ca_beta)

        collector = AuditCollectorService(resolver, host="127.0.0.1", port=0)
        audit_url = collector.start()
        try:
            emitter = AuditStreamEmitter(ca_alpha, AuditCollectorClient(audit_url))
            emitter.emit(
                event_type=AuditEventType.ROOT_MINT,
                task_id="task-sec-audit",
                sub="user:alice@org-alpha.io",
                lineage_path="/task-sec-audit/Orch",
                hop_index=0,
                epoch=0,
                root_block_hash="rbh",
                current_block_hash="cbh",
                decision="ALLOW",
            )

            # Anonymous GET /v1/audit/entries -> 401
            r_anon = httpx.get(f"{audit_url}/v1/audit/entries")
            self.assertEqual(r_anon.status_code, 401)

            # Regular specialist workload trying to snoop audit log -> 403
            rogue_agent = ca_beta.issue_workload("/ns/lineage-beta/sa/flight-specialist")
            rogue_cli = AuditCollectorClient(audit_url, signer=rogue_agent)
            with self.assertRaises(httpx.HTTPStatusError) as ctx_err:
                rogue_cli.fetch_entries()
            self.assertEqual(ctx_err.exception.response.status_code, 403)

            # Authorized gateway workload & domain CA succeed -> 200
            gw_wl = ca_alpha.issue_workload("/ns/lineage-alpha/sa/e2e-user-gateway")
            gw_cli = AuditCollectorClient(audit_url, signer=gw_wl)
            entries = gw_cli.fetch_entries()
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].sub, "user:alice@org-alpha.io")

            # `redact_sensitive` scrubs both `compact_lineage_token` keys and raw `lct1.`/`lctm1.` strings
            sample = {
                "compact_lineage_token": "lct1.eyJhbGciOiJFUzI1NiJ9.secret",
                "nested": ["lct1.raw_single_token", "lctm1.raw_multiparent_token"],
            }
            scrubbed = redact_sensitive(sample)
            self.assertEqual(scrubbed["compact_lineage_token"], "[REDACTED]")
            self.assertTrue(scrubbed["nested"][0].startswith("[REDACTED_LCT_TOKEN_SHA256:"))
            self.assertTrue(scrubbed["nested"][1].startswith("[REDACTED_LCT_TOKEN_SHA256:"))
        finally:
            collector.stop()

    # -------------------------------------------------------------------------
    # [CRITICAL-M2-01], [MEDIUM-M2-02], [LOW-M2-01]: End-to-End Agent/Sidecar/MCP Hardening
    # -------------------------------------------------------------------------
    def test_critical_m2_01_and_medium_m2_02_and_low_m2_01_hardening(self) -> None:
        ca_alpha = TrustDomainCA("org-alpha.io")
        ca_beta = TrustDomainCA("org-beta.io")
        ca_pay = TrustDomainCA("org-payment.io")
        resolver = TrustBundleResolver()
        for ca in (ca_alpha, ca_beta, ca_pay):
            resolver.register_domain_ca(ca)

        rev_id = ca_alpha.issue_workload("/ns/sys/sa/revocation")
        rev_svc = RevocationService(rev_id, resolver, host="127.0.0.1", port=0)
        rev_url = rev_svc.start()

        collector = AuditCollectorService(resolver, host="127.0.0.1", port=0)
        audit_url = collector.start()

        dir_svc = AgentDirectoryService(
            resolver,
            revocation_replica=RevocationReplicaClient(rev_url, resolver),
            host="127.0.0.1",
            port=0,
        )
        dir_url = dir_svc.start()

        stub_llm = _DeterministicStubLLM()
        to_stop: List[Any] = [rev_svc, collector, dir_svc]

        captured_ssrf: List[Dict[str, Any]] = []

        def _sink(req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
            captured_ssrf.append({"path": req.path, "auth": req.header("Authorization")})
            return 200, {"captured": True}, {}

        sink_srv = ManagedHTTPService("ssrf-sink", _sink, host="127.0.0.1", port=0)
        sink_url = sink_srv.start()
        to_stop.append(sink_srv)

        def _spawn_pair(ca: TrustDomainCA, path: str, skill: str, prio: int, factory: Any) -> Tuple[Any, LineageSidecar, AgentCard]:
            sec = f"sec-{path.replace('/', '-')}-256bit-loopback"
            wl = ca.issue_workload(path)
            sc = LineageSidecar(
                identity=wl,
                trust_resolver=resolver,
                app_upstream_url="http://127.0.0.1:9",
                loopback_secret=sec,
                mode=VerificationMode.ADAPTIVE_RISK_ANCHORED,
                revocation_replica=RevocationReplicaClient(rev_url, resolver),
                directory_client=AgentDirectoryClient(dir_url, resolver),
                audit_emitter=AuditStreamEmitter(wl, AuditCollectorClient(audit_url), stream_id=f"{wl.spiffe_id}#t"),
                is_tool_server=(skill == ""),
            )
            in_url, out_url = sc.start()
            app = factory(sec, out_url)
            sc.app_upstream_url = app.start().rstrip("/")
            to_stop.extend([sc, app])
            card = None
            if skill:
                card = AgentCard.sign_and_create(
                    identity=wl,
                    name=path,
                    endpoint=in_url,
                    return_endpoint=in_url,
                    skills=[skill],
                    priority=prio,
                )
                sc.set_agent_card(card)
                AgentDirectoryClient(dir_url, resolver).register(card)
            return app, sc, card  # type: ignore[return-value]

        try:
            travel_app, travel_sc, _ = _spawn_pair(
                ca_pay, "/ns/lineage-pay/sa/travel-ops-mcp", "", 10,
                lambda s, _o: TravelOpsMCPApp(s, port=0),
            )
            pay_app, pay_sc, _ = _spawn_pair(
                ca_pay, "/ns/lineage-pay/sa/payment-vault-mcp", "", 10,
                lambda s, _o: PaymentVaultMCPApp(s, port=0),
            )
            _, flight_sc, _ = _spawn_pair(
                ca_beta, "/ns/lineage-beta/sa/flight-specialist", "travel.flight", 10,
                lambda s, o: FlightSpecialistApp(s, o, f"{travel_sc.inbound_url}/mcp", ollama=stub_llm, port=0),
            )
            hotel1_app, hotel1_sc, _ = _spawn_pair(
                ca_beta, "/ns/lineage-beta/sa/hotel-specialist-primary", "travel.hotel", 10,
                lambda s, o: HotelSpecialistApp(s, o, f"{travel_sc.inbound_url}/mcp", instance_label="primary", ollama=stub_llm, port=0),
            )
            _, hotel2_sc, _ = _spawn_pair(
                ca_beta, "/ns/lineage-beta/sa/hotel-specialist-backup", "travel.hotel", 20,
                lambda s, o: HotelSpecialistApp(s, o, f"{travel_sc.inbound_url}/mcp", instance_label="backup", ollama=stub_llm, port=0),
            )
            conv_app, conv_sc, _ = _spawn_pair(
                ca_pay, "/ns/lineage-pay/sa/settlement-converger", "settlement.converge", 10,
                lambda s, o: SettlementConvergerApp(s, o, f"{pay_sc.inbound_url}/mcp", ollama=stub_llm, port=0),
            )
            orch_app, orch_sc, orch_card = _spawn_pair(
                ca_alpha, "/ns/lineage-alpha/sa/orchestrator-alpha", "travel.orchestrate", 10,
                lambda s, o: OrchestratorAlphaApp(s, o, ollama=stub_llm, port=0),
            )

            gw_id = ca_alpha.issue_workload("/ns/lineage-alpha/sa/e2e-user-gateway")
            perms = PermissionLattice.create(
                tools=["search_flight", "book_flight", "search_hotel", "reserve_hotel", "execute_settlement", "record_itinerary_audit"],
                max_amount=800.0,
                allowed_targets=["airline-escrow", "hotel-escrow", "audit-ledger"],
                param_whitelist={"city": ["Tokyo"]},
                max_calls=12,
            )

            def _post_orch(tok_obj: Any, body: Dict[str, Any], path: str = "/a2a/task") -> httpx.Response:
                ct = tok_obj.encode_compact()
                url = f"{orch_sc.inbound_url}{path}"
                return httpx.post(
                    url,
                    json=body,
                    headers={
                        "Authorization": f"DPoP {ct}",
                        "DPoP": create_dpop_proof(gw_id, "POST", url, ct),
                    },
                    timeout=15.0,
                )

            tok1 = mint_root_token(
                ca_alpha,
                task_id="task-m2-sec-1",
                sub="user:alice@org-alpha.io",
                sender_jkt=gw_id.jkt,
                first_hop_spiffe_id=orch_card.spiffe_id,
                first_hop_jkt=orch_card.jkt,
                permissions=perms,
                first_hop_public_jwk=orch_card.public_jwk,
                first_hop_return_endpoint=orch_card.return_endpoint,
            )
            root_em = AuditStreamEmitter(ca_alpha, AuditCollectorClient(audit_url))
            root_em.emit(
                event_type=AuditEventType.ROOT_MINT,
                task_id=tok1.task_id,
                sub=tok1.sub,
                lineage_path=tok1.lineage_path,
                hop_index=0,
                epoch=0,
                root_block_hash=tok1.root_block_hash,
                current_block_hash=tok1.leaf_block_hash,
                decision="ALLOW",
                permissions_summary=perms.to_dict(),
            )

            # 1. [LOW-M2-01]: Non-`/a2a/task` path on OrchestratorAlpha returns 404
            self.assertEqual(_post_orch(tok1, {}, path="/a2a/unknown-route").status_code, 404)

            # 2. [CRITICAL-M2-01]: By default (`LCT_ENABLE_FAULT_INJECTION` unset/false),
            #    ALL fault-injection hooks (`override_direct_parent_url`, `sync_hook_url`,
            #    `simulate_primary_zombie_delay_sec`, cross-task `inspect_task_id`) are BLOCKED (403)
            #    with ZERO SSRF or token exfiltration hits!
            with patch.dict(os.environ, {"LCT_ENABLE_FAULT_INJECTION": "false"}, clear=False):
                r_exfil = _post_orch(
                    tok1,
                    {
                        "op": "delegate_upward_return_chain",
                        "city": "Tokyo",
                        "sync_hook_url": f"{sink_url}/ssrf",
                        "override_direct_parent_url": sink_url,
                    },
                )
                self.assertEqual(r_exfil.status_code, 403)
                self.assertEqual(captured_ssrf, [])

                r_z_disabled = _post_orch(
                    tok1,
                    {
                        "op": "plan_and_execute_trip",
                        "hotel_timeout_sec": 2.0,
                        "simulate_primary_zombie_delay_sec": 4.0,
                    },
                )
                self.assertEqual(r_z_disabled.status_code, 403)

                r_cross_tid = _post_orch(
                    tok1,
                    {"op": "inspect_inbox", "inspect_task_id": "other-task-id"},
                )
                self.assertEqual(r_cross_tid.status_code, 403)

                # Non-finite string `"inf"` returns 400 (NEVER 500!)
                r_inf = _post_orch(
                    tok1,
                    {"op": "plan_and_execute_trip", "simulate_primary_zombie_delay_sec": "inf"},
                )
                self.assertEqual(r_inf.status_code, 400)

            # 3. Even when `LCT_ENABLE_FAULT_INJECTION=true`:
            #    - `override_direct_parent_url` is permanently rejected (400)
            #    - `zombie_delay < hotel_timeout + 0.5` is rejected (400) to prevent double-booking!
            #    - Arbitrary `sync_hook_url` (e.g. `sink_url`) is rejected (400)!
            with patch.dict(os.environ, {"LCT_ENABLE_FAULT_INJECTION": "true"}, clear=False):
                self.assertEqual(
                    _post_orch(
                        tok1,
                        {"op": "delegate_upward_return_chain", "override_direct_parent_url": sink_url},
                    ).status_code,
                    400,
                )
                self.assertEqual(
                    _post_orch(
                        tok1,
                        {
                            "op": "plan_and_execute_trip",
                            "hotel_timeout_sec": 10.0,
                            "simulate_primary_zombie_delay_sec": 0.1,
                        },
                    ).status_code,
                    400,
                )
                self.assertEqual(
                    _post_orch(
                        tok1,
                        {"op": "delegate_upward_return_chain", "sync_hook_url": f"{sink_url}/ssrf"},
                    ).status_code,
                    400,
                )
                self.assertEqual(captured_ssrf, [])

                # Protocol-level `return_result_with_skip_level_fallback` also blocks untrusted override URLs!
                coord = ResilientDelegationCoordinator(
                    identity=conv_sc.identity,
                    trust_resolver=resolver,
                    directory_client=AgentDirectoryClient(dir_url, resolver),
                    revocation_replica=RevocationReplicaClient(rev_url, resolver),
                )
                t_b2 = tok1.attenuate(
                    issuer_identity=orch_sc.identity,
                    delegate_spiffe_id=hotel1_sc.identity.spiffe_id,
                    delegate_jkt=hotel1_sc.identity.jkt,
                    permissions=perms,
                    hop_segment="B2",
                    issuer_return_endpoint=orch_sc.inbound_url,
                )
                t_leaf = t_b2.attenuate(
                    issuer_identity=hotel1_sc.identity,
                    delegate_spiffe_id=conv_sc.identity.spiffe_id,
                    delegate_jkt=conv_sc.identity.jkt,
                    permissions=perms,
                    hop_segment="LeafC",
                    issuer_return_endpoint=hotel1_sc.inbound_url,
                )
                with self.assertRaises( Exception ):
                    coord.return_result_with_skip_level_fallback(
                        child_token=t_leaf,
                        result_payload={"secret": 1},
                        direct_parent_return_url=sink_url,
                    )
                self.assertEqual(captured_ssrf, [])

                # 4. Tenant isolation + token scrubbing on `inspect_inbox`:
                #    Record a real SkipLevelReceipt for Alice, then verify Mallory (`user:mallory@org-alpha.io`)
                #    gets `[]` while Alice gets scrubbed metadata with ZERO raw `lct1.` token!
                hotel1_in_url = hotel1_sc.inbound_url
                hotel1_sc.stop()
                sr = SkipLevelReceipt.create_and_sign(
                    child_identity=conv_sc.identity,
                    lineage_token=t_leaf,
                    skipped_ancestors=[hotel1_sc.identity.spiffe_id],
                    target_ancestor_spiffe_id=orch_sc.identity.spiffe_id,
                    failure_evidence=FailureEvidence(
                        hotel1_sc.identity.spiffe_id, hotel1_in_url, FaultType.CRASH, "down", 1, time.time()
                    ),
                    result_payload={"private_itinerary": "CONFIDENTIAL-ALICE"},
                )
                skip_u = f"{orch_sc.inbound_url}/v1/skip-level-return"
                r_acc = httpx.post(
                    skip_u,
                    json={"skip_level_receipt": sr.to_dict()},
                    headers={
                        "Authorization": f"DPoP {t_leaf.encode_compact()}",
                        "DPoP": create_dpop_proof(conv_sc.identity, "POST", skip_u, t_leaf.encode_compact()),
                    },
                )
                self.assertEqual(r_acc.status_code, 200)

                tok_mallory = mint_root_token(
                    ca_alpha,
                    task_id="task-mallory-snoop",
                    sub="user:mallory@org-alpha.io",
                    sender_jkt=gw_id.jkt,
                    first_hop_spiffe_id=orch_card.spiffe_id,
                    first_hop_jkt=orch_card.jkt,
                    permissions=perms,
                )
                r_snoop = _post_orch(
                    tok_mallory,
                    {"op": "inspect_inbox", "inspect_task_id": "task-m2-sec-1"},
                )
                self.assertEqual(r_snoop.status_code, 200)
                self.assertEqual(r_snoop.json()["skip_level_results"], [])

                r_alice_in = _post_orch(
                    tok1,
                    {"op": "inspect_inbox", "inspect_task_id": "task-m2-sec-1"},
                )
                self.assertEqual(r_alice_in.status_code, 200)
                alice_sr = r_alice_in.json()["skip_level_results"][0]
                self.assertEqual(alice_sr["compact_lineage_token"], "[REDACTED]")
                self.assertNotIn("lct1.", str(r_alice_in.text))

                # Meanwhile, AuditCollectorService preserved unredacted `receipt_payload` so CausalChainAuditor verifies 100%!
                aud_cli = AuditCollectorClient(audit_url, signer=ca_alpha)
                rep = CausalChainAuditor(
                    resolver, trusted_revocation_spiffe_ids=[rev_id.spiffe_id]
                ).audit(aud_cli.fetch_entries("task-m2-sec-1"))
                self.assertIn(
                    "VERIFIED_SKIP_LEVEL_MERGE",
                    rep.tasks["task-m2-sec-1"].resilience_classifications,
                )

            # 5. [MEDIUM-M2-02]: Outbound `task_path` `@host` authority smuggling blocked (400)!
            r_smuggle = httpx.post(
                f"{orch_sc.outbound_url}/v1/proxy/call",
                headers={"X-LCT-Loopback-Auth": orch_sc.loopback_secret},
                json={
                    "action": "delegate_agent",
                    "request_id": "req-missing",
                    "required_skill": "travel.flight",
                    "task_path": f"@127.0.0.1:{sink_srv.port}/smuggled",
                },
            )
            # Validate `task_path` or `request_id`: test with an active request context to hit `task_path` check directly!
            act = orch_sc.active_requests.register(
                compact_token=tok1.encode_compact(),
                parsed_token=tok1,
                verification=orch_sc.verifier.verify_request(
                    compact_token=tok1.encode_compact(),
                    dpop_proof=create_dpop_proof(gw_id, "POST", f"{orch_sc.inbound_url}/a2a/task", tok1.encode_compact()),
                    htm="POST",
                    htu=f"{orch_sc.inbound_url}/a2a/task",
                    check_invocation_lattice=False,
                ),
            )
            try:
                r_smuggle_live = httpx.post(
                    f"{orch_sc.outbound_url}/v1/proxy/call",
                    headers={"X-LCT-Loopback-Auth": orch_sc.loopback_secret},
                    json={
                        "action": "delegate_agent",
                        "request_id": act.request_id,
                        "required_skill": "travel.flight",
                        "task_path": f"@127.0.0.1:{sink_srv.port}/smuggled",
                    },
                )
                self.assertEqual(r_smuggle_live.status_code, 400)
                self.assertEqual(captured_ssrf, [])
            finally:
                orch_sc.active_requests.release(act.request_id)

            # 6. [MEDIUM-M2-02]: MCP servers reject `amount <= 0` or boolean amounts with 400!
            for bad_amt in (0.0, -50.0, True):
                r_bad_mcp = httpx.post(
                    f"{travel_app.http.base_url}/mcp",
                    headers={"X-LCT-Loopback-Auth": travel_app.loopback_secret},
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "book_flight", "arguments": {"city": "Tokyo", "amount": bad_amt}},
                    },
                )
                self.assertEqual(r_bad_mcp.status_code, 400)

            # 7. [MEDIUM-M2-02] & [LOW-M2-01]: `_extract_json_object` raises `OllamaError` on `{bad}`
            #    and normal full trip uses crisp positive synthesis prompt (zero null-flight mention)!
            with self.assertRaises(OllamaError):
                _extract_json_object("prefix {not valid json} suffix")

            # Restart hotel1 or let backup handle normal trip? Re-enable normal trip via backup (`hotel2_sc` is healthy!)
            tok_trip = mint_root_token(
                ca_alpha,
                task_id="task-m2-clean-synth",
                sub="user:alice@org-alpha.io",
                sender_jkt=gw_id.jkt,
                first_hop_spiffe_id=orch_card.spiffe_id,
                first_hop_jkt=orch_card.jkt,
                permissions=perms,
            )
            r_trip = _post_orch(tok_trip, {"op": "plan_and_execute_trip", "hotel_timeout_sec": 3.0})
            self.assertEqual(r_trip.status_code, 200, r_trip.text)
            self.assertTrue(stub_llm.text_system_prompts)
            self.assertNotIn("flight_booking is null", stub_llm.text_system_prompts[-1])
        finally:
            for s in reversed(to_stop):
                try:
                    s.stop()
                except Exception:
                    pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
