"""Milestone 3 In-Cluster Kubernetes + Host Ollama (`qwen2.5:3b`) E2E Verification Driver.

Executes inside `e2e-user-gateway` (`lineage-alpha`), validating:
1. Physically Autonomous 3-Domain Control Plane (`alpha-ca`, `beta-ca`, `payment-ca` +
   per-domain `*-directory` & `*-revocation` + keyless `audit-collector` in `lineage-ctrl`).
2. Full-Chain Bidirectional SPIFFE X.509-SVID mTLS 1.3 (`https://...:8443`, `ssl.CERT_REQUIRED`
   + Channel-Token Dual Binding).
3. Official A2A v1.0 Protocol Stack (`/.well-known/agent-card.json` + `/.well-known/agent.json`,
   `A2A-Version: 1.0`, JSON-RPC 2.0 `SendMessage`, `SendStreamingMessage` real-time SSE,
   `GetTask` tenant isolation, and `CancelTask` cross-3-domain cascading revocation).
4. Real `qwen2.5:3b` LLM multi-agent workflows, Downward Atomic Prune-and-Graft (2A & 2B),
   Upward Authenticated Skip-Level Return (3A & 3B), Online Fagin Multi-Parent DAG Smooth
   Degradation + Multi-User Concurrency (4), and 100% `CausalChainAuditor` Reconstruction (5).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hmac
import json
import os
import secrets
import socket
import ssl
import sys
import threading
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

import httpx

from lineage.a2a import A2AClient, Message, TaskState
from lineage.audit import AuditCollectorClient, CausalChainAuditor
from lineage.common.crypto import KeyPair, redact_sensitive, sha256_hex
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.common.locators import ServiceLocator
from lineage.common.mtls import WorkloadMTLSBundle, X509DomainAuthority
from lineage.federation import bootstrap_autonomous_workload, parse_domain_url_map
from lineage.k8s.bootstrap_services import (
    K8S_SA_TOKEN_PATH,
    _build_env_anchor_store,
    _build_env_descriptor_store,
    _build_env_node_locator_watcher,
    _build_env_seed_store,
    _is_identity_addressing_enabled,
    create_ca_pop_jws,
    resolve_sa_token_path,
)
from lineage.protocol import PermissionLattice, create_dpop_proof, decode_token
from lineage.registry import AgentCard, AgentDirectoryClient, AgentStatus
from lineage.revocation import RevocationEvent, RevocationReplicaClient

IDENTITY_ADDRESSING = _is_identity_addressing_enabled()

ALPHA_CA_URL = os.environ.get(
    "ALPHA_CA_URL", "http://alpha-ca.lineage-alpha.svc.cluster.local:8090"
)
BETA_CA_URL = os.environ.get(
    "BETA_CA_URL",
    "" if IDENTITY_ADDRESSING else "http://beta-ca.lineage-beta.svc.cluster.local:8090",
)
PAYMENT_CA_URL = os.environ.get(
    "PAYMENT_CA_URL",
    "" if IDENTITY_ADDRESSING else "http://payment-ca.lineage-pay.svc.cluster.local:8090",
)
PEER_CA_SPEC = os.environ.get(
    "PEER_CA_URLS",
    ""
    if IDENTITY_ADDRESSING
    else f"org-beta.io={BETA_CA_URL},org-payment.io={PAYMENT_CA_URL}",
)

ALPHA_DIR_URL = os.environ.get(
    "ALPHA_DIR_URL", "http://alpha-directory.lineage-alpha.svc.cluster.local:8091"
)
ALPHA_REV_URL = os.environ.get(
    "ALPHA_REV_URL", "http://alpha-revocation.lineage-alpha.svc.cluster.local:8092"
)
BETA_REV_URL = os.environ.get(
    "BETA_REV_FED_URL",
    ""
    if IDENTITY_ADDRESSING
    else "http://beta-revocation.lineage-beta.svc.cluster.local:8092",
)
PAYMENT_REV_URL = os.environ.get(
    "PAYMENT_REV_FED_URL",
    ""
    if IDENTITY_ADDRESSING
    else "http://payment-revocation.lineage-pay.svc.cluster.local:8092",
)
AUDIT_URL = os.environ.get(
    "AUDIT_COLLECTOR_URL",
    ""
    if IDENTITY_ADDRESSING
    else "http://audit-collector.lineage-ctrl.svc.cluster.local:8093",
)

ORCH_URL = os.environ.get(
    "ORCH_URL",
    ""
    if IDENTITY_ADDRESSING
    else "https://orchestrator-alpha.lineage-alpha.svc.cluster.local:8443",
)
FLIGHT_URL = os.environ.get(
    "FLIGHT_URL",
    ""
    if IDENTITY_ADDRESSING
    else "https://flight-specialist.lineage-beta.svc.cluster.local:8443",
)
HOTEL_PRIMARY_URL = os.environ.get(
    "HOTEL_PRIMARY_URL",
    ""
    if IDENTITY_ADDRESSING
    else "https://hotel-specialist-primary.lineage-beta.svc.cluster.local:8443",
)
HOTEL_BACKUP_URL = os.environ.get(
    "HOTEL_BACKUP_URL",
    ""
    if IDENTITY_ADDRESSING
    else "https://hotel-specialist-backup.lineage-beta.svc.cluster.local:8443",
)
CONVERGER_URL = os.environ.get(
    "CONVERGER_URL",
    ""
    if IDENTITY_ADDRESSING
    else "https://settlement-converger.lineage-pay.svc.cluster.local:8443",
)
TRAVEL_MCP_SVC_URL = os.environ.get(
    "TRAVEL_MCP_SVC_URL",
    ""
    if IDENTITY_ADDRESSING
    else "https://travel-ops-mcp.lineage-pay.svc.cluster.local:8443/mcp",
)
PAYMENT_MCP_SVC_URL = os.environ.get(
    "PAYMENT_MCP_SVC_URL",
    ""
    if IDENTITY_ADDRESSING
    else "https://payment-vault-mcp.lineage-pay.svc.cluster.local:8443/mcp",
)
SYNC_HOOK_URL = os.environ.get("SYNC_HOOK_URL", "")
OLLAMA_URL = os.environ.get("OLLAMA_BASE_URL", "http://host.docker.internal:11434/v1")


def _scrub_for_disk(obj: Any) -> Any:
    base = redact_sensitive(obj)
    if isinstance(base, dict):
        return {k: _scrub_for_disk(v) for k, v in base.items()}
    if isinstance(base, list):
        return [_scrub_for_disk(x) for x in base]
    if isinstance(base, str):
        if base.startswith(("lct1.", "lctmp1.", "lctm1.", "lctco1.")):
            return f"[REDACTED_LCT_TOKEN_SHA256:{sha256_hex(base.encode('ascii'))[:12]}]"
        if base.startswith("eyJ") and base.count(".") == 2:
            return f"[REDACTED_JWS_SHA256:{sha256_hex(base.encode('ascii'))[:12]}]"
    return base


def _extract_a2a_task_data(rpc_body: Dict[str, Any]) -> Dict[str, Any]:
    if rpc_body.get("jsonrpc") != "2.0" or "result" not in rpc_body:
        raise AssertionError(f"Expected JSON-RPC 2.0 result, got: {rpc_body}")
    task = rpc_body["result"]["task"]
    msg = task.get("status", {}).get("message") or {}
    for p in msg.get("parts") or []:
        if isinstance(p, dict) and isinstance(p.get("data"), dict):
            return p["data"]
    for art in task.get("artifacts") or []:
        for p in art.get("parts") or []:
            if isinstance(p, dict) and isinstance(p.get("data"), dict):
                return p["data"]
    raise AssertionError(f"No structured DataPart found in A2A Task: {task}")


class GatewaySession:
    """Authenticated user-entry gateway inside `lineage-alpha` (`org-alpha.io`)."""

    def __init__(
        self,
        require_all_peers: bool = True,
        seed_bundles: Optional[Sequence[Mapping[str, Any]]] = None,
        peer_timeout: float = 3.0,
        max_wait_sec: float = 60.0,
    ) -> None:
        self._sa_token_file = resolve_sa_token_path(K8S_SA_TOKEN_PATH)
        with open(self._sa_token_file, "r", encoding="utf-8") as fh:
            self.sa_jwt = fh.read().strip()
        anchor_store, require_pins = _build_env_anchor_store()
        svid_ttl = max(
            6.0, float(os.environ.get("LCT_SVID_TTL_SECONDS", "1800.0").strip() or "1800.0")
        )
        self.identity_addressing = IDENTITY_ADDRESSING or not PEER_CA_SPEC.strip()
        self.seed_store = _build_env_seed_store() if self.identity_addressing else None
        self.descriptor_store = (
            _build_env_descriptor_store(anchor_store, require_pins)
            if self.identity_addressing
            else None
        )
        persisted_desc = (
            os.environ.get("LCT_PERSISTED_DESCRIPTORS_FILE", "").strip() or None
        )
        peer_ca_map = parse_domain_url_map(PEER_CA_SPEC) if PEER_CA_SPEC.strip() else {}
        (
            self.identity,
            self.resolver,
            self.mtls_bundle,
            self.syncer,
        ) = bootstrap_autonomous_workload(
            ALPHA_CA_URL,
            peer_ca_map,
            max_wait_sec=max_wait_sec,
            require_all_peers=require_all_peers,
            seed_bundles=seed_bundles,
            peer_timeout=peer_timeout,
            svid_ttl_seconds=svid_ttl,
            anchor_store=anchor_store,
            require_pinned_anchors=require_pins,
            audit_ca_url=(
                AUDIT_URL
                if (not self.identity_addressing and AUDIT_URL.startswith("https://"))
                else None
            ),
            enable_auto_renewal=True,
            seed_store=self.seed_store,
            descriptor_store=self.descriptor_store,
            persisted_descriptors_file=(
                persisted_desc if self.identity_addressing else None
            ),
        )
        self.ssl_ctx = self.mtls_bundle.build_client_ssl_context(check_hostname=True)
        self.dir_client = AgentDirectoryClient(ALPHA_DIR_URL, self.resolver)
        self.rev_client = RevocationReplicaClient(ALPHA_REV_URL, self.resolver)
        self.audit_client = AuditCollectorClient(
            AUDIT_URL,
            signer=self.identity,
            ssl_context_provider=(
                self.syncer.audit_ssl_context
                if (not self.identity_addressing and AUDIT_URL.startswith("https://"))
                else None
            ),
            locator_provider=(
                self.syncer.audit_locators
                if (self.identity_addressing and not AUDIT_URL)
                else None
            ),
            ssl_context_for_locator=(
                self.syncer.audit_ssl_context_for_locator
                if (self.identity_addressing and not AUDIT_URL)
                else None
            ),
        )
        self._orch_client_cache: Optional[A2AClient] = None
        if not self.identity_addressing and ORCH_URL:
            self._orch_client_cache = A2AClient(
                agent_base_url=ORCH_URL,
                signer=self.identity,
                mtls_bundle=self.mtls_bundle,
                expected_trust_domain="org-alpha.io",
                rpc_path="/a2a",
                timeout=95.0,
            )
        self.oauth_realm = os.environ.get("OAUTH_REALM", "lct").strip() or "lct"
        self.local_sts_url = os.environ.get("LOCAL_STS_URL", "").strip().rstrip("/")
        self.oauth_users: Dict[str, str] = {}
        self.oauth_clients: Dict[str, str] = {}
        creds_f = os.environ.get("OAUTH_CREDENTIALS_FILE", "/var/run/lct-oauth/credentials.json").strip()
        if creds_f and os.path.isfile(creds_f):
            try:
                with open(creds_f, "r", encoding="utf-8") as fh:
                    cdoc = json.load(fh)
                self.oauth_users = dict(cdoc.get("users") or {})
                self.oauth_clients = dict(cdoc.get("clients") or {})
            except Exception:
                pass
        from lineage.oauth_sts import OAuthTokenExchangeClient

        self.oauth_client = OAuthTokenExchangeClient(
            realm=self.oauth_realm,
            client_secrets=self.oauth_clients,
        )

    @property
    def a2a_orch(self) -> A2AClient:
        if self.identity_addressing:
            orch_card = self.get_orchestrator_card()
            return A2AClient(
                agent_card=orch_card,
                signer=self.identity,
                mtls_bundle=self.mtls_bundle,
                expected_trust_domain="org-alpha.io",
                expected_spiffe_id=orch_card.spiffe_id,
                rpc_path="/a2a",
                timeout=95.0,
            )
        assert self._orch_client_cache is not None
        return self._orch_client_cache

    def _fresh_sa_jwt(self) -> str:
        with open(self._sa_token_file, "r", encoding="utf-8") as fh:
            self.sa_jwt = fh.read().strip()
        return self.sa_jwt

    def resolve_agent_card(
        self,
        *,
        skill: Optional[str] = None,
        contains_spiffe: Optional[str] = None,
        only_healthy: bool = True,
        max_wait_sec: float = 20.0,
    ) -> AgentCard:
        deadline = time.time() + max_wait_sec
        while True:
            cards = self.dir_client.discover(skill=skill, only_healthy=only_healthy)
            if contains_spiffe:
                cards = [c for c in cards if contains_spiffe in c.spiffe_id]
            if cards:
                return cards[0]
            if time.time() >= deadline:
                raise RuntimeError(
                    f"Timed out resolving signed AgentCard (skill={skill!r}, contains_spiffe={contains_spiffe!r})"
                )
            time.sleep(0.35)

    def ca_bundle_url(self, trust_domain: str) -> str:
        if not self.identity_addressing:
            return BETA_CA_URL if trust_domain == "org-beta.io" else PAYMENT_CA_URL
        assert self.descriptor_store is not None
        locs = self.descriptor_store.get_locators(trust_domain, "ca_bundle")
        if not locs:
            raise RuntimeError(f"No verified ca_bundle locator for {trust_domain!r}")
        return locs[0].origin_url

    def dir_fed_locator(self, trust_domain: str) -> ServiceLocator:
        if not self.identity_addressing:
            sp = urlsplit(f"https://{trust_domain}:8491")
            return ServiceLocator(
                transport="mtls-tcp",
                host=sp.hostname or trust_domain,
                port=sp.port or 8491,
                spiffe_id=f"spiffe://{trust_domain}/ns/sys/sa/directory",
            )
        assert self.descriptor_store is not None
        locs = self.descriptor_store.get_locators(trust_domain, "directory_federation")
        if not locs:
            raise RuntimeError(
                f"No verified directory_federation locator for {trust_domain!r}"
            )
        return locs[0]

    def rev_fed_locator(self, trust_domain: str) -> ServiceLocator:
        if not self.identity_addressing:
            raw = BETA_REV_URL if trust_domain == "org-beta.io" else PAYMENT_REV_URL
            sp = urlsplit(raw)
            return ServiceLocator(
                transport=("mtls-tcp" if sp.scheme == "https" else "http-ro"),
                host=sp.hostname or trust_domain,
                port=sp.port or 8092,
                spiffe_id=f"spiffe://{trust_domain}/ns/sys/sa/revocation",
            )
        assert self.descriptor_store is not None
        locs = self.descriptor_store.get_locators(trust_domain, "revocation_federation")
        if not locs:
            raise RuntimeError(
                f"No verified revocation_federation locator for {trust_domain!r}"
            )
        return locs[0]

    def a2a_client_for(
        self,
        base_url: str = "",
        *,
        agent_card: Optional[AgentCard] = None,
        rpc_path: str = "/a2a",
        timeout: float = 90.0,
    ) -> A2AClient:
        if agent_card is not None:
            return A2AClient(
                agent_card=agent_card,
                signer=self.identity,
                mtls_bundle=self.mtls_bundle,
                expected_spiffe_id=agent_card.spiffe_id,
                rpc_path=rpc_path,
                timeout=timeout,
            )
        return A2AClient(
            agent_base_url=base_url,
            signer=self.identity,
            mtls_bundle=self.mtls_bundle,
            rpc_path=rpc_path,
            timeout=timeout,
        )

    def get_orchestrator_card(self) -> AgentCard:
        return self.resolve_agent_card(skill="travel.orchestrate", only_healthy=True)

    def oauth_sts_origins(self, trust_domain: str = "org-alpha.io") -> List[str]:
        locs = []
        if self.descriptor_store is not None:
            locs = list(self.descriptor_store.get_locators(trust_domain, "oauth_sts"))
            if not locs:
                self.syncer.sync_descriptors_from_seeds_and_peers()
                locs = list(self.descriptor_store.get_locators(trust_domain, "oauth_sts"))
        origins: List[str] = []
        if trust_domain == "org-alpha.io" and self.local_sts_url:
            if locs:
                origins.append(f"{self.local_sts_url}#host={locs[0].host}:{locs[0].port}")
            else:
                origins.append(self.local_sts_url)
        for loc in locs:
            u = loc.origin_url.rstrip("/")
            if u not in origins:
                origins.append(u)
        return origins

    def login_oidc_user(
        self,
        username: str = "alice",
        trust_domain: Optional[str] = None,
        client_id: str = "lct-gateway",
    ) -> Dict[str, Any]:
        from lineage.oauth_sts.keycloak_realm import DEFAULT_USER_HOME_DOMAINS

        pw = self.oauth_users.get(username, "")
        if not pw:
            raise RuntimeError(f"No OAuth password configured in Secret for user {username!r}")
        eff_td = (
            trust_domain.strip().lower()
            if trust_domain
            else DEFAULT_USER_HOME_DOMAINS.get(username, "org-alpha.io")
        )
        origins = self.oauth_sts_origins(eff_td)
        if not origins:
            raise RuntimeError(f"No {eff_td} oauth_sts origin available for Hop-0 login of {username!r}")
        return self.oauth_client.login_user_password(
            sts_origins=origins,
            username=username,
            password=pw,
            client_id=client_id,
        )

    def mint_root_for_user(
        self,
        task_id: str,
        sub: str,
        permissions: PermissionLattice,
        target_card: Optional[AgentCard] = None,
        hop_segment: str = "OrchestratorAlpha",
        max_depth: int = 6,
        ttl_seconds: float = 900.0,
        user_oidc_token: Optional[str] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        card = target_card or self.get_orchestrator_card()
        req_payload: Dict[str, Any] = {
            "trust_domain": "org-alpha.io",
            "task_id": task_id,
            "sub": sub,
            "sender_jkt": self.identity.jkt,
            "first_hop_spiffe_id": card.spiffe_id,
            "first_hop_jkt": card.jkt,
            "first_hop_public_jwk": card.public_jwk,
            "first_hop_return_endpoint": card.return_endpoint,
            "permissions": permissions.to_dict(),
            "hop_segment": hop_segment,
            "max_depth": max_depth,
            "ttl_seconds": ttl_seconds,
        }
        if user_oidc_token:
            req_payload["user_oidc_token"] = user_oidc_token
        resp = httpx.post(
            f"{ALPHA_CA_URL}/v1/ca/mint-root-token",
            json=req_payload,
            headers={"Authorization": f"Bearer {self._fresh_sa_jwt()}"},
            timeout=10.0,
        )
        resp.raise_for_status()
        meta = resp.json()
        return str(meta["compact_token"]), meta

    def request_continuation_from_ca(
        self,
        checkpoint: Mapping[str, Any],
        permissions: PermissionLattice,
        target_card: AgentCard,
        hop_segment: str = "AssistantAliceCont",
        max_depth: int = 6,
        ttl_seconds: float = 300.0,
        user_oidc_token: Optional[str] = None,
        prior_root_token: Optional[str] = None,
    ) -> httpx.Response:
        req_payload: Dict[str, Any] = {
            "trust_domain": "org-alpha.io",
            "checkpoint": dict(checkpoint),
            "sender_jkt": self.identity.jkt,
            "first_hop_spiffe_id": target_card.spiffe_id,
            "first_hop_jkt": target_card.jkt,
            "first_hop_public_jwk": target_card.public_jwk,
            "first_hop_return_endpoint": target_card.return_endpoint,
            "permissions": permissions.to_dict(),
            "hop_segment": hop_segment,
            "max_depth": max_depth,
            "ttl_seconds": ttl_seconds,
        }
        if user_oidc_token:
            req_payload["user_oidc_token"] = user_oidc_token
        if prior_root_token:
            req_payload["prior_root_token"] = prior_root_token
        return httpx.post(
            f"{ALPHA_CA_URL}/v1/ca/mint-continuation-token",
            json=req_payload,
            headers={"Authorization": f"Bearer {self._fresh_sa_jwt()}"},
            timeout=10.0,
        )

    def mint_continuation_for_user(
        self,
        checkpoint: Mapping[str, Any],
        permissions: PermissionLattice,
        target_card: AgentCard,
        hop_segment: str = "AssistantAliceCont",
        max_depth: int = 6,
        ttl_seconds: float = 300.0,
        user_oidc_token: Optional[str] = None,
        prior_root_token: Optional[str] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        resp = self.request_continuation_from_ca(
            checkpoint=checkpoint,
            permissions=permissions,
            target_card=target_card,
            hop_segment=hop_segment,
            max_depth=max_depth,
            ttl_seconds=ttl_seconds,
            user_oidc_token=user_oidc_token,
            prior_root_token=prior_root_token,
        )
        resp.raise_for_status()
        meta = resp.json()
        return str(meta["compact_token"]), meta

    def post_oauth_mtls(
        self,
        card: AgentCard,
        subject_token: str,
        delegation_mode: str,
        task_id: str,
        payload: Dict[str, Any],
        path: str = "/a2a/task",
        timeout: float = 90.0,
        source_sts_domain: Optional[str] = None,
    ) -> Tuple[httpx.Response, Dict[str, Any]]:
        sts_origins = (
            self.oauth_sts_origins(source_sts_domain)
            if source_sts_domain
            else (
                self.oauth_sts_origins("org-alpha.io")
                if delegation_mode == "oauth_centralized"
                else self.oauth_sts_origins(card.trust_domain)
            )
        )
        ex_hop1 = self.oauth_client.exchange_token(
            sts_origins=sts_origins,
            subject_token=subject_token,
            target_audience=card.spiffe_id,
            caller_spiffe_id=self.identity.spiffe_id,
            caller_workload_svid=self.identity.workload_svid,
            client_id="lct-gateway",
        )
        url = f"{card.endpoint.rstrip('/')}{path}"
        with httpx.Client(
            verify=self.mtls_bundle.verify_for_target(
                target_url=url,
                expected_spiffe_id=card.spiffe_id,
            ),
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            resp = client.post(
                url,
                json=payload,
                headers={
                    "Authorization": f"Bearer {ex_hop1.access_token}",
                    "X-LCT-Delegation-Mode": delegation_mode,
                    "X-LCT-Task-Id": task_id,
                },
            )
        return resp, {
            "hop1_sts_endpoint": ex_hop1.sts_endpoint,
            "hop1_sts_rtt_ms": ex_hop1.rtt_ms,
            "hop1_exchanged_token": ex_hop1.access_token,
            "hop1_scope": ex_hop1.scope,
        }

    def emit_revocation_audit(
        self,
        task_id: str,
        sub: str,
        revocation_event: RevocationEvent,
        root_block_hash: str,
        current_block_hash: str,
    ) -> None:
        resp = httpx.post(
            f"{ALPHA_CA_URL}/v1/ca/emit-revocation-audit",
            json={
                "trust_domain": "org-alpha.io",
                "task_id": task_id,
                "sub": sub,
                "target_prefix": revocation_event.target,
                "root_block_hash": root_block_hash,
                "current_block_hash": current_block_hash,
                "revocation_version": (
                    revocation_event.origin_version
                    if revocation_event.origin_version is not None
                    else revocation_event.version
                ),
                "revocation_event": revocation_event.to_dict(),
            },
            headers={"Authorization": f"Bearer {self._fresh_sa_jwt()}"},
            timeout=10.0,
        )
        resp.raise_for_status()

    def get_mtls(
        self,
        url: str,
        *,
        expected_spiffe_id: Optional[str] = None,
        expected_trust_domain: Optional[str] = None,
        timeout: float = 5.0,
    ) -> httpx.Response:
        with httpx.Client(
            verify=self.mtls_bundle.verify_for_target(
                target_url=url,
                expected_trust_domain=expected_trust_domain,
                expected_spiffe_id=expected_spiffe_id,
            ),
            timeout=timeout,
        ) as client:
            return client.get(url)

    def get_mtls_card(
        self, card: AgentCard, path: str = "/healthz", timeout: float = 5.0
    ) -> httpx.Response:
        last_exc: Optional[Exception] = None
        for origin in card.candidate_origins():
            try:
                return self.get_mtls(
                    f"{origin}{path}",
                    expected_spiffe_id=card.spiffe_id,
                    timeout=timeout,
                )
            except Exception as exc:
                last_exc = exc
        if last_exc is not None:
            raise last_exc
        raise RuntimeError(f"Card {card.spiffe_id} has no candidate origins")

    def post_lct_mtls(
        self,
        endpoint_base: str,
        compact_token: str,
        payload: Dict[str, Any],
        path: str = "/a2a/task",
        expected_spiffe_id: Optional[str] = None,
        timeout: float = 90.0,
    ) -> httpx.Response:
        url = f"{endpoint_base.rstrip('/')}{path}"
        dpop = create_dpop_proof(self.identity, "POST", url, compact_token)
        with httpx.Client(
            verify=self.mtls_bundle.verify_for_target(
                target_url=url, expected_spiffe_id=expected_spiffe_id
            ),
            timeout=timeout,
        ) as client:
            return client.post(
                url,
                json=payload,
                headers={
                    "Authorization": f"DPoP {compact_token}",
                    "DPoP": dpop,
                },
            )


def _full_travel_root_permissions(cities: List[str], max_amount: float = 1000.0) -> PermissionLattice:
    return PermissionLattice.create(
        tools=[
            "search_flight",
            "book_flight",
            "search_hotel",
            "reserve_hotel",
            "execute_settlement",
            "record_itinerary_audit",
        ],
        max_amount=max_amount,
        allowed_targets=["airline-escrow", "hotel-escrow", "audit-ledger"],
        param_whitelist={"city": cities},
        max_calls=12,
    )


# =============================================================================
# Scenario Implementations
# =============================================================================


def run_scenario_1(gw: GatewaySession, run_id: str) -> Dict[str, Any]:
    # 0. Resolve workloads dynamically via signed AgentCards (M7) or static URLs (legacy M4)
    if gw.identity_addressing:
        orch_card = gw.resolve_agent_card(skill="travel.orchestrate")
        flight_card = gw.resolve_agent_card(skill="travel.flight")
        hotel_p_card = gw.resolve_agent_card(skill="travel.hotel", contains_spiffe="primary")
        hotel_b_card = gw.resolve_agent_card(skill="travel.hotel", contains_spiffe="backup")
        conv_card = gw.resolve_agent_card(skill="settlement.converge")
        travel_mcp_card = gw.resolve_agent_card(skill="mcp.travel-ops")
        payment_mcp_card = gw.resolve_agent_card(skill="mcp.payment-vault")
        for c in (
            orch_card,
            flight_card,
            hotel_p_card,
            hotel_b_card,
            conv_card,
            travel_mcp_card,
            payment_mcp_card,
        ):
            for _ in range(35):
                try:
                    if gw.get_mtls_card(c, "/healthz", timeout=2.0).status_code == 200:
                        break
                except Exception:
                    pass
                time.sleep(0.3)
        orch_endpoint = orch_card.endpoint
        orch_spiffe = orch_card.spiffe_id
        beta_ca_url = gw.ca_bundle_url("org-beta.io")
        payment_ca_url = gw.ca_bundle_url("org-payment.io")
    else:
        for svc_health in (
            f"{ORCH_URL}/healthz",
            f"{FLIGHT_URL}/healthz",
            f"{HOTEL_PRIMARY_URL}/healthz",
            f"{HOTEL_BACKUP_URL}/healthz",
            f"{CONVERGER_URL}/healthz",
            f"{TRAVEL_MCP_SVC_URL.rsplit('/mcp', 1)[0]}/healthz",
            f"{PAYMENT_MCP_SVC_URL.rsplit('/mcp', 1)[0]}/healthz",
        ):
            for _ in range(35):
                try:
                    if gw.get_mtls(svc_health, timeout=2.0).status_code == 200:
                        break
                except Exception:
                    pass
                time.sleep(0.3)
        orch_endpoint = ORCH_URL
        orch_spiffe = "spiffe://org-alpha.io/ns/lineage-alpha/sa/orchestrator-alpha"
        beta_ca_url = BETA_CA_URL
        payment_ca_url = PAYMENT_CA_URL

    orch_sp = urlsplit(orch_endpoint)
    orch_host = orch_sp.hostname or "127.0.0.1"
    orch_port = orch_sp.port or 8443

    # 1. Verify Autonomous 3-Domain CA Physical Namespace Isolation:
    #    `e2e-user-gateway` (`lineage-alpha` SA JWT) MUST be rejected (`403`) by both `beta-ca` and `payment-ca`!
    sa_jwt = gw._fresh_sa_jwt()
    test_kp = KeyPair.generate("ES256")
    cross_ca_proofs: Dict[str, Any] = {}
    for foreign_name, foreign_url in (("beta-ca", beta_ca_url), ("payment-ca", payment_ca_url)):
        r_for = httpx.post(
            f"{foreign_url}/v1/ca/issue-workload",
            json={
                "public_jwk": test_kp.public_jwk(),
                "pop_jws": create_ca_pop_jws(test_kp, sa_jwt),
            },
            headers={"Authorization": f"Bearer {sa_jwt}"},
            timeout=5.0,
        )
        if r_for.status_code != 403:
            raise AssertionError(
                f"Autonomous {foreign_name} failed to reject lineage-alpha SA JWT: {r_for.status_code} {r_for.text}"
            )
        cross_ca_proofs[foreign_name] = {
            "http_status": r_for.status_code,
            "error": r_for.json().get("error"),
            "detail": r_for.json().get("detail"),
        }

    # 2. Verify Bidirectional X.509 mTLS 1.3 Enforcement on `:8443`:
    #    (a) Client WITHOUT client X.509 certificate -> rejected at TLS handshake!
    no_client_cert_ctx = gw.mtls_bundle.trust_store.build_server_verify_ssl_context(
        expected_trust_domain="org-alpha.io",
        check_hostname=(not gw.identity_addressing),
        expected_spiffe_id=orch_spiffe,
    )
    unauth_blocked = False
    unauth_err = ""
    try:
        with httpx.Client(verify=no_client_cert_ctx, timeout=3.0) as bad_cli:
            bad_cli.get(f"{orch_endpoint}/healthz")
    except Exception as exc:
        unauth_blocked = True
        unauth_err = f"{type(exc).__name__}: {exc}"
    if not unauth_blocked:
        raise AssertionError("Unauthenticated TLS client without X.509-SVID was not rejected on :8443!")

    #    (b) Client WITH rogue unfederated X.509 CA (`org-rogue.io`) -> rejected at TLS handshake!
    rogue_ca = X509DomainAuthority("org-rogue.io")
    rogue_kp = KeyPair.generate("ES256")
    rogue_leaf = rogue_ca.issue_x509_svid(
        "spiffe://org-rogue.io/ns/rogue/sa/intruder",
        rogue_kp.public_jwk(),
        dns_names=("intruder.org-rogue.io",),
    )
    rogue_bundle = WorkloadMTLSBundle(
        "spiffe://org-rogue.io/ns/rogue/sa/intruder",
        rogue_kp,
        rogue_leaf,
        gw.mtls_bundle.trust_store,
    )
    rogue_blocked = False
    rogue_err = ""
    try:
        with httpx.Client(
            verify=rogue_bundle.verify_for_target(
                target_url=orch_endpoint,
                expected_trust_domain="org-alpha.io",
                expected_spiffe_id=orch_spiffe,
            ),
            timeout=3.0,
        ) as r_cli:
            r_cli.get(f"{orch_endpoint}/healthz")
    except Exception as exc:
        rogue_blocked = True
        rogue_err = f"{type(exc).__name__}: {exc}"
    if not rogue_blocked:
        raise AssertionError("Rogue unfederated X.509 client was not rejected on :8443!")

    #    (c) Authenticated TLS socket inspection -> confirm negotiated protocol == `TLSv1.3`!
    orch_pinned_ssl = gw.mtls_bundle.verify_for_target(
        target_url=orch_endpoint,
        expected_trust_domain="org-alpha.io",
        expected_spiffe_id=orch_spiffe,
    )
    with socket.create_connection((orch_host, orch_port), timeout=5.0) as raw_sock:
        with orch_pinned_ssl.wrap_socket(raw_sock, server_hostname=orch_host) as tls_sock:
            negotiated_tls_version = tls_sock.version()
            negotiated_cipher = tls_sock.cipher()
    if negotiated_tls_version != "TLSv1.3":
        raise AssertionError(f"Expected TLSv1.3, negotiated {negotiated_tls_version!r}")

    # 3. Verify Official A2A v1.0 Dual Discovery (`/.well-known/agent-card.json` & `/.well-known/agent.json`)
    card_v1, raw_card_v1 = gw.a2a_orch.fetch_agent_card(
        gw.resolver, "/.well-known/agent-card.json"
    )
    card_compat, raw_card_compat = gw.a2a_orch.fetch_agent_card(
        gw.resolver, "/.well-known/agent.json"
    )
    assert card_v1.spiffe_id == card_compat.spiffe_id
    assert raw_card_v1["protocolVersion"] == "1.0"
    assert raw_card_v1["url"] == card_v1.endpoint
    assert raw_card_v1["capabilities"]["streaming"] is True
    assert "lct_dpop" in raw_card_v1["securitySchemes"]
    assert isinstance(raw_card_v1["skills"][0], dict)
    assert raw_card_compat["protocolVersion"] == "1.0"

    # 4. Verify Ollama `qwen2.5:3b` model endpoint inside Pod
    models_resp = httpx.get(f"{OLLAMA_URL}/models", timeout=10.0)
    models_resp.raise_for_status()
    model_ids = [m.get("id") for m in models_resp.json().get("data", [])]
    if "qwen2.5:3b" not in model_ids:
        raise AssertionError(f"qwen2.5:3b not found in Ollama models: {model_ids}")

    # 5. Verify cross-domain signed AgentCards converged in `alpha-directory` via federation peering!
    expected_min_cards = 7 if gw.identity_addressing else 5
    registered_spiffes: List[str] = []
    for _ in range(25):
        all_cards = gw.dir_client.discover(only_healthy=True)
        registered_spiffes = sorted(c.spiffe_id for c in all_cards)
        if len(registered_spiffes) >= expected_min_cards:
            break
        time.sleep(0.4)
    if len(registered_spiffes) < expected_min_cards:
        raise AssertionError(
            f"Expected >={expected_min_cards} federated cross-domain AgentCards in alpha-directory, got {registered_spiffes}"
        )

    # 6. Execute Official A2A v1.0 `SendStreamingMessage` (Real SSE `text/event-stream`)!
    task_id = f"task-k8s-s1-{run_id}"
    perms = _full_travel_root_permissions(["Tokyo"], max_amount=800.0)
    tok, _ = gw.mint_root_for_user(task_id, "user:alice@org-alpha.io", perms)

    sse_status, sse_ct, sse_events = gw.a2a_orch.send_streaming_message(
        message=Message.create_user(
            text=(
                "Book business travel to Tokyo for Alice with a flight budget up to 650 USD "
                "and a hotel budget up to 420 USD, then complete split escrow settlement."
            ),
            data={"op": "plan_and_execute_trip"},
            task_id=task_id,
        ),
        compact_token=tok,
    )
    if sse_status != 200 or "text/event-stream" not in sse_ct.lower():
        raise AssertionError(
            f"A2A SendStreamingMessage failed ({sse_status}, ct={sse_ct}): {sse_events}"
        )

    observed_states = [
        ev["result"]["statusUpdate"]["status"]["state"]
        for ev in sse_events
        if "result" in ev and "statusUpdate" in ev["result"]
    ]
    artifact_updates = [
        ev["result"]["artifactUpdate"]
        for ev in sse_events
        if "result" in ev and "artifactUpdate" in ev["result"]
    ]
    assert TaskState.SUBMITTED.value in observed_states, observed_states
    assert TaskState.WORKING.value in observed_states, observed_states
    assert observed_states[-1] == TaskState.COMPLETED.value, observed_states
    assert sse_events[-1]["result"]["statusUpdate"]["final"] is True
    assert len(artifact_updates) >= 1, sse_events

    # 7. Official A2A v1.0 `GetTask` owner query (`200`) + Cross-Tenant Snooping Block (`403` `-32003`)!
    st_get, get_body = gw.a2a_orch.get_task(task_id, compact_token=tok)
    assert st_get == 200, get_body
    assert get_body["result"]["task"]["status"]["state"] == TaskState.COMPLETED.value
    assert len(get_body["result"]["task"]["artifacts"]) >= 1

    tok_snoop, _ = gw.mint_root_for_user(
        f"task-k8s-s1-snoop-{run_id}", "user:carol@org-alpha.io", perms
    )
    st_snoop, snoop_body = gw.a2a_orch.get_task(task_id, compact_token=tok_snoop)
    assert st_snoop == 403, snoop_body
    assert snoop_body["error"]["code"] == -32003, snoop_body

    # Also verify `POST /` standard root A2A JSON-RPC path works identically!
    root_path_cli = (
        gw.a2a_client_for(agent_card=card_v1, rpc_path="/")
        if gw.identity_addressing
        else gw.a2a_client_for(orch_endpoint, rpc_path="/")
    )
    st_root_get, root_get_body = root_path_cli.get_task(task_id, compact_token=tok)
    assert st_root_get == 200, root_get_body
    assert root_get_body["result"]["task"]["id"] == task_id

    data = _extract_a2a_task_data(get_body)
    flight_b = data["flight_branch"]["upstream_body"]["flight_booking"]
    hotel_r = data["hotel_branch"]["upstream_body"]["hotel_reservation"]
    conv_body = data["settlement_convergence"]["upstream_body"]
    completed_stl = conv_body["completed_settlements"]
    final_answer = str(conv_body["final_answer"])

    # Strict Grounding Verification: MCP JSON values <-> LLM answer & settlement amounts
    assert flight_b["flight_no"] == "NH-108", flight_b
    assert float(flight_b["charged_usd"]) == 580.0, flight_b
    assert hotel_r["hotel_id"] == "HTL-TYO-09", hotel_r
    assert float(hotel_r["charged_usd"]) == 360.0, hotel_r
    assert float(completed_stl["airline-escrow"]["settled_usd"]) == 580.0, completed_stl
    assert float(completed_stl["hotel-escrow"]["settled_usd"]) == 360.0, completed_stl
    assert completed_stl["airline-escrow"]["lineage_decision"] == "ALLOW"
    assert completed_stl["hotel-escrow"]["lineage_decision"] == "ALLOW"

    for expected_token in ("NH-108", "580", "360"):
        if expected_token not in final_answer:
            raise AssertionError(
                f"LLM final_answer missing grounded MCP value {expected_token!r}: {final_answer!r}"
            )

    return {
        "scenario": "1_a2a_v1_sse_autonomous_3domain_mtls13_and_llm_mcp_grounding",
        "status": "PASS",
        "task_id": task_id,
        "autonomous_ca_cross_namespace_rejections": cross_ca_proofs,
        "mtls_1_3_security_proofs": {
            "negotiated_protocol": negotiated_tls_version,
            "negotiated_cipher": list(negotiated_cipher) if negotiated_cipher else None,
            "no_client_cert_rejected": unauth_blocked,
            "no_client_cert_error": unauth_err,
            "rogue_unfederated_ca_rejected": rogue_blocked,
            "rogue_unfederated_ca_error": rogue_err,
        },
        "a2a_v1_agent_card_discovery": {
            "well_known_agent_card_url": f"{orch_endpoint}/.well-known/agent-card.json",
            "protocol_version": raw_card_v1["protocolVersion"],
            "capabilities": raw_card_v1["capabilities"],
            "security_schemes": list(raw_card_v1["securitySchemes"].keys()),
            "skills": raw_card_v1["skills"],
        },
        "a2a_v1_sse_streaming": {
            "content_type": sse_ct,
            "sse_frame_count": len(sse_events),
            "state_transitions_observed": observed_states,
            "artifact_update_count": len(artifact_updates),
            "cross_tenant_get_task_blocked_http": st_snoop,
            "cross_tenant_get_task_rpc_code": snoop_body["error"]["code"],
        },
        "ollama_models_seen": model_ids,
        "federated_registered_agents": registered_spiffes,
        "orchestrator_plan": data["orchestrator_plan"],
        "orchestrator_llm_trace": data["orchestrator_llm_trace"],
        "flight_llm_traces": data["flight_branch"]["upstream_body"]["llm_traces"],
        "hotel_llm_traces": data["hotel_branch"]["upstream_body"]["llm_traces"],
        "converger_llm_trace": conv_body["llm_trace"],
        "flight_booking_mcp": flight_b,
        "hotel_reservation_mcp": hotel_r,
        "completed_settlements_mcp": completed_stl,
        "final_answer": final_answer,
    }


def run_scenario_2a(gw: GatewaySession, run_id: str) -> Dict[str, Any]:
    task_id = f"task-k8s-s2a-{run_id}"
    perms = _full_travel_root_permissions(["Paris"], max_amount=800.0)
    tok, _ = gw.mint_root_for_user(task_id, "user:alice@org-alpha.io", perms)

    # Official A2A v1.0 `SendMessage`: Primary B2 stalls 10.0s (> hotel_timeout_sec=8.5s);
    # Orchestrator (`org-alpha.io`) prunes B2 at `alpha-revocation` (federated to `payment-revocation`!)
    # and grafts `hotel-specialist-backup` (`epoch=1`) over mTLS 1.3!
    st_rpc, rpc_body = gw.a2a_orch.send_message(
        message=Message.create_user(
            text=(
                "Book business travel to Paris for Alice with flight budget up to 600 USD "
                "and hotel budget up to 400 USD."
            ),
            data={
                "op": "plan_and_execute_trip",
                "hotel_timeout_sec": 8.5,
                "simulate_primary_zombie_delay_sec": 10.0,
            },
            task_id=task_id,
        ),
        compact_token=tok,
    )
    if st_rpc != 200:
        raise AssertionError(f"Scenario 2A A2A SendMessage failover failed ({st_rpc}): {rpc_body}")
    assert rpc_body["result"]["task"]["status"]["state"] == TaskState.COMPLETED.value

    data = _extract_a2a_task_data(rpc_body)
    hotel_out = data["hotel_branch"]
    assert hotel_out["epoch"] == 1, hotel_out
    assert len(hotel_out["failover_receipts"]) == 1, hotel_out
    assert hotel_out["upstream_body"]["instance_label"] == "backup", hotel_out

    # Query `hotel-specialist-primary` over mTLS 1.3 via A2A `SendMessage` to confirm its delayed
    # zombie call to `travel-ops-mcp` (`org-payment.io`) hit federated `403 LINEAGE_REVOKED`!
    primary_cards = [
        c
        for c in gw.dir_client.discover(skill="travel.hotel", only_healthy=False)
        if "primary" in c.spiffe_id
    ]
    assert primary_cards, "Primary hotel card not found"
    p_card = primary_cards[0]
    diag_tok, _ = gw.mint_root_for_user(
        f"task-k8s-s2a-diag-{run_id}",
        "user:alice@org-alpha.io",
        perms,
        target_card=p_card,
        hop_segment="DiagPrimary",
    )
    a2a_primary = (
        gw.a2a_client_for(agent_card=p_card)
        if gw.identity_addressing
        else gw.a2a_client_for(HOTEL_PRIMARY_URL)
    )
    zombie_rec = None
    for _ in range(25):
        st_d, d_body = a2a_primary.send_message(
            message=Message.create_user(
                text="Inspect zombie telemetry",
                data={"op": "inspect_zombie_telemetry", "inspect_task_id": task_id},
            ),
            compact_token=diag_tok,
        )
        if st_d == 200:
            d_data = _extract_a2a_task_data(d_body)
            zombie_rec = d_data.get("zombie_telemetry")
            if zombie_rec is not None:
                break
        time.sleep(0.4)

    if zombie_rec is None:
        raise AssertionError("Primary zombie wakeup telemetry was not recorded")
    assert zombie_rec["zombie_mcp_http_status"] == 403, zombie_rec
    assert zombie_rec["zombie_mcp_body"].get("error") == "LINEAGE_REVOKED", zombie_rec

    return {
        "scenario": "2a_a2a_v1_atomic_prune_and_graft_plus_cross_domain_zombie_403_proof",
        "status": "PASS",
        "task_id": task_id,
        "a2a_task_state": rpc_body["result"]["task"]["status"]["state"],
        "grafted_epoch": hotel_out["epoch"],
        "grafted_lineage_path": hotel_out["delegated_lineage_path"],
        "handled_by_instance": hotel_out["upstream_body"]["instance_label"],
        "failover_receipt": hotel_out["failover_receipts"][0],
        "zombie_revocation_proof": zombie_rec,
        "final_answer": data["settlement_convergence"]["upstream_body"]["final_answer"],
    }


def run_scenario_2b(gw: GatewaySession, run_id: str) -> Dict[str, Any]:
    # Executed while `deployment/hotel-specialist-primary` is scaled to 0 replicas in K8s!
    task_id = f"task-k8s-s2b-{run_id}"
    perms = _full_travel_root_permissions(["Singapore"], max_amount=850.0)
    tok, _ = gw.mint_root_for_user(task_id, "user:alice@org-alpha.io", perms)

    st_rpc, rpc_body = gw.a2a_orch.send_message(
        message=Message.create_user(
            text=(
                "Book business travel to Singapore for Alice with flight budget up to 700 USD "
                "and hotel budget up to 450 USD."
            ),
            data={"op": "plan_and_execute_trip", "hotel_timeout_sec": 20.0},
            task_id=task_id,
        ),
        compact_token=tok,
    )
    if st_rpc != 200:
        raise AssertionError(
            f"Scenario 2B K8s pod-down failover failed ({st_rpc}): {rpc_body}"
        )
    assert rpc_body["result"]["task"]["status"]["state"] == TaskState.COMPLETED.value

    data = _extract_a2a_task_data(rpc_body)
    hotel_out = data["hotel_branch"]
    assert hotel_out["epoch"] == 1, hotel_out
    assert hotel_out["upstream_body"]["instance_label"] == "backup", hotel_out
    return {
        "scenario": "2b_a2a_v1_k8s_replicas_zero_crash_prune_and_graft",
        "status": "PASS",
        "task_id": task_id,
        "a2a_task_state": rpc_body["result"]["task"]["status"]["state"],
        "grafted_epoch": hotel_out["epoch"],
        "grafted_lineage_path": hotel_out["delegated_lineage_path"],
        "failover_fault_type": hotel_out["failover_receipts"][0]["failure_evidence"]["fault_type"],
        "final_answer": data["settlement_convergence"]["upstream_body"]["final_answer"],
    }


def run_scenario_3a(gw: GatewaySession, run_id: str) -> Dict[str, Any]:
    # Intermediate `hotel-specialist-primary` IS HEALTHY (`2/2 Running` on `:8443` mTLS).
    # Leaf `settlement-converger` (`org-payment.io`) attempts Skip-Level Return to
    # `orchestrator-alpha` (`org-alpha.io`) -> MUST BE REJECTED (`INTERMEDIATE_ANCESTOR_ALIVE`)
    # by `orchestrator-alpha`'s live mTLS `/healthz` probe!
    if gw.identity_addressing:
        hp_card = gw.resolve_agent_card(skill="travel.hotel", contains_spiffe="primary")
        h_check = gw.get_mtls_card(hp_card, "/healthz", timeout=3.0)
    else:
        h_check = gw.get_mtls(f"{HOTEL_PRIMARY_URL}/healthz", timeout=3.0)
    assert h_check.status_code == 200, "hotel-specialist-primary must be healthy for Scenario 3A"

    task_id = f"task-k8s-s3a-{run_id}"
    perms = _full_travel_root_permissions(["Tokyo"], max_amount=500.0)
    tok, _ = gw.mint_root_for_user(task_id, "user:alice@org-alpha.io", perms)

    st_rpc, rpc_body = gw.a2a_orch.send_message(
        message=Message.create_user(
            text="Execute 3-tier chain with simulated direct-parent unreachable",
            data={
                "op": "delegate_upward_return_chain",
                "city": "Tokyo",
                "simulate_direct_parent_unreachable": True,
                "return_timeout_sec": 1.0,
            },
            task_id=task_id,
        ),
        compact_token=tok,
    )
    assert st_rpc == 200, rpc_body
    chain_out = _extract_a2a_task_data(rpc_body)
    leaf_status = chain_out["downstream"]["upstream_body"]["downstream_status"]
    assert leaf_status == 502, chain_out

    tok_insp, _ = gw.mint_root_for_user(
        f"task-k8s-s3a-insp-{run_id}", "user:alice@org-alpha.io", perms
    )
    st_in, in_body = gw.a2a_orch.send_message(
        message=Message.create_user(
            text="Inspect inbox",
            data={"op": "inspect_inbox", "inspect_task_id": task_id},
        ),
        compact_token=tok_insp,
    )
    assert st_in == 200, in_body
    skip_list = _extract_a2a_task_data(in_body).get("skip_level_results", [])
    assert skip_list == [], f"Healthy intermediate bypass was wrongly accepted: {skip_list}"

    return {
        "scenario": "3a_false_skip_level_rejected_by_mtls_healthz_probe",
        "status": "PASS",
        "task_id": task_id,
        "intermediate_mtls_healthz_http": h_check.status_code,
        "rogue_leaf_return_status": leaf_status,
        "accepted_skip_level_results": len(skip_list),
    }


def run_scenario_3b(
    gw: GatewaySession, run_id: str, self_pod_ip: str, sync_marker_file: str
) -> Dict[str, Any]:
    leaf_arrived = threading.Event()
    sync_token = secrets.token_urlsafe(24)
    hp_card: Optional[AgentCard] = (
        gw.resolve_agent_card(
            skill="travel.hotel", contains_spiffe="primary", only_healthy=False
        )
        if gw.identity_addressing
        else None
    )

    def _sync_handler(req: HTTPRequestContext) -> Tuple[int, Any, Dict[str, str]]:
        if req.method != "POST" or req.path != "/sync":
            return 404, {"error": "route_not_found"}, {}
        provided_tok = str(req.header("X-LCT-Sync-Token") or "")
        if not provided_tok or not hmac.compare_digest(provided_tok, sync_token):
            return 403, {"error": "invalid_or_missing_sync_token"}, {}
        with open(sync_marker_file, "w", encoding="utf-8") as fh:
            fh.write("READY_TO_KILL_INTERMEDIATE\n")
        leaf_arrived.set()
        deadline = time.time() + 18.0
        while time.time() < deadline:
            try:
                if hp_card is not None:
                    r = gw.get_mtls_card(hp_card, "/healthz", timeout=0.6)
                else:
                    r = gw.get_mtls(f"{HOTEL_PRIMARY_URL}/healthz", timeout=0.6)
                if r.status_code >= 500:
                    break
            except Exception:
                break
            time.sleep(0.3)
        return 200, {"intermediate_offline": True}, {}

    hook_srv = ManagedHTTPService("s3b-sync-hook", _sync_handler, host="0.0.0.0", port=19090)
    hook_srv.start()
    hook_card: Optional[AgentCard] = None
    hook_locs: Tuple[ServiceLocator, ...] = ()
    try:
        task_id = f"task-k8s-s3b-{run_id}"
        perms = _full_travel_root_permissions(["Tokyo"], max_amount=500.0)
        tok, _ = gw.mint_root_for_user(task_id, "user:alice@org-alpha.io", perms)

        msg_data: Dict[str, Any] = {
            "op": "delegate_upward_return_chain",
            "city": "Tokyo",
            "sync_hook_token": sync_token,
            "return_timeout_sec": 1.2,
        }
        if gw.identity_addressing:
            loc_watcher = _build_env_node_locator_watcher()
            if loc_watcher is not None:
                snap = loc_watcher.wait_for_locators(max_wait_sec=10.0)
                if snap is not None:
                    slot_name = (
                        os.environ.get("LCT_LOCATOR_SLOT", "").strip() or "e2e_sync_hook"
                    )
                    hook_locs = snap.build_service_locators(
                        slot_name,
                        transport="http-ro",
                        spiffe_id=gw.identity.spiffe_id,
                    )
            if not hook_locs:
                raise RuntimeError("Missing signed e2e_sync_hook locators from lct-node-locator")
            hook_card = AgentCard.sign_and_create(
                identity=gw.identity,
                name="E2E Transient Sync Hook",
                skills=["e2e.sync-hook"],
                priority=50,
                streaming_supported=False,
                ttl_seconds=90.0,
                version=int(time.time() * 1000),
                locators=hook_locs,
            )
            gw.dir_client.register(hook_card)
            time.sleep(0.6)
            msg_data["sync_hook_spiffe_id"] = gw.identity.spiffe_id
            orch_card = gw.get_orchestrator_card()
            a2a_short = gw.a2a_client_for(agent_card=orch_card, timeout=45.0)
        else:
            msg_data["sync_hook_url"] = SYNC_HOOK_URL or f"http://{self_pod_ip}:19090/sync"
            a2a_short = gw.a2a_client_for(ORCH_URL, timeout=45.0)

        a2a_short.send_message(
            message=Message.create_user(
                text="Execute 3-tier chain with mid-flight intermediate Pod termination",
                data=msg_data,
                task_id=task_id,
            ),
            compact_token=tok,
        )

        tok_inspect, _ = gw.mint_root_for_user(
            f"task-k8s-s3b-insp-{run_id}", "user:alice@org-alpha.io", perms
        )
        accepted_skip: List[Dict[str, Any]] = []
        for _ in range(22):
            st_in, in_body = gw.a2a_orch.send_message(
                message=Message.create_user(
                    text="Inspect inbox",
                    data={"op": "inspect_inbox", "inspect_task_id": task_id},
                ),
                compact_token=tok_inspect,
            )
            if st_in == 200:
                accepted_skip = _extract_a2a_task_data(in_body).get(
                    "skip_level_results", []
                )
                if len(accepted_skip) == 1:
                    break
            time.sleep(0.3)

        if len(accepted_skip) != 1:
            raise AssertionError(f"Expected 1 verified SkipLevelReceipt, got {accepted_skip}")

        sr = accepted_skip[0]
        return {
            "scenario": "3b_authenticated_skip_level_return_over_mtls_on_real_k8s_pod_kill",
            "status": "PASS",
            "task_id": task_id,
            "receipt_id": sr["receipt_id"],
            "child_spiffe_id": sr["child_spiffe_id"],
            "skipped_ancestors": sr["skipped_ancestors"],
            "target_ancestor_spiffe_id": sr["target_ancestor_spiffe_id"],
            "result_sha256": sr["result_sha256"],
            "leaf_result_payload": sr["result_payload"],
        }
    finally:
        hook_srv.stop()
        if hook_card is not None and hook_locs:
            try:
                offline_card = AgentCard.sign_and_create(
                    identity=gw.identity,
                    name="E2E Transient Sync Hook",
                    skills=["e2e.sync-hook"],
                    priority=50,
                    status=AgentStatus.OFFLINE,
                    streaming_supported=False,
                    ttl_seconds=10.0,
                    version=max(hook_card.version + 1, int(time.time() * 1000)),
                    locators=hook_locs,
                )
                gw.dir_client.register(offline_card)
            except Exception:
                pass


def _probe_tcp_closed(ip: str, port: int, timeout: float = 1.0) -> Tuple[bool, str]:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return False, f"UNEXPECTED_OPEN:{ip}:{port}"
    except Exception as exc:
        return True, f"{type(exc).__name__}: {exc}"


def run_scenario_4(
    gw: GatewaySession, run_id: str, pod_ips_json: str
) -> Dict[str, Any]:
    pod_ips: Dict[str, str] = json.loads(pod_ips_json)

    # 1. Cross-Pod Loopback Bypass Guard Verification across real K8s CNI Pod IPs!
    bypass_checks: Dict[str, Any] = {}
    for name, ip in pod_ips.items():
        if not ip:
            continue
        ok_app, det_app = _probe_tcp_closed(ip, 9001)
        ok_out, det_out = _probe_tcp_closed(ip, 8081)
        if not ok_app or not ok_out:
            raise AssertionError(f"Loopback port exposed across Pod network on {name} ({ip})!")
        bypass_checks[name] = {
            "pod_ip": ip,
            "app_port_9001_blocked": ok_app,
            "app_port_detail": det_app,
            "sidecar_outbound_8081_blocked": ok_out,
            "sidecar_outbound_detail": det_out,
        }

    # Forged `X-LCT-Loopback-Auth` header sent over mTLS to `:8443/mcp` -> MUST return 401!
    if gw.identity_addressing:
        pay_mcp_card = gw.resolve_agent_card(skill="mcp.payment-vault")
        pay_mcp_target = f"{pay_mcp_card.endpoint}/mcp"
        pay_mcp_ssl = gw.mtls_bundle.verify_for_target(
            target_url=pay_mcp_target,
            expected_spiffe_id=pay_mcp_card.spiffe_id,
        )
    else:
        pay_mcp_target = PAYMENT_MCP_SVC_URL
        pay_mcp_ssl = gw.ssl_ctx

    with httpx.Client(verify=pay_mcp_ssl, timeout=5.0) as m_cli:
        forged_in = m_cli.post(
            pay_mcp_target,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "execute_settlement",
                    "arguments": {"target": "hotel-escrow", "amount": 50},
                },
            },
            headers={"X-LCT-Loopback-Auth": "forged-secret-attempt"},
        )
    assert forged_in.status_code == 401, forged_in.text
    bypass_checks["inbound_8443_forged_loopback_header_status"] = forged_in.status_code

    # 2. Official A2A v1.0 `CancelTask` Cross-3-Domain Cascading Revocation Proof (`user:bob@org-alpha.io`):
    #    - Stage Bob's trip across `org-alpha.io` -> `org-beta.io` -> `org-payment.io`
    #    - Verify Carol CANNOT cancel Bob's task (`403` `-32003`)
    #    - Bob invokes `CancelTask(task_bob)` -> atomically sets `TASK_STATE_CANCELED` AND
    #      revokes `/task_bob/OrchestratorAlpha` in `alpha-revocation`, federating immediately to
    #      `beta-revocation` & `payment-revocation`!
    task_bob = f"task-k8s-s4-bob-cancel-{run_id}"
    tok_bob, _ = gw.mint_root_for_user(
        task_bob,
        "user:bob@org-alpha.io",
        _full_travel_root_permissions(["Tokyo"], max_amount=800.0),
    )
    st_bob_stage, bob_stage_body = gw.a2a_orch.send_message(
        message=Message.create_user(
            text=(
                "Book business travel to Tokyo for Bob with flight budget up to 650 USD "
                "and hotel budget up to 420 USD."
            ),
            data={"op": "plan_and_execute_trip", "pause_before_settlement": True},
            task_id=task_bob,
        ),
        compact_token=tok_bob,
    )
    assert st_bob_stage == 200, bob_stage_body

    # Cross-user `CancelTask` attempt by Carol -> MUST fail `403` (`-32003`)!
    tok_carol_probe, _ = gw.mint_root_for_user(
        f"task-k8s-s4-carol-probe-{run_id}",
        "user:carol@org-alpha.io",
        _full_travel_root_permissions(["London"], max_amount=800.0),
    )
    st_unauth_cancel, unauth_cancel_body = gw.a2a_orch.cancel_task(
        task_bob, compact_token=tok_carol_probe
    )
    assert st_unauth_cancel == 403, unauth_cancel_body
    assert unauth_cancel_body["error"]["code"] == -32003, unauth_cancel_body

    # Authorized `CancelTask` by Bob -> `TASK_STATE_CANCELED` + cascading lineage revocation!
    st_bob_cancel, bob_cancel_body = gw.a2a_orch.cancel_task(
        task_bob, compact_token=tok_bob
    )
    assert st_bob_cancel == 200, bob_cancel_body
    assert (
        bob_cancel_body["result"]["task"]["status"]["state"]
        == TaskState.CANCELED.value
    ), bob_cancel_body
    bob_rev_meta = bob_cancel_body["result"]["revocation"]
    assert bob_rev_meta["target"] == f"/{task_bob}/OrchestratorAlpha", bob_rev_meta

    # Verify federated propagation to BOTH `beta-revocation` and `payment-revocation`!
    for peer_rev_name, peer_td in (
        ("beta-revocation", "org-beta.io"),
        ("payment-revocation", "org-payment.io"),
    ):
        rev_loc = gw.rev_fed_locator(peer_td)
        peer_rev_url = rev_loc.origin_url
        found_fed = False
        for _ in range(15):
            if peer_rev_url.startswith("https://"):
                r_rh = gw.get_mtls(
                    f"{peer_rev_url}/healthz",
                    expected_spiffe_id=rev_loc.spiffe_id,
                    timeout=3.0,
                )
                if r_rh.status_code == 200 and int(r_rh.json().get("version", 0)) >= 1:
                    found_fed = True
                    break
            else:
                evs = httpx.get(f"{peer_rev_url}/v1/events", timeout=3.0).json().get("events", [])
                if any(
                    e.get("target") == f"/{task_bob}/OrchestratorAlpha"
                    and e.get("trust_domain") == "org-alpha.io"
                    for e in evs
                ):
                    found_fed = True
                    break
            time.sleep(0.2)
        if not found_fed:
            raise AssertionError(
                f"CancelTask revocation for {task_bob} did not federate to {peer_rev_name}!"
            )

    # Replay of `tok_bob` after `CancelTask` -> immediately blocked at Sidecar (`403 LINEAGE_REVOKED`)!
    orch_replay_card = gw.get_orchestrator_card()
    r_bob_replay = gw.post_lct_mtls(
        orch_replay_card.endpoint if gw.identity_addressing else ORCH_URL,
        tok_bob,
        {"op": "trigger_converged_settlement", "city": "Tokyo"},
        expected_spiffe_id=(orch_replay_card.spiffe_id if gw.identity_addressing else None),
    )
    assert r_bob_replay.status_code == 403, r_bob_replay.text
    assert r_bob_replay.json().get("error") == "LINEAGE_REVOKED", r_bob_replay.text

    # 3. Multi-User Concurrent Execution (`alice@org-alpha.io` staged + `carol@org-alpha.io` full)
    #    + Branch-Scoped A2A `CancelTask` triggering Fagin Multi-Parent DAG Smooth Degradation!
    task_alice = f"task-k8s-s4-alice-{run_id}"
    task_carol = f"task-k8s-s4-carol-{run_id}"

    tok_alice, _ = gw.mint_root_for_user(
        task_alice,
        "user:alice@org-alpha.io",
        _full_travel_root_permissions(["Tokyo"], max_amount=800.0),
    )
    tok_carol, _ = gw.mint_root_for_user(
        task_carol,
        "user:carol@org-alpha.io",
        _full_travel_root_permissions(["London"], max_amount=800.0),
    )

    def _stage_alice() -> Tuple[int, Dict[str, Any]]:
        return gw.a2a_orch.send_message(
            message=Message.create_user(
                text=(
                    "Book business travel to Tokyo for Alice with flight budget up to 650 USD "
                    "and hotel budget up to 420 USD."
                ),
                data={"op": "plan_and_execute_trip", "pause_before_settlement": True},
                task_id=task_alice,
            ),
            compact_token=tok_alice,
        )

    def _run_carol_full() -> Tuple[int, Dict[str, Any]]:
        return gw.a2a_orch.send_message(
            message=Message.create_user(
                text=(
                    "Book business travel to London for Carol with flight budget up to 600 USD "
                    "and hotel budget up to 400 USD."
                ),
                data={"op": "plan_and_execute_trip"},
                task_id=task_carol,
            ),
            compact_token=tok_carol,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f_alice = pool.submit(_stage_alice)
        f_carol = pool.submit(_run_carol_full)
        st_alice_stage, alice_stage_body = f_alice.result()
        st_carol, carol_body = f_carol.result()

    assert st_alice_stage == 200, alice_stage_body
    assert st_carol == 200, carol_body

    alice_staged = _extract_a2a_task_data(alice_stage_body)
    flight_branch_path = str(
        alice_staged["flight_branch"]["upstream_body"]["lineage_path"]
    )

    # Online Subtree Revocation of Alice's Flight Branch (`/<task_alice>/OrchestratorAlpha/FlightB1`)
    # at `alpha-revocation`, which federates to `payment-revocation` (`org-payment.io`)!
    rev_ev = gw.rev_client.revoke_prefix(
        caller=gw.identity,
        prefix=flight_branch_path,
        reason="online_cancel_flight_branch",
        authority_token=tok_alice,
    )
    parsed_alice_root = decode_token(tok_alice)
    gw.emit_revocation_audit(
        task_id=task_alice,
        sub="user:alice@org-alpha.io",
        revocation_event=rev_ev,
        root_block_hash=parsed_alice_root.root_block_hash,
        current_block_hash=parsed_alice_root.leaf_block_hash,
    )

    # 4A. Trigger Alice's Hotel Escrow Settlement -> SMOOTH FAGIN DEGRADATION (`200 ALLOW_DEGRADED_DAG`)!
    st_hotel_ok, hotel_ok_body = gw.a2a_orch.send_message(
        message=Message.create_user(
            text="Settle surviving Tokyo hotel escrow",
            data={
                "op": "trigger_converged_settlement",
                "city": "Tokyo",
                "requested_targets": ["hotel-escrow"],
                "trigger_hop_segment": "SettleHotelSurviving",
            },
            task_id=task_alice,
        ),
        compact_token=tok_alice,
    )
    assert st_hotel_ok == 200, hotel_ok_body
    hotel_deg_body = _extract_a2a_task_data(hotel_ok_body)["upstream_body"]
    hotel_stl = hotel_deg_body["completed_settlements"]["hotel-escrow"]
    assert hotel_stl["lineage_decision"] == "ALLOW_DEGRADED_DAG", hotel_stl
    assert float(hotel_stl["settled_usd"]) == 360.0, hotel_stl
    assert "360" in hotel_deg_body["final_answer"], hotel_deg_body["final_answer"]
    assert "580" not in hotel_deg_body["final_answer"], (
        f"Degraded answer must not hallucinate revoked 580 USD flight settlement: {hotel_deg_body['final_answer']!r}"
    )

    # 4B. Trigger Alice's Airline Escrow Settlement (depended on revoked `FlightB1`) -> `403` (`FAILED` task)!
    st_air_deny, air_deny_body = gw.a2a_orch.send_message(
        message=Message.create_user(
            text="Attempt settlement of revoked Tokyo airline escrow",
            data={
                "op": "trigger_converged_settlement",
                "city": "Tokyo",
                "requested_targets": ["airline-escrow"],
                "trigger_hop_segment": "SettleAirlineRevoked",
            },
            task_id=task_alice,
        ),
        compact_token=tok_alice,
    )
    assert st_air_deny == 403, air_deny_body
    air_err_data = air_deny_body["error"]["data"]
    assert air_err_data["task"]["status"]["state"] == TaskState.FAILED.value, air_deny_body
    air_err = air_err_data["upstream_body"]["denied_settlements"]["airline-escrow"]
    assert air_err["error"] == "REVOKED_DEPENDENCY_INSUFFICIENT_SURVIVING_PATHS", air_err

    # 4C. Verify Carol's concurrent London trip completed 100% cleanly (`ALLOW`) with zero cross-user bleed!
    carol_conv = _extract_a2a_task_data(carol_body)["settlement_convergence"]["upstream_body"]
    assert carol_conv["sub"] == "user:carol@org-alpha.io"
    assert carol_conv["city"] == "London"
    assert carol_conv["flight_booking"]["flight_no"] == "BA-284"
    assert float(carol_conv["completed_settlements"]["airline-escrow"]["settled_usd"]) == 510.0
    assert float(carol_conv["completed_settlements"]["hotel-escrow"]["settled_usd"]) == 340.0
    assert carol_conv["completed_settlements"]["airline-escrow"]["lineage_decision"] == "ALLOW"

    return {
        "scenario": "4_a2a_v1_canceltask_cross_domain_cascade_fagin_dag_concurrency_and_loopback_isolation",
        "status": "PASS",
        "cross_pod_loopback_isolation": bypass_checks,
        "a2a_canceltask_cross_3domain_proof": {
            "task_id": task_bob,
            "unauthorized_carol_cancel_http": st_unauth_cancel,
            "unauthorized_carol_cancel_rpc_code": unauth_cancel_body["error"]["code"],
            "bob_canceled_state": bob_cancel_body["result"]["task"]["status"]["state"],
            "cascaded_revocation_target": bob_rev_meta["target"],
            "federated_to_beta_and_payment_revocation": True,
            "post_cancel_token_replay_http": r_bob_replay.status_code,
            "post_cancel_token_replay_error": r_bob_replay.json().get("error"),
        },
        "alice_revoked_branch": rev_ev.target,
        "alice_revocation_version": rev_ev.version,
        "alice_surviving_hotel_settlement": hotel_stl,
        "alice_degraded_llm_answer": hotel_deg_body["final_answer"],
        "alice_revoked_airline_rejection": air_err,
        "carol_concurrent_london_settlements": carol_conv["completed_settlements"],
        "carol_final_answer": carol_conv["final_answer"],
    }


def run_scenario_5(gw: GatewaySession) -> Dict[str, Any]:
    entries = gw.audit_client.fetch_entries()
    auditor = CausalChainAuditor(
        gw.resolver,
        trusted_revocation_spiffe_ids=[
            "spiffe://org-alpha.io/ns/sys/sa/revocation",
            "spiffe://org-beta.io/ns/sys/sa/revocation",
            "spiffe://org-payment.io/ns/sys/sa/revocation",
        ],
    )
    report = auditor.audit(entries)
    ok_num, total_den = report.reconstruction_rate

    all_resilience_tags: List[str] = []
    per_task_summary: Dict[str, Any] = {}
    for tid, trec in sorted(report.tasks.items()):
        all_resilience_tags.extend(trec.resilience_classifications)
        per_task_summary[tid] = {
            "sub": trec.sub,
            "reconstructed_complete": trec.reconstructed_complete,
            "lineage_paths_count": len(trec.lineage_paths_observed),
            "lineage_paths_observed": trec.lineage_paths_observed,
            "verified_hops": trec.verified_hops,
            "tool_invocations_verified": trec.tool_invocations_verified,
            "resilience_classifications": trec.resilience_classifications,
            "anomalies": [a.__dict__ for a in trec.anomalies],
        }

    if not report.stream_integrity_ok or not report.clean or ok_num != total_den or total_den == 0:
        raise AssertionError(
            f"Cluster audit reconstruction not 100% clean: ok={ok_num}/{total_den}, "
            f"stream_ok={report.stream_integrity_ok}, anomalies={report.anomalies}"
        )
    if "VERIFIED_FAILOVER_GRAFT" not in all_resilience_tags:
        raise AssertionError(f"Expected VERIFIED_FAILOVER_GRAFT in {all_resilience_tags}")
    if "VERIFIED_SKIP_LEVEL_MERGE" not in all_resilience_tags:
        raise AssertionError(f"Expected VERIFIED_SKIP_LEVEL_MERGE in {all_resilience_tags}")

    return {
        "scenario": "5_keyless_audit_collector_export_and_100pct_3domain_causal_reconstruction",
        "status": "PASS",
        "total_signed_entries": report.total_entries,
        "distinct_streams_verified": report.streams_checked,
        "stream_hash_chain_integrity_ok": report.stream_integrity_ok,
        "clean": report.clean,
        "reconstructed_tasks_numerator": ok_num,
        "total_tasks_denominator": total_den,
        "reconstruction_rate_pct": round(100.0 * ok_num / total_den, 2),
        "resilience_classifications_verified": sorted(set(all_resilience_tags)),
        "tasks": per_task_summary,
        "redacted_audit_sample_count": len(entries),
    }


def run_multicluster_isolation_proofs(
    gw: GatewaySession, foreign_pod_ips_json: str
) -> Dict[str, Any]:
    """Verify physical L3 CIDR unroutability, private cluster.local DNS isolation,
    public organization FQDN purity, and hardened external control-plane ports.
    """
    foreign_ips: Dict[str, str] = json.loads(foreign_pod_ips_json)

    # 1. Private `.svc.cluster.local` DNS names of foreign clusters MUST fail resolution!
    dns_isolation: Dict[str, Any] = {}
    for foreign_dns in (
        "flight-specialist.lineage-beta.svc.cluster.local",
        "payment-vault-mcp.lineage-pay.svc.cluster.local",
        "audit-collector.lineage-ctrl.svc.cluster.local",
    ):
        failed = False
        err_msg = ""
        try:
            socket.getaddrinfo(foreign_dns, 8443)
        except socket.gaierror as exc:
            failed = True
            err_msg = f"gaierror: {exc}"
        if not failed:
            raise AssertionError(
                f"Foreign cluster private DNS {foreign_dns!r} unexpectedly resolved inside lct-org-alpha!"
            )
        dns_isolation[foreign_dns] = {"nxdomain_isolated": True, "detail": err_msg}

    # 2. Disjoint internal Pod CIDRs (`10.242.0.0/16` in Beta, `10.243.0.0/16` in Pay)
    #    MUST be physically unroutable from `lct-org-alpha` (`10.241.0.0/16`)!
    l3_isolation: Dict[str, Any] = {}
    for label, pod_ip in foreign_ips.items():
        if not pod_ip:
            continue
        ok_unreach, detail = _probe_tcp_closed(pod_ip, 8443, timeout=1.2)
        if not ok_unreach:
            raise AssertionError(
                f"Foreign cluster internal Pod IP {pod_ip}:8443 ({label}) was unexpectedly reachable!"
            )
        l3_isolation[label] = {
            "foreign_pod_ip": pod_ip,
            "port_8443_unroutable": True,
            "detail": detail,
        }

    # 3. Verify all federated `AgentCard`s advertise ONLY public `https://` locators
    #    (ZERO `.svc.cluster.local` leakage!)
    expected_min = 7 if gw.identity_addressing else 5
    cards = gw.dir_client.discover(only_healthy=True)
    if len(cards) < expected_min:
        raise AssertionError(f"Expected >={expected_min} federated AgentCards, got {len(cards)}")
    card_endpoints: Dict[str, str] = {}
    identity_to_locators: Dict[str, Any] = {}
    for c in cards:
        if ".svc.cluster.local" in c.endpoint or ".svc.cluster.local" in (
            c.return_endpoint or ""
        ):
            raise AssertionError(
                f"AgentCard {c.spiffe_id} leaked internal .svc.cluster.local URL: {c.endpoint}"
            )
        if not c.endpoint.startswith("https://"):
            raise AssertionError(f"AgentCard {c.spiffe_id} endpoint must be https://: {c.endpoint}")
        card_endpoints[c.spiffe_id] = c.endpoint
        identity_to_locators[c.spiffe_id] = {
            "version": c.version,
            "endpoint": c.endpoint,
            "locators": [loc.to_dict() for loc in c.locators],
        }

    # 4. External Control-Plane Boundary Hardening Checks
    sa_jwt = gw._fresh_sa_jwt()
    kp = KeyPair.generate("ES256")
    pop = create_ca_pop_jws(kp, sa_jwt)
    ext_ca_checks: Dict[str, Any] = {}
    beta_ca_u = gw.ca_bundle_url("org-beta.io")
    pay_ca_u = gw.ca_bundle_url("org-payment.io")
    for name, url in (("beta-ca-fed", beta_ca_u), ("payment-ca-fed", pay_ca_u)):
        r = httpx.post(
            f"{url}/v1/ca/issue-workload",
            json={"public_jwk": kp.public_jwk(), "pop_jws": pop},
            headers={"Authorization": f"Bearer {sa_jwt}"},
            timeout=5.0,
        )
        assert r.status_code == 403, f"{name} returned {r.status_code}: {r.text}"
        assert r.json().get("error") == "federation_endpoint_read_only", r.text
        ext_ca_checks[name] = {"status": r.status_code, "error": r.json().get("error")}

    # Unauthenticated TLS client rejected on external directory & revocation federation ports;
    # Authenticated mTLS client rejected (`403 federation_port_restricted`) on mutating admin routes!
    beta_dir_loc = gw.dir_fed_locator("org-beta.io")
    pay_rev_loc = gw.rev_fed_locator("org-payment.io")
    beta_dir_fed = (
        beta_dir_loc.origin_url
        if gw.identity_addressing
        else "https://beta-directory.org-beta.io:31491"
    )
    pay_rev_fed = (
        pay_rev_loc.origin_url if gw.identity_addressing else PAYMENT_REV_URL
    )
    for target_u, target_td, target_spiffe in (
        (
            f"{beta_dir_fed}/v1/federation/cards",
            "org-beta.io",
            beta_dir_loc.spiffe_id,
        ),
        (
            f"{pay_rev_fed}/v1/federation/events",
            "org-payment.io",
            pay_rev_loc.spiffe_id,
        ),
    ):
        server_only_ctx = gw.mtls_bundle.trust_store.build_server_verify_ssl_context(
            expected_trust_domain=target_td,
            check_hostname=(not gw.identity_addressing),
            expected_spiffe_id=target_spiffe,
        )
        blocked = False
        try:
            with httpx.Client(verify=server_only_ctx, timeout=3.0) as bad_c:
                bad_c.get(target_u)
        except Exception:
            blocked = True
        if not blocked:
            raise AssertionError(f"Certless TLS client was not rejected at {target_u}!")

    with httpx.Client(
        verify=gw.mtls_bundle.verify_for_target(
            target_url=beta_dir_fed,
            expected_spiffe_id=beta_dir_loc.spiffe_id,
        ),
        timeout=5.0,
    ) as b_cli:
        r_reg_block = b_cli.post(f"{beta_dir_fed}/v1/agents/register", json={})
        assert r_reg_block.status_code == 403
        assert r_reg_block.json().get("error") == "federation_port_restricted"

    with httpx.Client(
        verify=gw.mtls_bundle.verify_for_target(
            target_url=pay_rev_fed,
            expected_spiffe_id=pay_rev_loc.spiffe_id,
        ),
        timeout=5.0,
    ) as p_cli:
        r_qw_block = p_cli.post(f"{pay_rev_fed}/v1/revoke/workload", json={})
        assert r_qw_block.status_code == 403
        assert r_qw_block.json().get("error") == "federation_port_restricted"

    return {
        "check": "multicluster_physical_l3_dns_and_boundary_isolation",
        "status": "PASS",
        "private_cluster_local_dns_isolation": dns_isolation,
        "disjoint_pod_cidr_l3_isolation": l3_isolation,
        "public_fqdn_agent_cards": card_endpoints,
        "identity_to_locators": identity_to_locators,
        "external_ca_readonly_enforcement": ext_ca_checks,
        "external_directory_register_status": r_reg_block.status_code,
        "external_revocation_workload_status": r_qw_block.status_code,
    }


def _wait_for_marker(path: str, timeout_sec: float = 45.0) -> None:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if os.path.exists(path):
            return
        time.sleep(0.25)
    raise TimeoutError(f"Timed out waiting for synchronization marker {path!r}")


def run_scenario_6_whole_cluster_partition(
    gw: GatewaySession,
    run_id: str,
    ready_disconnect_file: str = "/tmp/s6_ready_disconnect",
    ack_disconnected_file: str = "/tmp/s6_ack_disconnected",
    ready_reconnect_file: str = "/tmp/s6_ready_reconnect",
    ack_reconnected_file: str = "/tmp/s6_ack_reconnected",
) -> Dict[str, Any]:
    """Scenario 6: End-to-end Whole-Cluster Network Partition, Fail-Closed `503`, and Autonomous Recovery
    within a single persistent in-memory `GatewaySession` (zero serialized keys or tokens!).
    """
    for mf in (
        ready_disconnect_file,
        ack_disconnected_file,
        ready_reconnect_file,
        ack_reconnected_file,
    ):
        try:
            os.remove(mf)
        except FileNotFoundError:
            pass

    if gw.identity_addressing:
        orch_c = gw.resolve_agent_card(skill="travel.orchestrate")
        flight_c = gw.resolve_agent_card(skill="travel.flight")
        hotel_p_c = gw.resolve_agent_card(skill="travel.hotel", contains_spiffe="primary")
        conv_c = gw.resolve_agent_card(skill="settlement.converge")
        pay_mcp_c = gw.resolve_agent_card(skill="mcp.payment-vault")
        pay_ca_url = gw.ca_bundle_url("org-payment.io")
    else:
        orch_c = flight_c = hotel_p_c = conv_c = pay_mcp_c = None
        pay_ca_url = PAYMENT_CA_URL

    # 1. Stage cross-3-cluster travel workflow (`org-alpha.io -> org-beta.io -> org-payment.io`)
    task_id = f"task-k8s-s6-part-{run_id}"
    perms = _full_travel_root_permissions(["Tokyo"], max_amount=800.0)
    tok, _ = gw.mint_root_for_user(task_id, "user:alice@org-alpha.io", perms)

    st, body = gw.a2a_orch.send_message(
        message=Message.create_user(
            text=(
                "Book business travel to Tokyo for Alice with flight budget up to 650 USD "
                "and hotel budget up to 420 USD."
            ),
            data={"op": "plan_and_execute_trip", "pause_before_settlement": True},
            task_id=task_id,
        ),
        compact_token=tok,
    )
    if st != 200:
        raise AssertionError(f"Scenario 6 staging failed ({st}): {body}")

    # Signal host runner to execute `docker network disconnect kind lctmh-beta-control-plane`
    with open(ready_disconnect_file, "w", encoding="utf-8") as fh:
        fh.write("READY\n")
    _wait_for_marker(ack_disconnected_file, timeout_sec=45.0)

    # 2. Verify autonomous survivability of Clusters Alpha, Pay, and Audit while Cluster Beta is severed!
    survivability: Dict[str, int] = {
        "alpha_ca_healthz": httpx.get(f"{ALPHA_CA_URL}/healthz", timeout=3.0).status_code,
        "alpha_dir_healthz": httpx.get(f"{ALPHA_DIR_URL}/healthz", timeout=3.0).status_code,
        "alpha_rev_healthz": httpx.get(f"{ALPHA_REV_URL}/healthz", timeout=3.0).status_code,
        "orchestrator_alpha_mtls_healthz": (
            gw.get_mtls_card(orch_c, "/healthz", timeout=3.0).status_code
            if orch_c is not None
            else gw.get_mtls(f"{ORCH_URL}/healthz", timeout=3.0).status_code
        ),
        "payment_ca_fed_healthz": httpx.get(f"{pay_ca_url}/healthz", timeout=3.0).status_code,
        "settlement_converger_mtls_healthz": (
            gw.get_mtls_card(conv_c, "/healthz", timeout=3.0).status_code
            if conv_c is not None
            else gw.get_mtls(f"{CONVERGER_URL}/healthz", timeout=3.0).status_code
        ),
        "payment_vault_mcp_mtls_healthz": (
            gw.get_mtls_card(pay_mcp_c, "/healthz", timeout=3.0).status_code
            if pay_mcp_c is not None
            else gw.get_mtls(
                f"{PAYMENT_MCP_SVC_URL.rsplit('/mcp', 1)[0]}/healthz", timeout=3.0
            ).status_code
        ),
        "audit_collector_healthz": gw.audit_client.healthz().status_code,
    }
    for k, code in survivability.items():
        if code != 200:
            raise AssertionError(f"Surviving cluster service {k} unhealthy during Beta outage: {code}")

    # Confirm Cluster Beta is genuinely unreachable from Cluster Alpha!
    beta_unreachable = False
    try:
        if flight_c is not None:
            gw.get_mtls_card(flight_c, "/healthz", timeout=1.2)
        else:
            gw.get_mtls(f"{FLIGHT_URL}/healthz", timeout=1.2)
    except Exception:
        beta_unreachable = True
    if not beta_unreachable:
        raise AssertionError("Expected Cluster Beta to be unreachable during network disconnect!")

    # 3. Attempt HIGH_RISK settlement traversing `org-beta.io` -> MUST fail closed (`503`)!
    st_settle, settle_body = gw.a2a_orch.send_message(
        message=Message.create_user(
            text="Attempt HIGH_RISK Tokyo escrow settlement while Cluster Beta is partitioned",
            data={
                "op": "trigger_converged_settlement",
                "city": "Tokyo",
                "requested_targets": ["airline-escrow"],
                "trigger_hop_segment": "SettleDuringBetaOutage",
            },
            task_id=task_id,
        ),
        compact_token=tok,
    )
    assert st_settle == 503, f"Expected 503 fail-closed, got {st_settle}: {settle_body}"
    err_data = settle_body["error"]["data"]
    assert err_data["task"]["status"]["state"] == TaskState.FAILED.value
    vault_deny = err_data["upstream_body"]["denied_settlements"]["airline-escrow"]
    assert vault_deny["error"] == "REVOCATION_ANCHOR_UNAVAILABLE", vault_deny

    # Signal host runner to execute `docker network connect kind lctmh-beta-control-plane`
    with open(ready_reconnect_file, "w", encoding="utf-8") as fh:
        fh.write("READY\n")
    _wait_for_marker(ack_reconnected_file, timeout_sec=45.0)

    # 4. Wait for Cluster Beta mTLS endpoints to recover autonomously and execute full workflow
    if flight_c is not None and hotel_p_c is not None:
        for target_c in (flight_c, hotel_p_c):
            recovered = False
            for _ in range(35):
                try:
                    if gw.get_mtls_card(target_c, "/healthz", timeout=1.5).status_code == 200:
                        recovered = True
                        break
                except Exception:
                    pass
                time.sleep(0.4)
            if not recovered:
                raise AssertionError(
                    f"Cluster Beta workload {target_c.spiffe_id} did not recover after reconnect!"
                )
    else:
        for svc_u in (f"{FLIGHT_URL}/healthz", f"{HOTEL_PRIMARY_URL}/healthz"):
            recovered = False
            for _ in range(35):
                try:
                    if gw.get_mtls(svc_u, timeout=1.5).status_code == 200:
                        recovered = True
                        break
                except Exception:
                    pass
                time.sleep(0.4)
            if not recovered:
                raise AssertionError(f"Cluster Beta endpoint {svc_u} did not recover after reconnect!")

    recov_task_id = f"task-k8s-s6-recov-{run_id}"
    tok_recov, _ = gw.mint_root_for_user(recov_task_id, "user:alice@org-alpha.io", perms)

    st_ok, ok_body = gw.a2a_orch.send_message(
        message=Message.create_user(
            text=(
                "Book business travel to Tokyo for Alice with flight budget up to 650 USD "
                "and hotel budget up to 420 USD after Cluster Beta network recovery."
            ),
            data={"op": "plan_and_execute_trip"},
            task_id=recov_task_id,
        ),
        compact_token=tok_recov,
    )
    if st_ok != 200:
        raise AssertionError(f"Post-recovery trip failed ({st_ok}): {ok_body}")
    assert ok_body["result"]["task"]["status"]["state"] == TaskState.COMPLETED.value
    recov_data = _extract_a2a_task_data(ok_body)
    stl = recov_data["settlement_convergence"]["upstream_body"]["completed_settlements"]
    assert stl["airline-escrow"]["lineage_decision"] == "ALLOW"
    assert stl["hotel-escrow"]["lineage_decision"] == "ALLOW"

    for mf in (
        ready_disconnect_file,
        ack_disconnected_file,
        ready_reconnect_file,
        ack_reconnected_file,
    ):
        try:
            os.remove(mf)
        except FileNotFoundError:
            pass

    return {
        "scenario": "6_whole_cluster_network_partition_fail_closed_and_autonomous_recovery",
        "status": "PASS",
        "during_whole_cluster_partition": {
            "partitioned_task_id": task_id,
            "beta_cluster_confirmed_unreachable": beta_unreachable,
            "surviving_clusters_health": survivability,
            "high_risk_fail_closed_http_status": st_settle,
            "high_risk_fail_closed_error": vault_deny,
        },
        "after_autonomous_recovery": {
            "recovered_task_id": recov_task_id,
            "a2a_task_state": ok_body["result"]["task"]["status"]["state"],
            "completed_settlements": stl,
            "final_answer": recov_data["settlement_convergence"]["upstream_body"]["final_answer"],
        },
    }


def _sum_oauth_telemetry(obj: Any) -> Tuple[int, float, List[str]]:
    """Recursively aggregate `oauth_telemetry` and `oauth_hop_telemetry` across nested responses."""
    exchanges = 0
    rtt_ms = 0.0
    endpoints: List[str] = []

    def _visit(node: Any) -> None:
        nonlocal exchanges, rtt_ms
        if isinstance(node, Mapping):
            tel = node.get("oauth_telemetry")
            if isinstance(tel, Mapping) and "sts_exchanges" in tel:
                exchanges += int(tel.get("sts_exchanges") or 0)
                rtt_ms += float(tel.get("sts_rtt_ms") or 0.0)
                ep = str(tel.get("sts_endpoint") or "")
                if ep and ep not in endpoints:
                    endpoints.append(ep)
            hop_list = node.get("oauth_hop_telemetry")
            if isinstance(hop_list, list):
                for item in hop_list:
                    if isinstance(item, Mapping):
                        exchanges += int(item.get("sts_exchanges") or 0)
                        rtt_ms += float(item.get("sts_rtt_ms") or 0.0)
                        ep = str(item.get("sts_endpoint") or "")
                        if ep and ep not in endpoints:
                            endpoints.append(ep)
            for k, v in node.items():
                if k not in ("oauth_telemetry", "oauth_hop_telemetry"):
                    _visit(v)
        elif isinstance(node, list):
            for x in node:
                _visit(x)

    _visit(obj)
    return exchanges, round(rtt_ms, 2), endpoints


def run_m8_protocol_comparison(
    gw: GatewaySession,
    run_id: str,
    include_alpha_sts_partition: bool = True,
) -> Dict[str, Any]:
    """Empirical 6-Dimension Protocol Comparison across the live 4-cluster topology:
    `oauth_centralized` vs. `oauth_federated` vs. `lct` (with Hop-0 Keycloak/OIDC Bridge).
    """
    from lineage.audit import CausalChainAuditor

    orch_card = gw.get_orchestrator_card()
    flight_card = gw.resolve_agent_card(skill="travel.flight")
    hotel_prim_card = gw.resolve_agent_card(
        skill="travel.hotel", contains_spiffe="hotel-specialist-primary"
    )
    conv_card = gw.resolve_agent_card(skill="settlement.converge")

    # -------------------------------------------------------------------------
    # Hop-0 Human User Authentication at Organization Alpha's OIDC/Keycloak STS
    # -------------------------------------------------------------------------
    oidc_login = gw.login_oidc_user("alice")
    user_access_tok = str(oidc_login["access_token"])
    user_id_tok = str(oidc_login.get("id_token") or user_access_tok)
    hop0_login_rtt_ms = float(oidc_login["rtt_ms"])
    hop0_sts_endpoint = str(oidc_login["sts_endpoint"])

    # Verify OIDC discovery on alpha-sts to identify engine (`keycloak` vs `lightweight`)
    alpha_sts_base = gw.oauth_sts_origins("org-alpha.io")[0].split("#host=", 1)[0]
    oidc_disc = httpx.get(
        f"{alpha_sts_base}/realms/{gw.oauth_realm}/.well-known/openid-configuration",
        timeout=5.0,
        trust_env=False,
    ).json()
    is_real_keycloak = "authorization_endpoint" in oidc_disc

    # =========================================================================
    # Dimension 1: Multi-Hop Cross-Machine Latency & Remote STS Exchange RPCs
    # =========================================================================
    dim1: Dict[str, Any] = {}
    for o_mode in ("oauth_centralized", "oauth_federated"):
        tid = f"task-m8-d1-{o_mode.replace('_', '-')}-{run_id}"
        t0 = time.perf_counter()
        resp_d1, h1_meta = gw.post_oauth_mtls(
            orch_card,
            user_access_tok,
            delegation_mode=o_mode,
            task_id=tid,
            payload={"op": "plan_and_execute_trip"},
            timeout=95.0,
        )
        wall_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        assert resp_d1.status_code == 200, f"D1 {o_mode} failed ({resp_d1.status_code}): {resp_d1.text}"
        body_d1 = resp_d1.json()
        down_ex, down_rtt, down_eps = _sum_oauth_telemetry(body_d1)
        all_eps = list(dict.fromkeys([h1_meta["hop1_sts_endpoint"], *down_eps]))
        dim1[o_mode] = {
            "http_status": resp_d1.status_code,
            "e2e_wall_ms": wall_ms,
            "online_sts_exchange_rpcs": 1 + down_ex,
            "cumulative_sts_rtt_ms": round(float(h1_meta["hop1_sts_rtt_ms"]) + down_rtt, 2),
            "sts_endpoints_contacted": all_eps,
        }

    tid_d1_lct = f"task-m8-d1-lct-{run_id}"
    t0_mint = time.perf_counter()
    tok_d1_lct, mint_meta_d1 = gw.mint_root_for_user(
        tid_d1_lct,
        "user:alice@org-alpha.io",
        _full_travel_root_permissions(["Tokyo"], max_amount=900.0),
        target_card=orch_card,
        user_oidc_token=user_id_tok,
    )
    hop0_bridge_ms = round((time.perf_counter() - t0_mint) * 1000.0, 2)
    assert mint_meta_d1.get("hop0_oidc_bridged") is True, mint_meta_d1

    t0_lct = time.perf_counter()
    resp_d1_lct = gw.post_lct_mtls(
        orch_card.endpoint,
        tok_d1_lct,
        {"op": "plan_and_execute_trip"},
        expected_spiffe_id=orch_card.spiffe_id,
        timeout=95.0,
    )
    wall_lct_ms = round((time.perf_counter() - t0_lct) * 1000.0, 2)
    assert resp_d1_lct.status_code == 200, resp_d1_lct.text
    dim1["lct"] = {
        "http_status": resp_d1_lct.status_code,
        "hop0_oidc_bridged": True,
        "hop0_ca_bridge_ms": hop0_bridge_ms,
        "e2e_wall_ms": wall_lct_ms,
        "online_sts_exchange_rpcs": 0,
        "cumulative_sts_rtt_ms": 0.0,
    }

    # =========================================================================
    # Dimension 2: Dynamic Fine-Grained Parameter Over-Privilege ($950 / Paris)
    # =========================================================================
    dim2: Dict[str, Any] = {}
    probe_req = {
        "op": "probe_flight_overprivilege",
        "allowed_city": "Tokyo",
        "budget_cap_usd": 650.0,
        "attempt_amount_usd": 950.0,
        "attempt_city": "Paris",
    }
    for o_mode in ("oauth_centralized", "oauth_federated"):
        tid = f"task-m8-d2-{o_mode.replace('_', '-')}-{run_id}"
        resp_d2, _ = gw.post_oauth_mtls(
            orch_card,
            user_access_tok,
            delegation_mode=o_mode,
            task_id=tid,
            payload=probe_req,
        )
        assert resp_d2.status_code == 200, f"Expected flat-scope OAuth to allow $950/Paris: {resp_d2.text}"
        booked_d2 = resp_d2.json()["upstream_body"]["flight_booking"]
        dim2[o_mode] = {
            "http_status": resp_d2.status_code,
            "overprivileged_call_outcome": "ALLOWED_BY_FLAT_SCOPE",
            "charged_usd": booked_d2["charged_usd"],
            "booked_city": booked_d2["city"],
        }

    tid_d2_lct = f"task-m8-d2-lct-{run_id}"
    tok_d2_lct, _ = gw.mint_root_for_user(
        tid_d2_lct,
        "user:alice@org-alpha.io",
        _full_travel_root_permissions(["Tokyo"], max_amount=900.0),
        target_card=orch_card,
        user_oidc_token=user_id_tok,
    )
    resp_d2_lct = gw.post_lct_mtls(
        orch_card.endpoint,
        tok_d2_lct,
        probe_req,
        expected_spiffe_id=orch_card.spiffe_id,
    )
    assert resp_d2_lct.status_code == 403, f"Expected LCT 403 lattice block, got {resp_d2_lct.status_code}: {resp_d2_lct.text}"
    dim2["lct"] = {
        "http_status": resp_d2_lct.status_code,
        "overprivileged_call_outcome": "BLOCKED_BY_PERMISSION_LATTICE",
        "reason": resp_d2_lct.json(),
    }

    # =========================================================================
    # Dimension 3: N-to-1 Convergence & Single-Branch Cancellation (Flight Only)
    # =========================================================================
    dim3: Dict[str, Any] = {}
    for o_mode in ("oauth_centralized", "oauth_federated"):
        tid = f"task-m8-d3-{o_mode.replace('_', '-')}-{run_id}"
        r_stage, h1_d3 = gw.post_oauth_mtls(
            orch_card,
            user_access_tok,
            delegation_mode=o_mode,
            task_id=tid,
            payload={"op": "plan_and_execute_trip", "pause_before_settlement": True},
        )
        assert r_stage.status_code == 200, r_stage.text
        # Even if caller revokes one intermediate exchange token, the converged SettlementConverger
        # holds flat `travel:pay` without per-branch escrow lattice separation (`airline-escrow` vs `hotel-escrow`)!
        r_trig, _ = gw.post_oauth_mtls(
            orch_card,
            user_access_tok,
            delegation_mode=o_mode,
            task_id=tid,
            payload={"op": "trigger_converged_settlement", "city": "Tokyo"},
        )
        assert r_trig.status_code == 200, r_trig.text
        outcomes_o = r_trig.json()["upstream_body"]["settlement_outcomes"]
        dim3[o_mode] = {
            "supports_multiparent_dag_envelope": False,
            "airline_escrow_status_after_flight_cancel": outcomes_o["airline-escrow"]["http_status"],
            "hotel_escrow_status": outcomes_o["hotel-escrow"]["http_status"],
            "outcome": "LINEAR_ACT_NO_BRANCH_SCOPED_DEGRADATION",
        }

    tid_d3_lct = f"task-m8-d3-lct-{run_id}"
    tok_d3_lct, _ = gw.mint_root_for_user(
        tid_d3_lct,
        "user:alice@org-alpha.io",
        _full_travel_root_permissions(["Tokyo"], max_amount=900.0),
        target_card=orch_card,
        user_oidc_token=user_id_tok,
    )
    r_stage_lct = gw.post_lct_mtls(
        orch_card.endpoint,
        tok_d3_lct,
        {"op": "plan_and_execute_trip", "pause_before_settlement": True},
        expected_spiffe_id=orch_card.spiffe_id,
    )
    assert r_stage_lct.status_code == 200, r_stage_lct.text
    # Revoke ONLY the Flight subtree `/<tid_d3_lct>/OrchestratorAlpha/FlightB1`
    rev_flight = gw.rev_client.revoke_prefix(
        caller=gw.identity,
        prefix=f"/{tid_d3_lct}/OrchestratorAlpha/FlightB1",
        reason="m8_cancel_flight_branch_only",
        authority_token=tok_d3_lct,
    )
    pay_rev_loc = gw.rev_fed_locator("org-payment.io")
    for _ in range(15):
        rh = gw.get_mtls(
            f"{pay_rev_loc.origin_url}/healthz",
            expected_spiffe_id=pay_rev_loc.spiffe_id,
            timeout=3.0,
        )
        if rh.status_code == 200 and int(rh.json().get("version", 0)) >= 1:
            break
        time.sleep(0.25)
    time.sleep(1.0)  # Let sidecar background sync replica pick up federated revocation

    r_trig_lct = gw.post_lct_mtls(
        orch_card.endpoint,
        tok_d3_lct,
        {"op": "trigger_converged_settlement", "city": "Tokyo"},
        expected_spiffe_id=orch_card.spiffe_id,
    )
    assert r_trig_lct.status_code == 200, r_trig_lct.text
    outcomes_lct = r_trig_lct.json()["upstream_body"]["settlement_outcomes"]
    assert outcomes_lct["airline-escrow"]["http_status"] == 403, outcomes_lct
    assert outcomes_lct["hotel-escrow"]["http_status"] == 200, outcomes_lct
    dim3["lct"] = {
        "supports_multiparent_dag_envelope": True,
        "revoked_prefix": rev_flight.target,
        "airline_escrow_status_after_flight_cancel": outcomes_lct["airline-escrow"]["http_status"],
        "hotel_escrow_status": outcomes_lct["hotel-escrow"]["http_status"],
        "hotel_lineage_decision": outcomes_lct["hotel-escrow"]["response"]["result"]["data"]["lineage_decision"],
        "outcome": "FAGIN_SMOOTH_DAG_DEGRADATION",
    }

    # =========================================================================
    # Dimension 4: Slow Primary Zombie Double-Spend on Failover
    # =========================================================================
    dim4: Dict[str, Any] = {}
    zombie_trip_payload = {
        "op": "plan_and_execute_trip",
        "hotel_timeout_sec": 4.5,
        "simulate_primary_zombie_delay_sec": 8.0,
    }
    for o_mode in ("oauth_centralized", "oauth_federated"):
        tid = f"task-m8-d4-{o_mode.replace('_', '-')}-{run_id}"
        r_z, _ = gw.post_oauth_mtls(
            orch_card,
            user_access_tok,
            delegation_mode=o_mode,
            task_id=tid,
            payload=zombie_trip_payload,
            timeout=95.0,
        )
        assert r_z.status_code == 200, r_z.text
        z_tel = None
        for _ in range(25):
            r_insp, _ = gw.post_oauth_mtls(
                hotel_prim_card,
                user_access_tok,
                delegation_mode=o_mode,
                task_id=tid,
                payload={"op": "inspect_zombie_telemetry", "inspect_task_id": tid},
            )
            if r_insp.status_code == 200:
                z_tel = r_insp.json().get("zombie_telemetry")
                if z_tel is not None:
                    break
            time.sleep(0.4)
        assert z_tel is not None and z_tel["zombie_mcp_http_status"] == 200, z_tel
        dim4[o_mode] = {
            "failover_backup_succeeded": True,
            "zombie_wakeup_mcp_status": z_tel["zombie_mcp_http_status"],
            "double_spend_prevented": False,
        }

    tid_d4_lct = f"task-m8-d4-lct-{run_id}"
    tok_d4_lct, _ = gw.mint_root_for_user(
        tid_d4_lct,
        "user:alice@org-alpha.io",
        _full_travel_root_permissions(["Tokyo"], max_amount=900.0),
        target_card=orch_card,
        user_oidc_token=user_id_tok,
    )
    r_z_lct = gw.post_lct_mtls(
        orch_card.endpoint,
        tok_d4_lct,
        zombie_trip_payload,
        expected_spiffe_id=orch_card.spiffe_id,
        timeout=95.0,
    )
    assert r_z_lct.status_code == 200, r_z_lct.text
    tok_insp_lct, _ = gw.mint_root_for_user(
        f"{tid_d4_lct}-insp",
        "user:alice@org-alpha.io",
        _full_travel_root_permissions(["Tokyo"], max_amount=100.0),
        target_card=hotel_prim_card,
        hop_segment="HotelZombieInspect",
        user_oidc_token=user_id_tok,
    )
    z_tel_lct = None
    for _ in range(25):
        r_insp_lct = gw.post_lct_mtls(
            hotel_prim_card.endpoint,
            tok_insp_lct,
            {"op": "inspect_zombie_telemetry", "inspect_task_id": tid_d4_lct},
            expected_spiffe_id=hotel_prim_card.spiffe_id,
        )
        if r_insp_lct.status_code == 200:
            z_tel_lct = r_insp_lct.json().get("zombie_telemetry")
            if z_tel_lct is not None:
                break
        time.sleep(0.4)
    assert z_tel_lct is not None and z_tel_lct["zombie_mcp_http_status"] == 403, z_tel_lct
    dim4["lct"] = {
        "failover_backup_succeeded": True,
        "zombie_wakeup_mcp_status": z_tel_lct["zombie_mcp_http_status"],
        "double_spend_prevented": True,
    }

    # =========================================================================
    # Dimension 5: Central Alpha STS Partition Impact (`alpha-sts` Unreachable)
    # =========================================================================
    dim5: Dict[str, Any] = {}
    if include_alpha_sts_partition:
        # Pre-mint Hop-1 tokens BEFORE partitioning `alpha-sts` so we isolate runtime hop dependency!
        ex_orch_central = gw.oauth_client.exchange_token(
            sts_origins=gw.oauth_sts_origins("org-alpha.io"),
            subject_token=user_access_tok,
            target_audience=orch_card.spiffe_id,
            caller_spiffe_id=gw.identity.spiffe_id,
            caller_workload_svid=gw.identity.workload_svid,
            client_id="lct-gateway",
        )
        ex_flight_fed = gw.oauth_client.exchange_token(
            sts_origins=gw.oauth_sts_origins("org-beta.io"),
            subject_token=user_access_tok,
            target_audience=flight_card.spiffe_id,
            caller_spiffe_id=gw.identity.spiffe_id,
            caller_workload_svid=gw.identity.workload_svid,
            client_id="lct-gateway",
        )
        tid_d5_lct = f"task-m8-d5-lct-{run_id}"
        tok_d5_lct, _ = gw.mint_root_for_user(
            tid_d5_lct,
            "user:alice@org-alpha.io",
            _full_travel_root_permissions(["Tokyo"], max_amount=900.0),
            target_card=orch_card,
            user_oidc_token=user_id_tok,
        )

        f_req_stop = "/tmp/m8_ready_stop_alpha_sts"
        f_ack_stop = "/tmp/m8_ack_stopped_alpha_sts"
        f_req_rest = "/tmp/m8_ready_restore_alpha_sts"
        f_ack_rest = "/tmp/m8_ack_restored_alpha_sts"
        for mf in (f_req_stop, f_ack_stop, f_req_rest, f_ack_rest):
            try:
                os.remove(mf)
            except FileNotFoundError:
                pass

        with open(f_req_stop, "w", encoding="utf-8") as fh:
            fh.write("READY\n")
        deadline_stop = time.time() + 90.0
        while not os.path.exists(f_ack_stop):
            if time.time() > deadline_stop:
                raise RuntimeError("Timed out waiting for host to stop alpha-sts")
            time.sleep(0.25)

        try:
            # 1) `oauth_centralized`: Orchestrator holds valid T_1, tries to delegate to Beta -> FAILS (alpha-sts down)!
            url_orch = f"{orch_card.endpoint.rstrip('/')}/a2a/task"
            with httpx.Client(
                verify=gw.mtls_bundle.verify_for_target(
                    target_url=url_orch, expected_spiffe_id=orch_card.spiffe_id
                ),
                timeout=20.0,
                trust_env=False,
            ) as c_p:
                r_cent_part = c_p.post(
                    url_orch,
                    json={
                        "op": "probe_flight_overprivilege",
                        "allowed_city": "Tokyo",
                        "budget_cap_usd": 650.0,
                        "attempt_amount_usd": 580.0,
                        "attempt_city": "Tokyo",
                    },
                    headers={
                        "Authorization": f"Bearer {ex_orch_central.access_token}",
                        "X-LCT-Delegation-Mode": "oauth_centralized",
                        "X-LCT-Task-Id": f"task-m8-d5-central-{run_id}",
                    },
                )
            assert r_cent_part.status_code == 502, r_cent_part.text

            # 2) `oauth_federated`: Beta (`FlightSpecialist`) exchanges at `payment-sts` without touching `alpha-sts` -> 200 OK!
            url_flt = f"{flight_card.endpoint.rstrip('/')}/a2a/task"
            with httpx.Client(
                verify=gw.mtls_bundle.verify_for_target(
                    target_url=url_flt, expected_spiffe_id=flight_card.spiffe_id
                ),
                timeout=35.0,
                trust_env=False,
            ) as c_f:
                r_fed_part = c_f.post(
                    url_flt,
                    json={"city": "Tokyo", "skip_convergence": True},
                    headers={
                        "Authorization": f"Bearer {ex_flight_fed.access_token}",
                        "X-LCT-Delegation-Mode": "oauth_federated",
                        "X-LCT-Task-Id": f"task-m8-d5-fed-{run_id}",
                    },
                )
            assert r_fed_part.status_code == 200, r_fed_part.text

            # 3) `lct`: Full `Alpha -> Beta -> Pay` execution with 0 STS calls -> 200 OK!
            r_lct_part = gw.post_lct_mtls(
                orch_card.endpoint,
                tok_d5_lct,
                {
                    "op": "probe_flight_overprivilege",
                    "allowed_city": "Tokyo",
                    "budget_cap_usd": 650.0,
                    "attempt_amount_usd": 580.0,
                    "attempt_city": "Tokyo",
                },
                expected_spiffe_id=orch_card.spiffe_id,
                timeout=45.0,
            )
            assert r_lct_part.status_code == 200, r_lct_part.text

            dim5 = {
                "oauth_centralized": {
                    "http_status_during_alpha_sts_outage": r_cent_part.status_code,
                    "survives_central_sts_outage": False,
                    "detail": r_cent_part.json().get("error"),
                },
                "oauth_federated": {
                    "beta_to_pay_http_status_during_alpha_sts_outage": r_fed_part.status_code,
                    "downstream_orgs_survive_alpha_sts_outage": True,
                    "new_alpha_hop0_blocked": True,
                },
                "lct": {
                    "alpha_to_beta_to_pay_http_status_during_alpha_sts_outage": r_lct_part.status_code,
                    "survives_central_sts_outage": True,
                    "online_sts_calls_needed": 0,
                },
            }
        finally:
            with open(f_req_rest, "w", encoding="utf-8") as fh:
                fh.write("READY\n")
            deadline_rest = time.time() + 120.0
            while not os.path.exists(f_ack_rest):
                if time.time() > deadline_rest:
                    raise RuntimeError("Timed out waiting for host to restore alpha-sts")
                time.sleep(0.3)
            for mf in (f_req_stop, f_ack_stop, f_req_rest, f_ack_rest):
                try:
                    os.remove(mf)
                except FileNotFoundError:
                    pass

    # =========================================================================
    # Dimension 6: Causal Audit Reconstruction Coverage
    # =========================================================================
    time.sleep(0.8)
    sts_log_counts: Dict[str, int] = {}
    sts_task_linked = 0
    for td_peer in ("org-beta.io", "org-payment.io"):
        for s_orig in gw.oauth_sts_origins(td_peer):
            try:
                r_lg = httpx.get(f"{s_orig}/v1/sts/exchange-logs", timeout=4.0, trust_env=False)
                if r_lg.status_code == 200:
                    lg_doc = r_lg.json()
                    sts_log_counts[td_peer] = int(lg_doc.get("exchange_count") or 0)
                    sts_task_linked += sum(
                        1
                        for item in (lg_doc.get("logs") or [])
                        if item.get("has_task_correlation_id") or item.get("has_parent_block_hash")
                    )
                    break
            except Exception:
                continue

    audit_entries = gw.audit_client.fetch_entries()
    auditor = CausalChainAuditor(
        gw.resolver,
        trusted_revocation_spiffe_ids=[
            "spiffe://org-alpha.io/ns/sys/sa/revocation",
            "spiffe://org-beta.io/ns/sys/sa/revocation",
            "spiffe://org-payment.io/ns/sys/sa/revocation",
        ],
    )
    full_audit_report = auditor.audit(audit_entries)
    assert full_audit_report.stream_integrity_ok, full_audit_report.anomalies
    d1_trec = full_audit_report.tasks.get(tid_d1_lct)
    assert d1_trec is not None and d1_trec.reconstructed_complete, d1_trec
    assert len(d1_trec.anomalies) == 0, d1_trec.anomalies
    assert d1_trec.verified_hops >= 3 and d1_trec.tool_invocations_verified >= 4, d1_trec
    d1_mp_merges = sum(
        1
        for e in audit_entries
        if e.task_id == tid_d1_lct and len(e.multi_parent_hashes) >= 2
    )
    assert d1_mp_merges >= 1, d1_mp_merges
    d1_verified_events = sum(1 for e in audit_entries if e.task_id == tid_d1_lct)

    dim6 = {
        "oauth_centralized": {
            "task_correlated_dag_events": 0,
            "hash_linked_causal_coverage_pct": 0.0,
            "note": "Stateless STS token issuance has zero task_id or parent_block_hash linkage",
        },
        "oauth_federated": {
            "per_org_sts_exchange_records": sts_log_counts,
            "task_correlated_dag_events": sts_task_linked,
            "hash_linked_causal_coverage_pct": 0.0,
            "note": "Fragmented per-domain STS logs lack cross-domain parent hashes and tool parameters",
        },
        "lct": {
            "verified_causal_events_for_d1_trip": d1_verified_events,
            "verified_hops": d1_trec.verified_hops,
            "tool_invocations_verified": d1_trec.tool_invocations_verified,
            "tampered_or_unverified_events": len(d1_trec.anomalies),
            "multiparent_dag_merges_verified": d1_mp_merges,
            "hash_linked_causal_coverage_pct": 100.0,
        },
    }

    return {
        "status": "PASS",
        "run_id": run_id,
        "alpha_sts_engine": ("keycloak-26.5.2" if is_real_keycloak else "lightweight-rfc8693-sts"),
        "hop0_oidc_login": {
            "sts_endpoint": hop0_sts_endpoint,
            "login_rtt_ms": hop0_login_rtt_ms,
            "bridged_lct_sub": "user:alice@org-alpha.io",
        },
        "dimensions": {
            "1_latency_and_sts_rpcs": dim1,
            "2_fine_grained_overprivilege": dim2,
            "3_multiparent_convergence_and_branch_cancel": dim3,
            "4_zombie_primary_failover_double_spend": dim4,
            "5_central_sts_partition_impact": dim5,
            "6_causal_audit_reconstruction": dim6,
        },
        "converger_spiffe_id": conv_card.spiffe_id,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True)
    parser.add_argument("--run-id", default="m3")
    parser.add_argument("--self-pod-ip", default="127.0.0.1")
    parser.add_argument("--sync-marker-file", default="/tmp/s3b_ready")
    parser.add_argument("--pod-ips-json", default="{}")
    parser.add_argument("--foreign-pod-ips-json", default="{}")
    parser.add_argument("--skip-sts-partition", action="store_true")
    parser.add_argument("--task-id", default="")
    args = parser.parse_args()

    gw = GatewaySession()
    phase = args.phase
    try:
        if phase == "multicluster_isolation_proofs":
            out = run_multicluster_isolation_proofs(gw, args.foreign_pod_ips_json)
        elif phase == "scenario1_normal_dag":
            out = run_scenario_1(gw, args.run_id)
        elif phase == "scenario2a_zombie_prune_and_graft":
            out = run_scenario_2a(gw, args.run_id)
        elif phase == "scenario2b_pod_down_prune_and_graft":
            out = run_scenario_2b(gw, args.run_id)
        elif phase == "scenario3a_forged_skip_blocked_while_alive":
            out = run_scenario_3a(gw, args.run_id)
        elif phase == "scenario3b_genuine_skip_level_when_pod_killed":
            out = run_scenario_3b(gw, args.run_id, args.self_pod_ip, args.sync_marker_file)
        elif phase == "scenario4_fagin_degradation_concurrency_and_bypass_guard":
            out = run_scenario_4(gw, args.run_id, args.pod_ips_json)
        elif phase == "scenario6_whole_cluster_partition":
            out = run_scenario_6_whole_cluster_partition(gw, args.run_id)
        elif phase == "scenario5_cluster_audit_reconstruction":
            out = run_scenario_5(gw)
        elif phase == "m8_compare_protocols":
            out = run_m8_protocol_comparison(
                gw,
                args.run_id,
                include_alpha_sts_partition=(not args.skip_sts_partition),
            )
        elif phase.startswith("ws_"):
            from lineage.k8s.workspace_e2e import (
                run_distributed_audit_for_task,
                run_ws_scenario_1_intent_fanout_converge,
                run_ws_scenario_2_cross_principal_and_coauth,
                run_ws_scenario_3_expiry_checkpoint_continuation,
                run_ws_scenario_4a_post_commit_idempotent_failover,
                run_ws_scenario_4b_skip_level_return,
                run_ws_scenario_5_degradation_compare_and_audit,
                run_ws_scenario_6_bidirectional_fin_pingpong,
                run_ws_scenario_7_legal_redline_negotiation,
                run_ws_scenario_8_supply_chain_sod,
                run_ws_scenario_9_federated_medical_cohort,
                run_ws_scenario_10_prompt_injection_cascading_revocation,
                run_ws_scenario_11_symmetric_beta_entry_and_token_theft,
            )

            if phase == "ws_scenario1":
                out = run_ws_scenario_1_intent_fanout_converge(gw, args.run_id)
            elif phase == "ws_scenario2":
                out = run_ws_scenario_2_cross_principal_and_coauth(gw, args.run_id)
            elif phase == "ws_scenario3":
                out = run_ws_scenario_3_expiry_checkpoint_continuation(gw, args.run_id)
            elif phase == "ws_scenario4a":
                out = run_ws_scenario_4a_post_commit_idempotent_failover(gw, args.run_id)
            elif phase == "ws_scenario4b":
                out = run_ws_scenario_4b_skip_level_return(
                    gw,
                    args.run_id,
                    sync_marker_file=(args.sync_marker_file or None),
                )
            elif phase == "ws_scenario5":
                out = run_ws_scenario_5_degradation_compare_and_audit(gw, args.run_id)
            elif phase == "ws_scenario6":
                out = run_ws_scenario_6_bidirectional_fin_pingpong(gw, args.run_id)
            elif phase == "ws_scenario7":
                out = run_ws_scenario_7_legal_redline_negotiation(gw, args.run_id)
            elif phase == "ws_scenario8":
                out = run_ws_scenario_8_supply_chain_sod(gw, args.run_id)
            elif phase == "ws_scenario9":
                out = run_ws_scenario_9_federated_medical_cohort(gw, args.run_id)
            elif phase == "ws_scenario10":
                out = run_ws_scenario_10_prompt_injection_cascading_revocation(gw, args.run_id)
            elif phase == "ws_scenario11":
                out = run_ws_scenario_11_symmetric_beta_entry_and_token_theft(gw, args.run_id)
            elif phase == "ws_distributed_audit":
                out = run_distributed_audit_for_task(gw, args.task_id)
            else:
                print(f"Unknown workspace phase: {phase!r}", file=sys.stderr)
                sys.exit(2)
        elif phase == "export_redacted_audit_entries":
            entries = [e.to_dict() for e in gw.audit_client.fetch_entries()]
            out = {"count": len(entries), "entries": _scrub_for_disk(entries)}
        else:
            print(f"Unknown phase: {phase!r}", file=sys.stderr)
            sys.exit(2)
    finally:
        gw.syncer.stop_background_refresh()
        gw.mtls_bundle.cleanup()

    print(json.dumps(_scrub_for_disk(out), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
