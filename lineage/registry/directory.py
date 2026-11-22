"""Real HTTP Agent Directory Service & Client with Anti-Poisoning & Fallback Discovery."""

from __future__ import annotations

import ssl
import threading
import time
import uuid
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Set, Tuple

import httpx

from lineage.common.crypto import (
    CryptoError,
    jws_sign_compact,
    jws_verify_compact,
    require_finite_timestamp,
    sha256_b64url,
)
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.common.mtls import WorkloadMTLSBundle
from lineage.identity.spiffe import (
    IdentityError,
    SpiffeId,
    TrustDomainCA,
    WorkloadIdentity,
)
from lineage.identity.trust_bundle import TrustBundleResolver
from lineage.protocol.dpop import JTIReplayCache
from lineage.protocol.token import (
    LineageToken,
    TokenError,
    decode_token,
    is_lineage_segment_prefix,
    lineage_token_delegator_paths,
    verify_lineage_token_cryptography,
)
from lineage.registry.agent_card import AgentCard, AgentCardError, AgentStatus


class AgentDirectoryService:
    """HTTP-backed Dynamic Agent Directory supporting cross-domain signed AgentCards."""

    def __init__(
        self,
        trust_resolver: TrustBundleResolver,
        authorized_admins: Iterable[str] = (),
        revocation_trie: Optional[Any] = None,
        revocation_replica: Optional[Any] = None,
        host: str = "127.0.0.1",
        port: int = 0,
        local_trust_domain: Optional[str] = None,
        peer_directory_urls: Optional[Mapping[str, str]] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
        peer_cert_verifier: Optional[Callable[[bytes], Tuple[str, str]]] = None,
        client_ssl_context: Optional[ssl.SSLContext] = None,
        federation_port: Optional[int] = None,
        federation_ssl_context: Optional[ssl.SSLContext] = None,
        federation_peer_cert_verifier: Optional[Callable[[bytes], Tuple[str, str]]] = None,
        mtls_bundle: Optional[WorkloadMTLSBundle] = None,
    ) -> None:
        self.trust_resolver = trust_resolver
        self.revocation_trie = revocation_trie
        self.revocation_replica = revocation_replica
        self.local_trust_domain = local_trust_domain
        self.peer_directory_urls: Dict[str, str] = {
            str(td): str(u).rstrip("/")
            for td, u in (peer_directory_urls or {}).items()
            if str(td) and str(td) != local_trust_domain
        }
        self._client_ssl_context = client_ssl_context
        self._mtls_bundle = mtls_bundle
        self._lock = threading.RLock()
        self._cards: Dict[str, AgentCard] = {}
        self._quarantined_spiffe_ids: Set[str] = set()
        self._authorized_admins: Set[str] = {
            SpiffeId.parse(a).uri for a in authorized_admins
        }
        self._cmd_replay_cache = JTIReplayCache(ttl_seconds=300.0)
        self._fed_stop = threading.Event()
        self._fed_thread: Optional[threading.Thread] = None
        self._http = ManagedHTTPService(
            service_name="agent-directory",
            dispatcher=self._dispatch,
            host=host,
            port=port,
            ssl_context=ssl_context,
            peer_cert_verifier=peer_cert_verifier,
        )
        eff_fed_ssl = federation_ssl_context
        eff_fed_verifier = federation_peer_cert_verifier
        if eff_fed_ssl is None and mtls_bundle is not None and federation_port is not None:
            eff_fed_ssl = mtls_bundle.build_server_ssl_context(require_client_cert=True)
        if eff_fed_verifier is None and mtls_bundle is not None and federation_port is not None:
            eff_fed_verifier = mtls_bundle.trust_store.verify_peer_der_cert
        self._fed_require_mtls = eff_fed_ssl is not None
        self._federation_http: Optional[ManagedHTTPService] = (
            ManagedHTTPService(
                service_name="agent-directory-federation",
                dispatcher=self._dispatch_federation,
                host=host,
                port=int(federation_port),
                ssl_context=eff_fed_ssl,
                peer_cert_verifier=eff_fed_verifier,
            )
            if federation_port is not None
            else None
        )

    def start(self) -> str:
        url = self._http.start()
        if self._federation_http is not None:
            self._federation_http.start()
        if self.peer_directory_urls:
            self.start_federation_sync()
        return url

    def stop(self) -> None:
        self.stop_federation_sync()
        if self._federation_http is not None:
            self._federation_http.stop()
        self._http.stop()

    def _http_verify_kwarg(
        self,
        peer_url: Optional[str] = None,
        expected_domain: Optional[str] = None,
    ) -> Any:
        if self._mtls_bundle is not None:
            return self._mtls_bundle.verify_for_target(
                target_url=peer_url,
                expected_trust_domain=expected_domain,
            )
        return self._client_ssl_context if self._client_ssl_context is not None else True

    @property
    def base_url(self) -> str:
        return self._http.base_url

    @property
    def federation_base_url(self) -> Optional[str]:
        return (
            self._federation_http.base_url if self._federation_http is not None else None
        )

    @property
    def port(self) -> int:
        return self._http.port

    @property
    def federation_port(self) -> Optional[int]:
        return self._federation_http.port if self._federation_http is not None else None

    def _resolve_trie(self) -> Optional[Any]:
        if self.revocation_replica is not None:
            try:
                self.revocation_replica.sync_now()
            except Exception:
                pass
            return getattr(self.revocation_replica, "trie", self.revocation_trie)
        return self.revocation_trie

    def _is_workload_quarantined(self, spiffe_id: str) -> bool:
        with self._lock:
            if spiffe_id in self._quarantined_spiffe_ids:
                return True
        trie = self._resolve_trie()
        if trie is not None and trie.check_workloads([spiffe_id]) is not None:
            return True
        return False

    def register_card_direct(self, raw_card: Dict[str, Any]) -> AgentCard:
        """Validate and store a signed AgentCard (enforcing local_trust_domain when configured)."""
        card = AgentCard.from_dict_and_verify(raw_card, self.trust_resolver)
        if (
            self.local_trust_domain is not None
            and card.trust_domain != self.local_trust_domain
        ):
            raise AgentCardError(
                f"Direct registration rejected: card domain {card.trust_domain!r} != "
                f"autonomous directory domain {self.local_trust_domain!r}"
            )
        if self._is_workload_quarantined(card.spiffe_id):
            raise AgentCardError(
                f"Workload {card.spiffe_id!r} is quarantined and cannot re-register"
            )
        with self._lock:
            if card.spiffe_id in self._quarantined_spiffe_ids:
                raise AgentCardError(
                    f"Workload {card.spiffe_id!r} is quarantined and cannot re-register"
                )
            existing = self._cards.get(card.spiffe_id)
            if existing is not None and card.version <= existing.version:
                raise AgentCardError(
                    f"AgentCard version rollback rejected for {card.spiffe_id!r}: "
                    f"v{card.version} <= existing v{existing.version}"
                )
            self._cards[card.spiffe_id] = card
        return card

    def ingest_federated_card(
        self, raw_card: Mapping[str, Any], expected_peer_domain: str
    ) -> AgentCard:
        """Cryptographically verify and import a foreign-domain AgentCard from a federated peer.

        Strictly blocks cross-domain card spoofing (`beta-directory` serving an `org-alpha.io` card).
        """
        if self.local_trust_domain and expected_peer_domain == self.local_trust_domain:
            raise AgentCardError("Cannot ingest own domain via federated peer channel")
        card = AgentCard.from_dict_and_verify(raw_card, self.trust_resolver)
        if card.trust_domain != expected_peer_domain:
            raise AgentCardError(
                f"Federated directory spoofing blocked: peer {expected_peer_domain!r} "
                f"advertised card claiming trust_domain={card.trust_domain!r} ({card.spiffe_id!r})"
            )
        if self._is_workload_quarantined(card.spiffe_id):
            raise AgentCardError(f"Federated workload {card.spiffe_id!r} is quarantined")
        with self._lock:
            existing = self._cards.get(card.spiffe_id)
            if existing is not None:
                if card.version < existing.version:
                    raise AgentCardError(
                        f"Federated AgentCard version rollback rejected for {card.spiffe_id!r}"
                    )
                if card.version == existing.version:
                    return existing
            self._cards[card.spiffe_id] = card
        return card

    def sync_from_federation_peers(self) -> int:
        """Pull verified public AgentCards from all configured peer domain directories."""
        imported = 0
        for peer_td, peer_url in list(self.peer_directory_urls.items()):
            try:
                with httpx.Client(
                    verify=self._http_verify_kwarg(peer_url=peer_url, expected_domain=peer_td),
                    timeout=2.0,
                ) as client:
                    resp = client.get(f"{peer_url}/v1/federation/cards")
                    resp.raise_for_status()
                    data = resp.json()
            except Exception:
                continue
            if data.get("trust_domain") != peer_td:
                continue
            for raw_c in data.get("cards") or []:
                try:
                    self.ingest_federated_card(raw_c, expected_peer_domain=peer_td)
                    imported += 1
                except Exception:
                    continue
        return imported

    def start_federation_sync(self, interval_sec: float = 0.8) -> None:
        if self._fed_thread is not None and self._fed_thread.is_alive():
            return
        self._fed_stop.clear()

        def _loop() -> None:
            while not self._fed_stop.is_set():
                try:
                    self.sync_from_federation_peers()
                except Exception:
                    pass
                self._fed_stop.wait(interval_sec)

        self._fed_thread = threading.Thread(
            target=_loop,
            name=f"dir-fed-{self.local_trust_domain or 'shared'}",
            daemon=True,
        )
        self._fed_thread.start()

    def stop_federation_sync(self) -> None:
        self._fed_stop.set()
        if self._fed_thread is not None:
            self._fed_thread.join(timeout=2.0)
            self._fed_thread = None

    def _notify_federation_peers(self) -> None:
        """Zero-trust wakeup signal prompting peer directories to pull `/v1/federation/cards`."""
        if not self.peer_directory_urls:
            return
        for peer_td, peer_url in list(self.peer_directory_urls.items()):
            try:
                with httpx.Client(
                    verify=self._http_verify_kwarg(peer_url=peer_url, expected_domain=peer_td),
                    timeout=0.6,
                ) as client:
                    client.post(f"{peer_url}/v1/federation/notify", json={})
            except Exception:
                pass

    def quarantine_workload(self, spiffe_id: str) -> bool:
        """Mark a workload as QUARANTINED so discovery immediately excludes it."""
        with self._lock:
            self._quarantined_spiffe_ids.add(spiffe_id)
            return spiffe_id in self._cards

    def discover_cards(
        self,
        skill: Optional[str] = None,
        trust_domain: Optional[str] = None,
        exclude_spiffe_ids: Iterable[str] = (),
        only_healthy: bool = True,
        now: Optional[float] = None,
    ) -> List[AgentCard]:
        ts = time.time() if now is None else float(now)
        excluded = set(exclude_spiffe_ids)
        results: List[AgentCard] = []
        with self._lock:
            for spiffe_id, card in self._cards.items():
                if spiffe_id in excluded:
                    continue
                if card.expires_at <= ts:
                    continue
                is_quarantined = (
                    spiffe_id in self._quarantined_spiffe_ids
                    or card.status == AgentStatus.QUARANTINED
                )
                if only_healthy:
                    if is_quarantined or card.status != AgentStatus.ACTIVE:
                        continue
                if trust_domain and card.trust_domain != trust_domain:
                    continue
                if skill and skill not in card.skills:
                    continue
                results.append(card)

        # Sort by priority ascending (lower number = higher priority), then version desc, then spiffe_id
        results.sort(key=lambda c: (c.priority, -c.version, c.spiffe_id))
        return results

    def _dispatch_federation(
        self, req: HTTPRequestContext
    ) -> Tuple[int, Any, Dict[str, str]]:
        """External mTLS 1.3 cross-cluster directory port (`:8491`).

        Strictly allows ONLY `/healthz`, `GET /v1/federation/cards`, and
        `POST /v1/federation/notify` for authenticated federated X.509 peers;
        rejects external `/v1/agents/register` & `/v1/agents/quarantine` with `403`.
        """
        if req.method == "GET" and req.path == "/healthz":
            return (
                200,
                {
                    "status": "ok",
                    "service": "agent-directory-federation",
                    "trust_domain": self.local_trust_domain,
                },
                {},
            )
        if self._fed_require_mtls:
            if not req.peer_spiffe_id:
                return 403, {"error": "unauthenticated_federation_peer"}, {}
            try:
                SpiffeId.parse(req.peer_spiffe_id)
            except IdentityError:
                return 403, {"error": "invalid_federation_peer_spiffe"}, {}

        if req.method == "GET" and req.path == "/v1/federation/cards":
            return self._dispatch(req)
        if req.method == "POST" and req.path == "/v1/federation/notify":
            return self._dispatch(req)
        return (
            403,
            {
                "error": "federation_port_restricted",
                "detail": f"Route {req.method} {req.path} is forbidden on external federation directory port",
            },
            {},
        )

    def _dispatch(
        self, req: HTTPRequestContext
    ) -> Tuple[int, Any, Dict[str, str]]:
        if req.method == "GET" and req.path == "/healthz":
            return 200, {"status": "ok", "service": "agent-directory"}, {}

        if req.method == "GET" and req.path == "/.well-known/jwks.json":
            return (
                200,
                {"bundles": self.trust_resolver.export_federation_bundles()},
                {},
            )

        if req.method == "POST" and req.path == "/v1/agents/register":
            body = req.json()
            card_payload = body.get("agent_card", body)
            try:
                card = self.register_card_direct(card_payload)
            except AgentCardError as exc:
                return 403, {"error": "agent_card_rejected", "detail": str(exc)}, {}
            self._notify_federation_peers()
            return (
                200,
                {
                    "registered": True,
                    "spiffe_id": card.spiffe_id,
                    "version": card.version,
                    "jkt": card.jkt,
                },
                {},
            )

        if req.method == "POST" and req.path == "/v1/federation/notify":
            imported = self.sync_from_federation_peers()
            return 200, {"synced": True, "imported": imported}, {}

        if req.method == "POST" and req.path == "/v1/agents/quarantine":
            # Signed administrative/resilience quarantine command with strict domain & delegator scope
            body = req.json()
            try:
                auth_mode = str(body.get("auth_mode", "workload"))
                command_jws = str(body.get("command_jws", ""))
                if not command_jws:
                    return 403, {"error": "missing_command_jws"}, {}

                if auth_mode == "domain_authority":
                    caller_td = str(body.get("trust_domain", ""))
                    _, cmd = self.trust_resolver.verify_domain_jws(
                        command_jws,
                        expected_trust_domain=caller_td,
                        expected_typ="lct-quarantine+jwt",
                    )
                    reporter_uri = f"spiffe://{caller_td}/authority/root"
                else:
                    reporter_svid = str(body.get("reporter_svid", ""))
                    svid_claims = self.trust_resolver.verify_workload_svid(reporter_svid)
                    reporter_jwk = svid_claims["cnf"]["jwk"]
                    reporter_jkt = str(svid_claims["cnf"]["jkt"])
                    _, cmd = jws_verify_compact(
                        command_jws, reporter_jwk, expected_typ="lct-quarantine+jwt"
                    )
                    reporter_uri = str(svid_claims["sub"])

                target_spiffe = SpiffeId.parse(str(cmd["target_spiffe_id"]))
                now_ts = time.time()
                iat_val = require_finite_timestamp(cmd.get("iat"), "iat")
                if abs(now_ts - iat_val) > 30.0:
                    return 403, {"error": "stale_quarantine_command"}, {}

                cmd_jti = str(cmd.get("jti") or sha256_b64url(command_jws.encode("ascii")))
                if not self._cmd_replay_cache.check_and_record(cmd_jti, now=now_ts):
                    return 403, {"error": "replayed_quarantine_command"}, {}

                # Enforce strict trust-domain boundary & Hop-0 Root Coordinator / CA jurisdiction (`[HIGH-R2-01]`)
                if auth_mode == "domain_authority":
                    if caller_td != target_spiffe.trust_domain:
                        return (
                            403,
                            {
                                "error": "cross_domain_quarantine_forbidden",
                                "detail": f"CA {caller_td!r} cannot quarantine {target_spiffe.uri!r}",
                            },
                            {},
                        )
                else:
                    reporter_spiffe = SpiffeId.parse(reporter_uri)
                    if reporter_spiffe.trust_domain != target_spiffe.trust_domain:
                        return (
                            403,
                            {
                                "error": "cross_domain_quarantine_forbidden",
                                "detail": (
                                    f"Workload {reporter_spiffe.uri!r} cannot globally quarantine "
                                    f"foreign-domain workload {target_spiffe.uri!r}"
                                ),
                            },
                            {},
                        )
                    # Quarantined callers are stripped of quarantine authority (`[MEDIUM-R3-01]`)
                    if self._is_workload_quarantined(reporter_spiffe.uri):
                        return (
                            403,
                            {
                                "error": "quarantined_caller_forbidden",
                                "detail": f"Quarantined caller {reporter_spiffe.uri!r} cannot quarantine peers",
                            },
                            {},
                        )
                    if reporter_spiffe.uri not in self._authorized_admins:
                        if target_spiffe.path.startswith("/ns/sys/"):
                            return (
                                403,
                                {
                                    "error": "unauthorized_quarantine_caller",
                                    "detail": "System infrastructure workload may only be quarantined by TrustDomainCA or authorized_admins",
                                },
                                {},
                            )
                        if reporter_spiffe.path.startswith(
                            ("/ns/sandbox/", "/ns/untrusted/", "/ns/evil/")
                        ):
                            return (
                                403,
                                {
                                    "error": "unauthorized_quarantine_caller",
                                    "detail": "Sandbox/untrusted workload forbidden from global quarantine",
                                },
                                {},
                            )
                        auth_tok_str = cmd.get("authority_token") or body.get("authority_token")
                        if not auth_tok_str or not isinstance(auth_tok_str, str):
                            return (
                                403,
                                {
                                    "error": "unauthorized_quarantine_caller",
                                    "detail": "Same-domain non-admin workload must present unexpired 1-hop authority_token",
                                },
                                {},
                            )
                        parsed_auth = decode_token(auth_tok_str)
                        if not isinstance(parsed_auth, LineageToken):
                            return 403, {"error": "invalid_authority_token_kind"}, {}
                        verify_lineage_token_cryptography(
                            parsed_auth, self.trust_resolver, now=now_ts
                        )
                        if (
                            parsed_auth.root.issuer_trust_domain != target_spiffe.trust_domain
                            or parsed_auth.root.delegate_spiffe_id != reporter_spiffe.uri
                            or parsed_auth.root.cnf_jkt != reporter_jkt
                            or parsed_auth.root.max_depth < 1
                            or reporter_spiffe.uri == target_spiffe.uri
                            or len(parsed_auth.hops) != 1
                            or parsed_auth.hops[0].issuer_spiffe_id != reporter_spiffe.uri
                            or parsed_auth.hops[0].delegate_spiffe_id != target_spiffe.uri
                        ):
                            return (
                                403,
                                {
                                    "error": "unauthorized_quarantine_caller",
                                    "detail": (
                                        f"{reporter_spiffe.uri!r} must present a valid 1-hop Root Coordinator "
                                        f"authority_token directly delegating to {target_spiffe.uri!r}"
                                    ),
                                },
                                {},
                            )
                        trie = self._resolve_trie()
                        hop0_coord = f"/{parsed_auth.root.task_id}/{parsed_auth.root.hop_segment}"
                        if (
                            trie is not None
                            and trie.check_lineage_path(
                                hop0_coord,
                                trust_domain=parsed_auth.root.issuer_trust_domain,
                            )
                            is not None
                        ):
                            return (
                                403,
                                {
                                    "error": "revoked_authority_token",
                                    "detail": f"Hop-0 lineage {hop0_coord!r} has already been revoked",
                                },
                                {},
                            )
            except (IdentityError, CryptoError, TokenError, KeyError, ValueError) as exc:
                return 403, {"error": "invalid_quarantine_auth", "detail": str(exc)}, {}

            existed = self.quarantine_workload(target_spiffe.uri)
            return (
                200,
                {
                    "quarantined": True,
                    "target_spiffe_id": target_spiffe.uri,
                    "reporter": reporter_uri,
                    "card_existed": existed,
                },
                {},
            )

        if req.method == "GET" and req.path == "/v1/federation/cards":
            local_cards = self.discover_cards(
                trust_domain=self.local_trust_domain,
                only_healthy=True,
            )
            return (
                200,
                {
                    "trust_domain": self.local_trust_domain,
                    "cards": [c.to_dict() for c in local_cards],
                },
                {},
            )

        if req.method == "GET" and req.path == "/v1/agents/get":
            spiffe_id = str(req.query.get("spiffe_id", ""))
            with self._lock:
                card = self._cards.get(spiffe_id)
                quarantined = spiffe_id in self._quarantined_spiffe_ids
            if card is None and self.peer_directory_urls:
                self.sync_from_federation_peers()
                with self._lock:
                    card = self._cards.get(spiffe_id)
                    quarantined = spiffe_id in self._quarantined_spiffe_ids
            if card is None:
                return 404, {"error": "not_found", "spiffe_id": spiffe_id}, {}
            if self._is_workload_quarantined(spiffe_id):
                quarantined = True
            return (
                200,
                {
                    "agent_card": card.to_dict(),
                    "quarantined": quarantined or card.status == AgentStatus.QUARANTINED,
                },
                {},
            )

        if req.method == "GET" and req.path == "/v1/agents/discover":
            skill = req.query.get("skill")
            if isinstance(skill, list):
                skill = skill[0]
            trust_domain = req.query.get("trust_domain")
            if isinstance(trust_domain, list):
                trust_domain = trust_domain[0]
            exclude_param = req.query.get("exclude", "")
            if isinstance(exclude_param, list):
                excluded = [item for sub in exclude_param for item in sub.split(",") if item]
            elif exclude_param:
                excluded = [x.strip() for x in str(exclude_param).split(",") if x.strip()]
            else:
                excluded = []

            only_healthy_str = str(req.query.get("only_healthy", "true")).lower()
            only_healthy = only_healthy_str in ("true", "1", "yes")

            cards = self.discover_cards(
                skill=str(skill) if skill else None,
                trust_domain=str(trust_domain) if trust_domain else None,
                exclude_spiffe_ids=excluded,
                only_healthy=only_healthy,
            )
            if not cards and self.peer_directory_urls:
                self.sync_from_federation_peers()
                cards = self.discover_cards(
                    skill=str(skill) if skill else None,
                    trust_domain=str(trust_domain) if trust_domain else None,
                    exclude_spiffe_ids=excluded,
                    only_healthy=only_healthy,
                )
            return 200, {"agents": [c.to_dict() for c in cards]}, {}

        return 404, {"error": "route_not_found", "path": req.path}, {}


class AgentDirectoryClient:
    """HTTP client for AgentDirectoryService that locally re-verifies every AgentCard."""

    def __init__(
        self,
        directory_url: str,
        trust_resolver: TrustBundleResolver,
        timeout: float = 3.0,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        self.directory_url = directory_url.rstrip("/")
        self.trust_resolver = trust_resolver
        self.timeout = timeout
        self.ssl_context = ssl_context

    def _verify_kwarg(self) -> Any:
        return self.ssl_context if self.ssl_context is not None else True

    def register(self, card: AgentCard) -> Dict[str, Any]:
        with httpx.Client(verify=self._verify_kwarg(), timeout=self.timeout) as client:
            resp = client.post(
                f"{self.directory_url}/v1/agents/register",
                json={"agent_card": card.to_dict()},
            )
        if resp.status_code != 200:
            raise AgentCardError(
                f"Directory rejected registration ({resp.status_code}): {resp.text}"
            )
        return resp.json()

    def quarantine(
        self,
        reporter_identity: WorkloadIdentity | TrustDomainCA,
        target_spiffe_id: str,
        reason: str,
        authority_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        cmd_payload: Dict[str, Any] = {
            "jti": f"qcmd-{uuid.uuid4().hex}",
            "target_spiffe_id": target_spiffe_id,
            "reason": reason,
            "iat": time.time(),
        }
        if authority_token:
            cmd_payload["authority_token"] = authority_token

        if isinstance(reporter_identity, TrustDomainCA):
            cmd_jws = jws_sign_compact(
                payload=cmd_payload,
                keypair=reporter_identity.active_keypair,
                typ="lct-quarantine+jwt",
            )
            req_json: Dict[str, Any] = {
                "auth_mode": "domain_authority",
                "trust_domain": reporter_identity.trust_domain,
                "command_jws": cmd_jws,
            }
        else:
            cmd_jws = jws_sign_compact(
                payload=cmd_payload,
                keypair=reporter_identity.keypair,
                typ="lct-quarantine+jwt",
            )
            req_json = {
                "auth_mode": "workload",
                "reporter_svid": reporter_identity.workload_svid,
                "command_jws": cmd_jws,
            }

        with httpx.Client(verify=self._verify_kwarg(), timeout=self.timeout) as client:
            resp = client.post(
                f"{self.directory_url}/v1/agents/quarantine",
                json=req_json,
            )
        if resp.status_code != 200:
            raise AgentCardError(
                f"Directory rejected quarantine ({resp.status_code}): {resp.text}"
            )
        return resp.json()

    def get_agent(self, spiffe_id: str) -> Optional[AgentCard]:
        with httpx.Client(verify=self._verify_kwarg(), timeout=self.timeout) as client:
            resp = client.get(
                f"{self.directory_url}/v1/agents/get",
                params={"spiffe_id": spiffe_id},
            )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
        if data.get("quarantined"):
            return None
        return AgentCard.from_dict_and_verify(data["agent_card"], self.trust_resolver)

    def discover(
        self,
        skill: Optional[str] = None,
        trust_domain: Optional[str] = None,
        exclude_spiffe_ids: Iterable[str] = (),
        only_healthy: bool = True,
    ) -> List[AgentCard]:
        params: Dict[str, str] = {
            "only_healthy": "true" if only_healthy else "false",
        }
        if skill:
            params["skill"] = skill
        if trust_domain:
            params["trust_domain"] = trust_domain
        excluded_list = [e for e in exclude_spiffe_ids if e]
        if excluded_list:
            params["exclude"] = ",".join(excluded_list)

        with httpx.Client(verify=self._verify_kwarg(), timeout=self.timeout) as client:
            resp = client.get(
                f"{self.directory_url}/v1/agents/discover",
                params=params,
            )
        resp.raise_for_status()
        raw_agents = resp.json().get("agents", [])
        verified: List[AgentCard] = []
        excluded_set = set(excluded_list)
        for raw_card in raw_agents:
            # Defense-in-depth: client locally verifies signature & SVID against TrustBundle!
            card = AgentCard.from_dict_and_verify(raw_card, self.trust_resolver)
            if card.spiffe_id in excluded_set:
                continue
            if skill and skill not in card.skills:
                continue
            if only_healthy and card.status != AgentStatus.ACTIVE:
                continue
            verified.append(card)
        return verified
