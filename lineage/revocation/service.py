"""HTTP Revocation Service & Edge Replica Client with Domain-Scoped Trie & Hop-0 Quarantine Auth."""

from __future__ import annotations

import ssl
import threading
import time
import uuid
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Set, Tuple

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
    TokenExpiredError,
    decode_token,
    is_lineage_segment_prefix,
    lineage_token_delegator_paths,
    verify_lineage_token_cryptography,
)
from lineage.revocation.trie import (
    LineagePrefixTrie,
    RevocationEvent,
    parse_revocation_prefix,
)


class RevocationError(Exception):
    """Raised on revocation authentication/authorization failure or anchor sync failure."""


class RevocationService:
    """Authoritative HTTP Cascading Revocation Service with Domain Namespace Isolation."""

    def __init__(
        self,
        service_identity: WorkloadIdentity,
        trust_resolver: TrustBundleResolver,
        audit_hook: Optional[Callable[[RevocationEvent], None]] = None,
        authorized_admins: Iterable[str] = (),
        host: str = "127.0.0.1",
        port: int = 0,
        strict_domain_isolation: bool = False,
        peer_revocation_urls: Optional[Mapping[str, str]] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
        peer_cert_verifier: Optional[Callable[[bytes], Tuple[str, str]]] = None,
        client_ssl_context: Optional[ssl.SSLContext] = None,
        federation_port: Optional[int] = None,
        federation_ssl_context: Optional[ssl.SSLContext] = None,
        federation_peer_cert_verifier: Optional[Callable[[bytes], Tuple[str, str]]] = None,
        mtls_bundle: Optional[WorkloadMTLSBundle] = None,
    ) -> None:
        self.service_identity = service_identity
        self.trust_resolver = trust_resolver
        self.trie = LineagePrefixTrie()
        self._audit_hook = audit_hook
        self._authorized_admins: Set[str] = {
            SpiffeId.parse(a).uri for a in authorized_admins
        }
        self._cmd_replay_cache = JTIReplayCache(ttl_seconds=300.0)
        self.strict_domain_isolation = bool(
            strict_domain_isolation or peer_revocation_urls is not None
        )
        self.peer_revocation_urls: Dict[str, str] = {
            str(td): str(u).rstrip("/")
            for td, u in (peer_revocation_urls or {}).items()
            if str(td) and str(td) != service_identity.trust_domain
        }
        self._client_ssl_context = client_ssl_context
        self._mtls_bundle = mtls_bundle
        self._peer_cursors: Dict[str, int] = {}
        self._fed_lock = threading.Lock()
        self._fed_stop = threading.Event()
        self._fed_thread: Optional[threading.Thread] = None
        self._http = ManagedHTTPService(
            service_name="revocation-service",
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
                service_name="revocation-federation",
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
        if self.peer_revocation_urls:
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
    def federation_base_url(self) -> Optional[str]:
        return (
            self._federation_http.base_url if self._federation_http is not None else None
        )

    @property
    def federation_port(self) -> Optional[int]:
        return self._federation_http.port if self._federation_http is not None else None

    def ingest_federated_event(
        self, raw_ev: Mapping[str, Any], expected_peer_domain: str
    ) -> RevocationEvent:
        """Verify and import a peer-domain RevocationEvent (blocking cross-domain spoofing)."""
        if expected_peer_domain == self.service_identity.trust_domain:
            raise RevocationError("Cannot ingest own domain as federated revocation peer")
        ev = RevocationEvent.from_dict(raw_ev)
        if ev.trust_domain != expected_peer_domain:
            raise RevocationError(
                f"Federated revocation spoofing blocked: peer {expected_peer_domain!r} "
                f"emitted event claiming trust_domain={ev.trust_domain!r}"
            )
        if not ev.service_svid or not ev.service_signature:
            raise RevocationError("Federated RevocationEvent missing service_svid or signature")
        try:
            svid_claims = self.trust_resolver.verify_workload_svid(ev.service_svid)
            signer_spiffe = SpiffeId.parse(str(svid_claims["sub"]))
        except IdentityError as exc:
            raise RevocationError(f"Federated revocation SVID invalid: {exc}") from exc

        if (
            signer_spiffe.trust_domain != expected_peer_domain
            or signer_spiffe.path != "/ns/sys/sa/revocation"
        ):
            raise RevocationError(
                f"Unauthorized federated revocation signer {signer_spiffe.uri!r} "
                f"for peer domain {expected_peer_domain!r}"
            )

        try:
            _, signed_claims = jws_verify_compact(
                ev.service_signature,
                svid_claims["cnf"]["jwk"],
                expected_typ="lct-revocation-event+jwt",
            )
        except CryptoError as exc:
            raise RevocationError(
                f"Federated RevocationEvent signature invalid: {exc}"
            ) from exc

        if signed_claims != ev.core_claims():
            raise RevocationError("Federated RevocationEvent claims tampered")

        return self.trie.ingest_federated_event(ev)

    def sync_from_federation_peers(
        self, strict_required_domains: Optional[Iterable[str]] = None
    ) -> int:
        """Pull new signed revocation events from configured peer domain authorities.

        When `strict_required_domains` is non-empty (used by synchronous `HIGH_RISK`
        revocation anchoring), any connection failure, timeout, domain mismatch,
        unconfigured peer, or signature verification error on a required foreign domain
        immediately raises `RevocationError` so the caller fails closed (`503`).
        """
        strict_set: Set[str] = {
            str(d).strip().lower()
            for d in (strict_required_domains or ())
            if str(d).strip() and str(d).strip().lower() != self.service_identity.trust_domain
        }
        if self.strict_domain_isolation:
            for req_td in sorted(strict_set):
                if req_td not in self.peer_revocation_urls:
                    raise RevocationError(
                        f"Federated revocation peer for required trust_domain {req_td!r} is not configured"
                    )

        imported = 0
        for peer_td, peer_url in list(self.peer_revocation_urls.items()):
            is_strict = peer_td in strict_set
            with self._fed_lock:
                since_v = self._peer_cursors.get(peer_td, 0)
            try:
                with httpx.Client(
                    verify=self._http_verify_kwarg(peer_url=peer_url, expected_domain=peer_td),
                    timeout=httpx.Timeout(connect=1.2, read=1.5, write=1.5, pool=1.5),
                ) as client:
                    resp = client.get(
                        f"{peer_url}/v1/federation/events",
                        params={"since_version": since_v},
                    )
                    resp.raise_for_status()
                    data = resp.json()
            except Exception as exc:
                if is_strict:
                    raise RevocationError(
                        f"Federated revocation peer {peer_td!r} ({peer_url}) unreachable during HIGH_RISK anchor: {exc}"
                    ) from exc
                continue

            if not isinstance(data, Mapping) or data.get("trust_domain") != peer_td:
                if is_strict:
                    raise RevocationError(
                        f"Federated revocation peer {peer_url} returned mismatched trust_domain "
                        f"{data.get('trust_domain') if isinstance(data, Mapping) else None!r} != {peer_td!r}"
                    )
                continue

            default_svid = str(data.get("service_svid") or "")
            if is_strict:
                try:
                    svid_claims = self.trust_resolver.verify_workload_svid(default_svid)
                    peer_sp = SpiffeId.parse(str(svid_claims["sub"]))
                    if (
                        peer_sp.trust_domain != peer_td
                        or peer_sp.path != "/ns/sys/sa/revocation"
                    ):
                        raise RevocationError(
                            f"Unauthorized federated revocation service SVID {peer_sp.uri!r}"
                        )
                except (IdentityError, RevocationError, KeyError) as exc:
                    raise RevocationError(
                        f"Federated revocation peer {peer_td!r} failed SVID verification: {exc}"
                    ) from exc

            max_seen = since_v
            for raw_item in data.get("events") or []:
                item_dict = dict(raw_item)
                item_dict.setdefault("service_svid", default_svid)
                try:
                    stored = self.ingest_federated_event(item_dict, expected_peer_domain=peer_td)
                    orig_v = (
                        stored.origin_version
                        if stored.origin_version is not None
                        else stored.version
                    )
                    if orig_v > max_seen:
                        max_seen = orig_v
                    imported += 1
                except Exception as exc:
                    if is_strict:
                        raise RevocationError(
                            f"Federated revocation event verification failed for {peer_td!r}: {exc}"
                        ) from exc
                    continue
            with self._fed_lock:
                if max_seen > self._peer_cursors.get(peer_td, 0):
                    self._peer_cursors[peer_td] = max_seen
        return imported

    def start_federation_sync(self, interval_sec: float = 0.4) -> None:
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
            target=_loop, name=f"rev-fed-{self.service_identity.trust_domain}", daemon=True
        )
        self._fed_thread.start()

    def stop_federation_sync(self) -> None:
        self._fed_stop.set()
        if self._fed_thread is not None:
            self._fed_thread.join(timeout=2.0)
            self._fed_thread = None

    def _notify_federation_peers(self) -> None:
        """Zero-trust wakeup signal prompting peer domain revocation nodes to pull `/v1/federation/events`."""
        if not self.peer_revocation_urls:
            return
        for peer_td, peer_url in list(self.peer_revocation_urls.items()):
            try:
                with httpx.Client(
                    verify=self._http_verify_kwarg(peer_url=peer_url, expected_domain=peer_td),
                    timeout=0.6,
                ) as client:
                    client.post(f"{peer_url}/v1/federation/notify", json={})
            except Exception:
                pass

    @property
    def base_url(self) -> str:
        return self._http.base_url

    @property
    def port(self) -> int:
        return self._http.port

    def _sign_event(self, core_claims: Dict[str, Any]) -> str:
        return jws_sign_compact(
            payload=core_claims,
            keypair=self.service_identity.keypair,
            typ="lct-revocation-event+jwt",
        )

    def revoke_prefix_direct(
        self,
        prefix: str,
        requested_by: str,
        reason: str = "manual",
        trust_domain: Optional[str] = None,
    ) -> RevocationEvent:
        ev = self.trie.revoke_prefix(
            prefix=prefix,
            requested_by=requested_by,
            reason=reason,
            signer_fn=self._sign_event,
            service_svid=self.service_identity.workload_svid,
            trust_domain=trust_domain,
        )
        if self._audit_hook:
            self._audit_hook(ev)
        return ev

    def quarantine_workload_direct(
        self, spiffe_id: str, requested_by: str, reason: str = "quarantine"
    ) -> RevocationEvent:
        ev = self.trie.quarantine_workload(
            spiffe_id=spiffe_id,
            requested_by=requested_by,
            reason=reason,
            signer_fn=self._sign_event,
            service_svid=self.service_identity.workload_svid,
        )
        if self._audit_hook:
            self._audit_hook(ev)
        return ev

    def _verify_caller_command(
        self, body: Dict[str, Any]
    ) -> Tuple[str, str, str, Dict[str, Any]]:
        """Authenticate revocation command signed by either a Workload SVID or Domain Root CA."""
        auth_mode = str(body.get("auth_mode", "workload"))
        command_jws = str(body.get("command_jws", ""))
        if not command_jws:
            raise RevocationError("Missing command_jws")

        if auth_mode == "domain_authority":
            trust_domain = str(body.get("trust_domain", ""))
            try:
                _, cmd = self.trust_resolver.verify_domain_jws(
                    command_jws,
                    expected_trust_domain=trust_domain,
                    expected_typ="lct-revoke-cmd+jwt",
                )
            except IdentityError as exc:
                raise RevocationError(
                    f"Domain authority verification failed: {exc}"
                ) from exc
            caller_id = f"spiffe://{trust_domain}/authority/root"
            caller_meta = trust_domain
        elif auth_mode == "workload":
            caller_svid = str(body.get("caller_svid", ""))
            try:
                svid_claims = self.trust_resolver.verify_workload_svid(caller_svid)
                caller_jwk = svid_claims["cnf"]["jwk"]
                caller_jkt = str(svid_claims["cnf"]["jkt"])
                _, cmd = jws_verify_compact(
                    command_jws, caller_jwk, expected_typ="lct-revoke-cmd+jwt"
                )
            except (IdentityError, CryptoError) as exc:
                raise RevocationError(f"Workload revocation auth failed: {exc}") from exc
            caller_id = str(svid_claims["sub"])
            caller_meta = caller_jkt
        else:
            raise RevocationError(f"Unsupported auth_mode: {auth_mode!r}")

        now_ts = time.time()
        try:
            iat = require_finite_timestamp(cmd.get("iat"), "iat")
        except CryptoError as exc:
            raise RevocationError(f"Invalid command timestamp: {exc}") from exc

        if abs(now_ts - iat) > 30.0:
            raise RevocationError("Stale or future timestamp in revocation command")

        cmd_jti = str(cmd.get("jti") or sha256_b64url(command_jws.encode("ascii")))
        if not self._cmd_replay_cache.check_and_record(cmd_jti, now=now_ts):
            raise RevocationError("Replayed revocation command rejected")

        return auth_mode, caller_id, caller_meta, cmd

    def _authorize_prefix_revocation(
        self,
        auth_mode: str,
        caller_id: str,
        caller_meta: str,
        norm_prefix: str,
        target_task_id: str,
        cmd: Dict[str, Any],
        body: Dict[str, Any],
    ) -> str:
        """Enforce lineage jurisdiction and return the authoritative `trust_domain` scope."""
        if auth_mode == "domain_authority":
            # Scoped strictly to `caller_meta` (`caller_td`); cannot affect other domains' tasks!
            return caller_meta

        caller_spiffe = SpiffeId.parse(caller_id)
        auth_tok_str = cmd.get("authority_token") or body.get("authority_token")

        if caller_id in self._authorized_admins and not auth_tok_str:
            return caller_spiffe.trust_domain

        if not auth_tok_str or not isinstance(auth_tok_str, str):
            raise RevocationError(
                f"Workload {caller_id!r} lacks authority_token proving lineage jurisdiction over {norm_prefix!r}"
            )

        try:
            parsed = decode_token(auth_tok_str)
        except TokenError as exc:
            raise RevocationError(f"Invalid authority_token: {exc}") from exc

        if not isinstance(parsed, LineageToken):
            raise RevocationError("authority_token must be a single-chain LineageToken")

        if parsed.task_id != target_task_id:
            raise RevocationError(
                f"authority_token task_id {parsed.task_id!r} != target task {target_task_id!r}"
            )

        try:
            verify_lineage_token_cryptography(parsed, self.trust_resolver)
        except TokenExpiredError:
            pass
        except TokenError as exc:
            raise RevocationError(
                f"authority_token cryptographic verification failed: {exc}"
            ) from exc

        caller_jkt = caller_meta
        root_td = parsed.root.issuer_trust_domain

        if caller_id in self._authorized_admins and caller_spiffe.trust_domain == root_td:
            return root_td

        # Case 1: Caller is the originating root sender of B_0 in the root trust domain
        if caller_jkt == parsed.root.sender_jkt and caller_spiffe.trust_domain == root_td:
            return root_td

        # Case 2: Caller is a verified ancestor or holder whose coordinate is a prefix of `norm_prefix`
        d_paths = lineage_token_delegator_paths(parsed)
        caller_coord = d_paths.get(caller_spiffe.uri)
        if caller_coord is not None and is_lineage_segment_prefix(
            caller_coord, norm_prefix
        ):
            return root_td

        raise RevocationError(
            f"Workload {caller_id!r} (at {caller_coord!r}) is not an upstream ancestor of {norm_prefix!r}"
        )

    def _authorize_workload_quarantine(
        self,
        auth_mode: str,
        caller_id: str,
        caller_meta: str,
        target_spiffe: SpiffeId,
        cmd: Dict[str, Any],
        body: Dict[str, Any],
    ) -> None:
        """Enforce strict cluster-wide quarantine policy (`[HIGH-R2-01]`).

        Global workload quarantine affects all tasks cluster-wide and is restricted to:
        1. Same-domain `TrustDomainCA` (`domain_authority`)
        2. Explicitly configured same-domain `authorized_admins`
        3. CA-attested Hop-0 Root Coordinator (`parsed.root.delegate_spiffe_id == caller_id`
           and `parsed.root.cnf_jkt == caller_jkt` in non-sandbox namespace)
        Downstream `hop >= 1` workloads can NEVER trigger global workload quarantine via
        unilateral offline `attenuate()`.
        """
        if auth_mode == "domain_authority":
            if caller_meta != target_spiffe.trust_domain:
                raise RevocationError(
                    f"Cross-domain CA {caller_meta!r} cannot quarantine {target_spiffe.uri!r}"
                )
            return

        caller_spiffe = SpiffeId.parse(caller_id)
        if caller_spiffe.trust_domain != target_spiffe.trust_domain:
            raise RevocationError(
                f"Cross-domain workload {caller_spiffe.uri!r} cannot globally quarantine {target_spiffe.uri!r}"
            )

        # Quarantined callers are immediately stripped of quarantine authority (`[MEDIUM-R3-01]`)
        if self.trie.check_workloads([caller_spiffe.uri]) is not None:
            raise RevocationError(
                f"Quarantined caller {caller_spiffe.uri!r} is forbidden from issuing quarantine commands"
            )

        if caller_spiffe.uri in self._authorized_admins:
            return

        if target_spiffe.path.startswith("/ns/sys/"):
            raise RevocationError(
                f"System infrastructure workload {target_spiffe.uri!r} may only be quarantined by TrustDomainCA or authorized_admins"
            )

        if caller_spiffe.path.startswith(("/ns/sandbox/", "/ns/untrusted/", "/ns/evil/")):
            raise RevocationError(
                f"Untrusted namespace workload {caller_spiffe.uri!r} forbidden from global quarantine"
            )

        auth_tok_str = cmd.get("authority_token") or body.get("authority_token")
        if not auth_tok_str or not isinstance(auth_tok_str, str):
            raise RevocationError(
                "Same-domain non-admin workload must present unexpired 1-hop authority_token"
            )

        try:
            parsed = decode_token(auth_tok_str)
            if not isinstance(parsed, LineageToken):
                raise RevocationError("authority_token must be a LineageToken")
            verify_lineage_token_cryptography(
                parsed, self.trust_resolver, now=time.time()
            )
        except TokenError as exc:
            raise RevocationError(f"Invalid or expired authority_token: {exc}") from exc

        caller_jkt = caller_meta
        if (
            parsed.root.issuer_trust_domain != target_spiffe.trust_domain
            or parsed.root.delegate_spiffe_id != caller_spiffe.uri
            or parsed.root.cnf_jkt != caller_jkt
            or parsed.root.max_depth < 1
            or caller_spiffe.uri == target_spiffe.uri
        ):
            raise RevocationError(
                f"Workload {caller_spiffe.uri!r} is not a CA-attested Hop-0 Root Coordinator; "
                "downstream hops (hop >= 1) may only revoke task prefixes, never global workloads"
            )

        if (
            len(parsed.hops) != 1
            or parsed.hops[0].issuer_spiffe_id != caller_spiffe.uri
            or parsed.hops[0].delegate_spiffe_id != target_spiffe.uri
        ):
            raise RevocationError(
                "Hop-0 Root Coordinator must present a 1-hop authority_token directly delegating to target_spiffe_id"
            )

        hop0_coord = f"/{parsed.root.task_id}/{parsed.root.hop_segment}"
        if (
            self.trie.check_lineage_path(
                hop0_coord, trust_domain=parsed.root.issuer_trust_domain
            )
            is not None
        ):
            raise RevocationError(
                f"Authority token Hop-0 lineage {hop0_coord!r} has already been revoked"
            )

    def _dispatch_federation(
        self, req: HTTPRequestContext
    ) -> Tuple[int, Any, Dict[str, str]]:
        """External mTLS 1.3 cross-cluster revocation port (`:8492`).

        Allows ONLY `/healthz`, `GET /v1/federation/events`, `POST /v1/federation/notify`,
        and authenticated cross-domain `POST /v1/revoke/prefix`; blocks external
        `/v1/revoke/workload` global quarantine and internal replica endpoints with `403`.
        """
        if req.method == "GET" and req.path == "/healthz":
            return (
                200,
                {
                    "status": "ok",
                    "service": "revocation-federation",
                    "trust_domain": self.service_identity.trust_domain,
                    "version": self.trie.version,
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

        if req.method == "GET" and req.path == "/v1/federation/events":
            return self._dispatch(req)
        if req.method == "POST" and req.path in ("/v1/federation/notify", "/v1/revoke/prefix"):
            return self._dispatch(req)
        return (
            403,
            {
                "error": "federation_port_restricted",
                "detail": f"Route {req.method} {req.path} is forbidden on external federation revocation port",
            },
            {},
        )

    def _dispatch(
        self, req: HTTPRequestContext
    ) -> Tuple[int, Any, Dict[str, str]]:
        if req.method == "GET" and req.path == "/healthz":
            return (
                200,
                {
                    "status": "ok",
                    "service": "revocation-service",
                    "version": self.trie.version,
                    "service_spiffe_id": self.service_identity.spiffe_id,
                },
                {},
            )

        if req.method == "GET" and req.path == "/v1/service-info":
            return (
                200,
                {
                    "service_spiffe_id": self.service_identity.spiffe_id,
                    "service_svid": self.service_identity.workload_svid,
                    "public_jwk": self.service_identity.public_jwk(),
                    "version": self.trie.version,
                },
                {},
            )

        if req.method == "POST" and req.path == "/v1/revoke/prefix":
            body = req.json()
            try:
                auth_mode, caller_id, caller_meta, cmd = self._verify_caller_command(body)
                prefix = str(cmd["prefix"])
                segments = parse_revocation_prefix(prefix)
                norm_prefix = "/" + "/".join(segments)
                resolved_td = self._authorize_prefix_revocation(
                    auth_mode=auth_mode,
                    caller_id=caller_id,
                    caller_meta=caller_meta,
                    norm_prefix=norm_prefix,
                    target_task_id=segments[0],
                    cmd=cmd,
                    body=body,
                )
                reason = str(cmd.get("reason", "prefix_revoked"))
                if (
                    self.strict_domain_isolation
                    and resolved_td != self.service_identity.trust_domain
                ):
                    peer_url = self.peer_revocation_urls.get(resolved_td)
                    if not peer_url:
                        raise RevocationError(
                            f"Local revocation service ({self.service_identity.trust_domain}) "
                            f"cannot sign revocations for foreign domain {resolved_td!r}"
                        )
                    # Route signed caller command to the authoritative home domain RevocationService
                    with httpx.Client(
                        verify=self._http_verify_kwarg(
                            peer_url=peer_url, expected_domain=resolved_td
                        ),
                        timeout=3.0,
                    ) as client:
                        fwd_r = client.post(f"{peer_url}/v1/revoke/prefix", json=body)
                    if fwd_r.status_code != 200:
                        raise RevocationError(
                            f"Authoritative peer {resolved_td} rejected revocation: {fwd_r.text}"
                        )
                    fwd_json = fwd_r.json()
                    ev_dict = dict(fwd_json["event"])
                    ev_dict.setdefault("service_svid", str(fwd_json.get("service_svid", "")))
                    ev = self.ingest_federated_event(
                        ev_dict, expected_peer_domain=resolved_td
                    )
                    return (
                        200,
                        {
                            "revoked": True,
                            "event": ev.to_dict(),
                            "service_svid": ev.service_svid,
                        },
                        {},
                    )

                ev = self.revoke_prefix_direct(
                    prefix=norm_prefix,
                    requested_by=caller_id,
                    reason=reason,
                    trust_domain=resolved_td,
                )
            except (RevocationError, KeyError, ValueError, IdentityError) as exc:
                return 403, {"error": "revocation_rejected", "detail": str(exc)}, {}

            self._notify_federation_peers()
            return (
                200,
                {
                    "revoked": True,
                    "event": ev.to_dict(),
                    "service_svid": self.service_identity.workload_svid,
                },
                {},
            )

        if req.method == "POST" and req.path == "/v1/revoke/workload":
            body = req.json()
            try:
                auth_mode, caller_id, caller_meta, cmd = self._verify_caller_command(body)
                target_spiffe = SpiffeId.parse(str(cmd["target_spiffe_id"]))
                if (
                    self.strict_domain_isolation
                    and target_spiffe.trust_domain != self.service_identity.trust_domain
                ):
                    raise RevocationError(
                        f"Local revocation service ({self.service_identity.trust_domain}) "
                        f"cannot quarantine foreign workload {target_spiffe.uri!r}"
                    )
                self._authorize_workload_quarantine(
                    auth_mode=auth_mode,
                    caller_id=caller_id,
                    caller_meta=caller_meta,
                    target_spiffe=target_spiffe,
                    cmd=cmd,
                    body=body,
                )
                reason = str(cmd.get("reason", "workload_quarantine"))
                ev = self.quarantine_workload_direct(
                    spiffe_id=target_spiffe.uri, requested_by=caller_id, reason=reason
                )
            except (RevocationError, KeyError, ValueError, IdentityError) as exc:
                return 403, {"error": "quarantine_rejected", "detail": str(exc)}, {}

            self._notify_federation_peers()
            return (
                200,
                {
                    "quarantined": True,
                    "event": ev.to_dict(),
                    "service_svid": self.service_identity.workload_svid,
                },
                {},
            )

        if req.method == "POST" and req.path == "/v1/federation/notify":
            imported = self.sync_from_federation_peers()
            return 200, {"synced": True, "imported": imported}, {}

        if req.method == "GET" and req.path == "/v1/federation/events":
            since_ver = int(req.query.get("since_version", 0))
            local_events = self.trie.local_domain_events_since(
                trust_domain=self.service_identity.trust_domain,
                since_origin_version=since_ver,
            )
            return (
                200,
                {
                    "trust_domain": self.service_identity.trust_domain,
                    "service_svid": self.service_identity.workload_svid,
                    "events": [e.to_dict() for e in local_events],
                },
                {},
            )

        if req.method == "GET" and req.path == "/v1/events":
            since_ver_raw = req.query.get("since_version", 0)
            if isinstance(since_ver_raw, list):
                since_ver_raw = since_ver_raw[0]
            wait_ms_raw = req.query.get("wait_ms", 0)
            if isinstance(wait_ms_raw, list):
                wait_ms_raw = wait_ms_raw[0]
            since_ver = int(since_ver_raw)
            wait_ms = int(wait_ms_raw)

            req_td_param = req.query.get("require_trust_domain", "")
            if isinstance(req_td_param, list):
                req_tds = [
                    x.strip().lower()
                    for part in req_td_param
                    for x in str(part).split(",")
                    if x.strip()
                ]
            elif req_td_param:
                req_tds = [x.strip().lower() for x in str(req_td_param).split(",") if x.strip()]
            else:
                req_tds = []

            strict_param = req.query.get("strict", "")
            if isinstance(strict_param, list):
                strict_param = strict_param[0]
            strict_all = str(strict_param).strip().lower() in ("1", "true", "yes")

            if wait_ms == 0 and (self.peer_revocation_urls or req_tds):
                strict_domains: Set[str] = set(req_tds)
                if strict_all:
                    strict_domains.update(self.peer_revocation_urls.keys())
                try:
                    self.sync_from_federation_peers(
                        strict_required_domains=strict_domains
                    )
                except RevocationError as exc:
                    return (
                        503,
                        {
                            "error": "federation_anchor_unavailable",
                            "detail": str(exc),
                        },
                        {},
                    )
            cur_ver, events = self.trie.events_since(
                since_version=since_ver, wait_ms=wait_ms
            )
            return (
                200,
                {
                    "version": cur_ver,
                    "service_svid": self.service_identity.workload_svid,
                    "events": [e.to_dict() for e in events],
                },
                {},
            )

        return 404, {"error": "route_not_found", "path": req.path}, {}


class RevocationReplicaClient:
    """Edge replica maintaining a synchronized local `LineagePrefixTrie`."""

    def __init__(
        self,
        revocation_url: str,
        trust_resolver: TrustBundleResolver,
        local_trie: Optional[LineagePrefixTrie] = None,
        timeout: float = 3.0,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        self.revocation_url = revocation_url.rstrip("/")
        self.trust_resolver = trust_resolver
        self.trie = local_trie if local_trie is not None else LineagePrefixTrie()
        self.timeout = timeout
        self.ssl_context = ssl_context
        self._sync_lock = threading.Lock()
        self._bg_stop = threading.Event()
        self._bg_thread: Optional[threading.Thread] = None
        self.last_service_svid: str = ""

    def _verify_kwarg(self) -> Any:
        return self.ssl_context if self.ssl_context is not None else True

    def _verify_and_apply_events(
        self, service_svid: str, raw_events: Iterable[Dict[str, Any]]
    ) -> int:
        events_list = list(raw_events)
        if not events_list:
            if service_svid:
                self.last_service_svid = service_svid
            return self.trie.version

        verified_jwk_cache: Dict[str, Tuple[str, Dict[str, Any]]] = {}

        def _resolve_signer(svid_tok: str) -> Tuple[str, Dict[str, Any]]:
            cached = verified_jwk_cache.get(svid_tok)
            if cached is not None:
                return cached
            try:
                claims = self.trust_resolver.verify_workload_svid(svid_tok)
            except IdentityError as exc:
                raise RevocationError(
                    f"Revocation service SVID verification failed: {exc}"
                ) from exc
            sp = SpiffeId.parse(str(claims["sub"]))
            res = (sp.trust_domain, claims["cnf"]["jwk"])
            verified_jwk_cache[svid_tok] = res
            return res

        if service_svid:
            _resolve_signer(service_svid)
            self.last_service_svid = service_svid

        for raw_ev in events_list:
            ev_dict = dict(raw_ev)
            ev_svid = str(ev_dict.get("service_svid") or service_svid)
            ev_dict["service_svid"] = ev_svid
            ev = RevocationEvent.from_dict(ev_dict)
            if not ev.service_signature or not ev_svid:
                raise RevocationError("RevocationEvent missing service_signature or SVID")
            signer_td, svc_jwk = _resolve_signer(ev_svid)
            if ev.origin_version is not None and ev.trust_domain != signer_td:
                raise RevocationError(
                    f"Federated RevocationEvent signer domain {signer_td!r} != {ev.trust_domain!r}"
                )
            try:
                _, signed_claims = jws_verify_compact(
                    ev.service_signature,
                    svc_jwk,
                    expected_typ="lct-revocation-event+jwt",
                )
            except CryptoError as exc:
                raise RevocationError(
                    f"RevocationEvent signature invalid at v{ev.version}: {exc}"
                ) from exc
            if signed_claims != ev.core_claims():
                raise RevocationError("RevocationEvent payload tampered in transit")
            self.trie.apply_replicated_event(ev)

        return self.trie.version

    def sync_now(
        self,
        wait_ms: int = 0,
        required_trust_domains: Optional[Iterable[str]] = None,
    ) -> int:
        """Synchronously pull and verify all new revocation events since local version."""
        since = self.trie.version
        params: Dict[str, Any] = {"since_version": since, "wait_ms": wait_ms}
        if required_trust_domains:
            norm_req = sorted(
                {str(d).strip().lower() for d in required_trust_domains if str(d).strip()}
            )
            if norm_req:
                params["require_trust_domain"] = ",".join(norm_req)
        try:
            with httpx.Client(
                verify=self._verify_kwarg(),
                timeout=max(self.timeout, (wait_ms / 1000.0) + 4.5),
            ) as client:
                resp = client.get(
                    f"{self.revocation_url}/v1/events",
                    params=params,
                )
                resp.raise_for_status()
                body = resp.json()
        except Exception as exc:
            raise RevocationError(
                f"Failed to sync with RevocationService at {self.revocation_url}: {exc}"
            ) from exc

        with self._sync_lock:
            return self._verify_and_apply_events(
                service_svid=str(body.get("service_svid", "")),
                raw_events=body.get("events", []),
            )

    def start_background_sync(self, wait_ms: int = 500) -> None:
        if self._bg_thread is not None and self._bg_thread.is_alive():
            return
        self._bg_stop.clear()

        def _loop() -> None:
            while not self._bg_stop.is_set():
                try:
                    self.sync_now(wait_ms=wait_ms)
                except Exception:
                    self._bg_stop.wait(0.2)

        self._bg_thread = threading.Thread(
            target=_loop, name="revocation-replica-sync", daemon=True
        )
        self._bg_thread.start()

    def stop_background_sync(self) -> None:
        self._bg_stop.set()
        if self._bg_thread is not None:
            self._bg_thread.join(timeout=2.0)
            self._bg_thread = None

    def revoke_prefix(
        self,
        caller: WorkloadIdentity | TrustDomainCA,
        prefix: str,
        reason: str = "subtree_prune",
        authority_token: Optional[str] = None,
    ) -> RevocationEvent:
        """Issue an authenticated & jurisdiction-authorized prefix revocation."""
        cmd_payload: Dict[str, Any] = {
            "jti": f"revcmd-{uuid.uuid4().hex}",
            "prefix": prefix,
            "reason": reason,
            "iat": time.time(),
        }
        if authority_token:
            cmd_payload["authority_token"] = authority_token

        if isinstance(caller, TrustDomainCA):
            cmd_jws = jws_sign_compact(
                payload=cmd_payload,
                keypair=caller.active_keypair,
                typ="lct-revoke-cmd+jwt",
            )
            req_body: Dict[str, Any] = {
                "auth_mode": "domain_authority",
                "trust_domain": caller.trust_domain,
                "command_jws": cmd_jws,
            }
        else:
            cmd_jws = jws_sign_compact(
                payload=cmd_payload,
                keypair=caller.keypair,
                typ="lct-revoke-cmd+jwt",
            )
            req_body = {
                "auth_mode": "workload",
                "caller_svid": caller.workload_svid,
                "command_jws": cmd_jws,
            }

        with httpx.Client(verify=self._verify_kwarg(), timeout=self.timeout) as client:
            resp = client.post(
                f"{self.revocation_url}/v1/revoke/prefix",
                json=req_body,
            )
        if resp.status_code != 200:
            raise RevocationError(
                f"Prefix revocation rejected ({resp.status_code}): {resp.text}"
            )
        self.sync_now()
        resp_json = resp.json()
        ev_raw = dict(resp_json["event"])
        ev_raw.setdefault("service_svid", str(resp_json.get("service_svid", "")))
        return RevocationEvent.from_dict(ev_raw)

    def quarantine_workload(
        self,
        caller: WorkloadIdentity | TrustDomainCA,
        target_spiffe_id: str,
        reason: str = "policy_fault",
        authority_token: Optional[str] = None,
    ) -> RevocationEvent:
        """Issue an authenticated & Hop-0-or-CA-authorized workload quarantine."""
        cmd_payload: Dict[str, Any] = {
            "jti": f"qwlcmd-{uuid.uuid4().hex}",
            "target_spiffe_id": target_spiffe_id,
            "reason": reason,
            "iat": time.time(),
        }
        if authority_token:
            cmd_payload["authority_token"] = authority_token

        if isinstance(caller, TrustDomainCA):
            cmd_jws = jws_sign_compact(
                payload=cmd_payload,
                keypair=caller.active_keypair,
                typ="lct-revoke-cmd+jwt",
            )
            req_body: Dict[str, Any] = {
                "auth_mode": "domain_authority",
                "trust_domain": caller.trust_domain,
                "command_jws": cmd_jws,
            }
        else:
            cmd_jws = jws_sign_compact(
                payload=cmd_payload,
                keypair=caller.keypair,
                typ="lct-revoke-cmd+jwt",
            )
            req_body = {
                "auth_mode": "workload",
                "caller_svid": caller.workload_svid,
                "command_jws": cmd_jws,
            }

        with httpx.Client(verify=self._verify_kwarg(), timeout=self.timeout) as client:
            resp = client.post(
                f"{self.revocation_url}/v1/revoke/workload",
                json=req_body,
            )
        if resp.status_code != 200:
            raise RevocationError(
                f"Workload quarantine rejected ({resp.status_code}): {resp.text}"
            )
        self.sync_now()
        resp_json = resp.json()
        ev_raw = dict(resp_json["event"])
        ev_raw.setdefault("service_svid", str(resp_json.get("service_svid", "")))
        return RevocationEvent.from_dict(ev_raw)
