"""RFC 8693 / RFC 7662 / RFC 7009 / OIDC Compliant Security Token Service (`OAuthSTSService`).

Implements the exact `/realms/<realm>/protocol/openid-connect/*` HTTP wire contract used by
Keycloak 26.5.2 with real 2048-bit `RS256` asymmetric cryptography:
1. `GET  /realms/<realm>/.well-known/openid-configuration`
2. `GET  /realms/<realm>/protocol/openid-connect/certs` (public RS256 JWKS)
3. `POST /realms/<realm>/protocol/openid-connect/token`:
   - `grant_type=password` (Hop-0 human user login issuing RS256 `access_token` + `id_token`)
   - `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693 Section 2):
     - Authenticates workload callers via SPIFFE `JWT-SVID` client assertion OR confidential
       `client_id` + `client_secret` (HTTP Basic or form-encoded);
     - Verifies `subject_token` against local RS256 JWKS (`oauth_centralized`) OR federated
       peer organization STS JWKS (`oauth_federated` cross-domain relay);
     - Enforces flat OAuth scope subsetting (`requested_scope <= subject_scope`);
     - Pushes caller identity onto nested RFC 8693 Section 4.1 `act` claim (`{"sub": ..., "act": ...}`);
4. `POST /realms/<realm>/protocol/openid-connect/introspect` (RFC 7662)
5. `POST /realms/<realm>/protocol/openid-connect/revoke` (RFC 7009 single-JTI revocation)
6. `GET  /v1/sts/exchange-logs` (bounded, secret-redacted STS audit records for empirical comparison).
"""

from __future__ import annotations

import base64
from collections import OrderedDict, deque
import hmac
import threading
import time
from typing import Any, Callable, Deque, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import parse_qs, unquote
import uuid

import httpx

from lineage.common.crypto import (
    CryptoError,
    KeyPair,
    jws_parse_unverified,
    jws_sign_compact,
    jws_verify_compact,
    require_finite_timestamp,
    sha256_hex,
)
from lineage.common.http_utils import HTTPRequestContext, ManagedHTTPService
from lineage.identity.spiffe import IdentityError
from lineage.identity.trust_bundle import TrustBundleResolver
from lineage.oauth_sts.keycloak_realm import (
    DEFAULT_FLAT_OAUTH_SCOPES,
    DEFAULT_REALM_NAME,
    STANDARD_OAUTH_CLIENT_IDS,
    spiffe_id_to_oauth_client_id,
)

GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token"
TOKEN_TYPE_ID = "urn:ietf:params:oauth:token-type:id_token"
CLIENT_ASSERTION_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
CLIENT_ASSERTION_JWT_SPIFFE = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"
MAX_STS_EXCHANGE_LOGS = 2000
MAX_REVOKED_JTIS = 8192
MAX_PEER_JWKS = 128


class OAuthSTSError(Exception):
    """Raised when an OAuth 2.0 / OIDC / RFC 8693 STS operation fails."""


def _parse_form_body(raw_body: bytes) -> Dict[str, str]:
    if not raw_body:
        return {}
    text = raw_body.decode("utf-8", errors="strict")
    parsed = parse_qs(text, keep_blank_values=True)
    return {k: (v[0] if v else "") for k, v in parsed.items()}


def _extract_basic_client_creds(auth_header: Optional[str]) -> Optional[Tuple[str, str]]:
    if not auth_header or not isinstance(auth_header, str):
        return None
    parts = auth_header.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "basic":
        return None
    try:
        decoded = base64.b64decode(parts[1].strip()).decode("utf-8")
    except Exception:
        return None
    if ":" not in decoded:
        return None
    cid, csec = decoded.split(":", 1)
    return unquote(cid), unquote(csec)


class OAuthSTSService:
    """Real RS256 OIDC & RFC 8693 Token Exchange STS (Keycloak wire-compatible)."""

    def __init__(
        self,
        trust_domain: str = "org-alpha.io",
        realm: str = DEFAULT_REALM_NAME,
        user_passwords: Optional[Mapping[str, str]] = None,
        client_secrets: Optional[Mapping[str, str]] = None,
        spiffe_trust_resolver: Optional[TrustBundleResolver] = None,
        peer_sts_jwks_Urls_provider: Optional[Callable[[], List[str]]] = None,
        issuer_override: Optional[str] = None,
        token_ttl_seconds: float = 900.0,
        host: str = "127.0.0.1",
        port: int = 0,
        rsa_keypair: Optional[KeyPair] = None,
    ) -> None:
        self.trust_domain = trust_domain.strip().lower()
        self.realm = realm.strip() or DEFAULT_REALM_NAME
        self.keypair = rsa_keypair or KeyPair.generate("RS256")
        self.token_ttl_seconds = max(5.0, float(token_ttl_seconds))
        self._issuer_override = issuer_override.rstrip("/") if issuer_override else None
        self._user_passwords: Dict[str, str] = dict(user_passwords or {})
        self._client_secrets: Dict[str, str] = dict(client_secrets or {})
        self.spiffe_trust_resolver = spiffe_trust_resolver
        self._peer_sts_jwks_urls_provider = peer_sts_jwks_Urls_provider

        self._lock = threading.RLock()
        self._revoked_jtis: "OrderedDict[str, float]" = OrderedDict()
        self._issued_tokens_meta: Dict[str, Dict[str, Any]] = {}
        self._peer_jwks_cache: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._peer_jwks_last_fetch: float = 0.0
        self._exchange_logs: Deque[Dict[str, Any]] = deque(maxlen=MAX_STS_EXCHANGE_LOGS)

        self.http = ManagedHTTPService(
            service_name=f"oauth-sts-{self.trust_domain}",
            dispatcher=self._dispatch,
            host=host,
            port=port,
        )

    def start(self) -> str:
        return self.http.start()

    def stop(self) -> None:
        self.http.stop()

    @property
    def base_url(self) -> str:
        return self.http.base_url

    def realm_issuer(self, req: Optional[HTTPRequestContext] = None) -> str:
        if self._issuer_override:
            return f"{self._issuer_override}/realms/{self.realm}"
        if req is not None:
            host_hdr = req.header("Host")
            if host_hdr:
                scheme = "https" if req.tls_version else "http"
                return f"{scheme}://{host_hdr}/realms/{self.realm}"
        return f"{self.http.base_url}/realms/{self.realm}"

    def register_peer_jwk(self, jwk: Mapping[str, Any]) -> None:
        kid = str(jwk.get("kid") or "")
        if kid and len(kid) <= 128:
            with self._lock:
                self._peer_jwks_cache[kid] = dict(jwk)
                self._peer_jwks_cache.move_to_end(kid)
                while len(self._peer_jwks_cache) > MAX_PEER_JWKS:
                    self._peer_jwks_cache.popitem(last=False)

    def _refresh_federated_peer_jwks(self, force: bool = False) -> None:
        if self._peer_sts_jwks_urls_provider is None:
            return
        now_ts = time.time()
        with self._lock:
            if not force and (now_ts - self._peer_jwks_last_fetch) < 10.0 and self._peer_jwks_cache:
                return
        urls = list(self._peer_sts_jwks_urls_provider() or [])[:32]
        fetched: Dict[str, Dict[str, Any]] = {}
        for u in urls:
            try:
                resp = httpx.get(u, timeout=2.5, follow_redirects=False, trust_env=False)
                if resp.status_code == 200:
                    for k in (resp.json().get("keys") or [])[:32]:
                        if isinstance(k, Mapping) and k.get("kid"):
                            kid_s = str(k["kid"])
                            if len(kid_s) <= 128:
                                fetched[kid_s] = dict(k)
            except Exception:
                continue
        with self._lock:
            for k_id, k_doc in fetched.items():
                self._peer_jwks_cache[k_id] = k_doc
                self._peer_jwks_cache.move_to_end(k_id)
            while len(self._peer_jwks_cache) > MAX_PEER_JWKS:
                self._peer_jwks_cache.popitem(last=False)
            self._peer_jwks_last_fetch = now_ts

    def export_jwks(self) -> Dict[str, Any]:
        jwk = self.keypair.public_jwk()
        jwk["use"] = "sig"
        return {"keys": [jwk]}

    def _authenticate_client(
        self, req: HTTPRequestContext, form: Mapping[str, str]
    ) -> Tuple[str, str]:
        """Authenticate calling OAuth client; returns `(client_id, actor_identifier)`."""
        assertion_type = form.get("client_assertion_type", "").strip()
        assertion = form.get("client_assertion", "").strip()
        if assertion and assertion_type in (
            CLIENT_ASSERTION_JWT_BEARER,
            CLIENT_ASSERTION_JWT_SPIFFE,
        ):
            if self.spiffe_trust_resolver is None:
                raise OAuthSTSError("spiffe_assertion_verifier_not_configured")
            try:
                claims = self.spiffe_trust_resolver.verify_workload_svid(assertion)
            except IdentityError as exc:
                raise OAuthSTSError(f"invalid_spiffe_client_assertion: {exc}") from exc
            spiffe_sub = str(claims["sub"])
            cid = form.get("client_id", "").strip() or spiffe_id_to_oauth_client_id(spiffe_sub)
            return cid, spiffe_sub

        basic = _extract_basic_client_creds(req.header("Authorization"))
        if basic is not None:
            cid, csec = basic
        else:
            cid = form.get("client_id", "").strip()
            csec = form.get("client_secret", "").strip()

        if not cid or not csec:
            raise OAuthSTSError("missing_client_credentials")
        expected = self._client_secrets.get(cid)
        if not expected or not hmac.compare_digest(
            csec.encode("utf-8"), expected.encode("utf-8")
        ):
            raise OAuthSTSError(f"invalid_client_credentials:{cid}")
        return cid, cid

    def _verify_subject_jwt(self, raw_jwt: str, allow_federated: bool = True) -> Dict[str, Any]:
        hdr, _, _, _ = jws_parse_unverified(raw_jwt)
        kid = str(hdr.get("kid") or "")
        own_jwk = self.keypair.public_jwk()
        candidate_jwk: Optional[Dict[str, Any]] = None
        if kid == own_jwk["kid"]:
            candidate_jwk = own_jwk
        elif allow_federated:
            with self._lock:
                candidate_jwk = self._peer_jwks_cache.get(kid)
            if candidate_jwk is None:
                self._refresh_federated_peer_jwks(force=True)
                with self._lock:
                    candidate_jwk = self._peer_jwks_cache.get(kid)
        if candidate_jwk is None:
            raise OAuthSTSError(f"unknown_signing_kid:{kid}")

        try:
            _, claims = jws_verify_compact(raw_jwt, candidate_jwk, expected_typ=None)
        except CryptoError as exc:
            raise OAuthSTSError(f"invalid_subject_token_signature:{exc}") from exc

        now_ts = time.time()
        exp = require_finite_timestamp(claims.get("exp"), "exp")
        if exp <= now_ts:
            raise OAuthSTSError("subject_token_expired")
        if "iat" in claims and claims.get("iat") is not None:
            iat = require_finite_timestamp(claims.get("iat"), "iat")
            if iat > now_ts + 30.0:
                raise OAuthSTSError("subject_token_iat_in_future")
        jti = str(claims.get("jti") or "")
        with self._lock:
            if jti and jti in self._revoked_jtis:
                raise OAuthSTSError("subject_token_revoked")
        return claims

    def _mint_jwt(
        self,
        *,
        issuer: str,
        sub: str,
        preferred_username: str,
        aud: Any,
        azp: str,
        scope: str,
        act: Optional[Dict[str, Any]] = None,
        typ: str = "JWT",
    ) -> Tuple[str, Dict[str, Any]]:
        now_ts = int(time.time())
        exp_ts = now_ts + int(self.token_ttl_seconds)
        jti = str(uuid.uuid4())
        claims: Dict[str, Any] = {
            "jti": jti,
            "iss": issuer,
            "sub": sub,
            "preferred_username": preferred_username,
            "aud": aud,
            "azp": azp,
            "iat": now_ts,
            "exp": exp_ts,
            "scope": scope,
        }
        if act is not None:
            claims["act"] = act
        jwt_str = jws_sign_compact(claims, self.keypair, typ=typ)
        with self._lock:
            if len(self._issued_tokens_meta) >= 4096:
                oldest_k = next(iter(self._issued_tokens_meta))
                self._issued_tokens_meta.pop(oldest_k, None)
            self._issued_tokens_meta[jti] = {
                "sub": sub,
                "preferred_username": preferred_username,
                "aud": aud,
                "azp": azp,
                "scope": scope,
                "exp": exp_ts,
                "act": act,
            }
        return jwt_str, claims

    def _dispatch(
        self, req: HTTPRequestContext
    ) -> Tuple[int, Any, Dict[str, str]]:
        path = req.path.rstrip("/") or "/"
        realm_prefix = f"/realms/{self.realm}"

        if req.method == "GET" and path in ("/healthz", "/health/ready"):
            return (
                200,
                {
                    "status": "UP",
                    "service": "lct-oauth-sts",
                    "trust_domain": self.trust_domain,
                    "realm": self.realm,
                },
                {},
            )

        if req.method == "GET" and path == "/v1/sts/exchange-logs":
            with self._lock:
                logs_copy = list(self._exchange_logs)
            return (
                200,
                {
                    "trust_domain": self.trust_domain,
                    "realm": self.realm,
                    "exchange_count": len(logs_copy),
                    "logs": logs_copy,
                },
                {},
            )

        if req.method == "GET" and path == f"{realm_prefix}/.well-known/openid-configuration":
            iss = self.realm_issuer(req)
            return (
                200,
                {
                    "issuer": iss,
                    "token_endpoint": f"{iss}/protocol/openid-connect/token",
                    "jwks_uri": f"{iss}/protocol/openid-connect/certs",
                    "introspection_endpoint": f"{iss}/protocol/openid-connect/token/introspect",
                    "revocation_endpoint": f"{iss}/protocol/openid-connect/revoke",
                    "grant_types_supported": [
                        "password",
                        "client_credentials",
                        GRANT_TOKEN_EXCHANGE,
                    ],
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "token_endpoint_auth_methods_supported": [
                        "client_secret_basic",
                        "client_secret_post",
                        "private_key_jwt",
                    ],
                },
                {},
            )

        if req.method == "GET" and path == f"{realm_prefix}/protocol/openid-connect/certs":
            return 200, self.export_jwks(), {}

        if req.method == "POST" and path == f"{realm_prefix}/protocol/openid-connect/token":
            try:
                form = _parse_form_body(req.body)
                client_id, actor_id = self._authenticate_client(req, form)
            except Exception as exc:
                return (
                    401,
                    {"error": "invalid_client", "error_description": str(exc)},
                    {},
                )

            grant_type = form.get("grant_type", "").strip()
            iss = self.realm_issuer(req)

            if grant_type == "password":
                username = form.get("username", "").strip()
                password = form.get("password", "")
                expected_pw = self._user_passwords.get(username)
                if not username or not expected_pw or not hmac.compare_digest(
                    password.encode("utf-8"), expected_pw.encode("utf-8")
                ):
                    return (
                        401,
                        {
                            "error": "invalid_grant",
                            "error_description": "Invalid user credentials",
                        },
                        {},
                    )
                req_scope_raw = form.get("scope", "").strip()
                default_scopes = ["openid", "profile", "email", *DEFAULT_FLAT_OAUTH_SCOPES]
                if req_scope_raw:
                    req_parts = [s for s in req_scope_raw.split() if s]
                    eff_scopes = list(dict.fromkeys([*req_parts, *DEFAULT_FLAT_OAUTH_SCOPES]))
                else:
                    eff_scopes = default_scopes
                scope_str = " ".join(eff_scopes)
                aud_list = [cid for cid in STANDARD_OAUTH_CLIENT_IDS if cid != client_id]
                acc_jwt, acc_claims = self._mint_jwt(
                    issuer=iss,
                    sub=username,
                    preferred_username=username,
                    aud=aud_list or client_id,
                    azp=client_id,
                    scope=scope_str,
                )
                id_jwt, _ = self._mint_jwt(
                    issuer=iss,
                    sub=username,
                    preferred_username=username,
                    aud=client_id,
                    azp=client_id,
                    scope="openid profile email",
                )
                return (
                    200,
                    {
                        "access_token": acc_jwt,
                        "id_token": id_jwt,
                        "token_type": "Bearer",
                        "expires_in": int(self.token_ttl_seconds),
                        "scope": scope_str,
                        "jti": acc_claims["jti"],
                    },
                    {},
                )

            if grant_type == GRANT_TOKEN_EXCHANGE:
                subj_tok = form.get("subject_token", "").strip()
                if not subj_tok:
                    return (
                        400,
                        {"error": "invalid_request", "error_description": "Missing subject_token"},
                        {},
                    )
                subj_type = form.get("subject_token_type", TOKEN_TYPE_ACCESS).strip()
                if subj_type not in ("", TOKEN_TYPE_ACCESS, TOKEN_TYPE_ID):
                    return (
                        400,
                        {
                            "error": "invalid_request",
                            "error_description": f"Unsupported subject_token_type {subj_type!r}",
                        },
                        {},
                    )
                req_tok_type = form.get("requested_token_type", TOKEN_TYPE_ACCESS).strip()
                if req_tok_type not in ("", TOKEN_TYPE_ACCESS):
                    return (
                        400,
                        {
                            "error": "invalid_request",
                            "error_description": f"Unsupported requested_token_type {req_tok_type!r}",
                        },
                        {},
                    )
                try:
                    subj_claims = self._verify_subject_jwt(subj_tok, allow_federated=True)
                except OAuthSTSError as exc:
                    return (
                        400,
                        {"error": "invalid_grant", "error_description": str(exc)},
                        {},
                    )

                # Optional RFC 8693 `actor_token`
                actor_tok = form.get("actor_token", "").strip()
                explicit_actor_sub: Optional[str] = None
                if actor_tok:
                    try:
                        if self.spiffe_trust_resolver is not None:
                            act_svid = self.spiffe_trust_resolver.verify_workload_svid(actor_tok)
                            explicit_actor_sub = str(act_svid["sub"])
                        else:
                            act_c = self._verify_subject_jwt(actor_tok, allow_federated=True)
                            explicit_actor_sub = str(act_c.get("sub") or client_id)
                    except Exception as exc:
                        return (
                            400,
                            {"error": "invalid_grant", "error_description": f"Invalid actor_token: {exc}"},
                            {},
                        )

                # Flat OAuth scope subset check (RFC 8693 cannot express parameter bounds!)
                parent_scopes = set(str(subj_claims.get("scope") or "").split())
                req_scope_str = form.get("scope", "").strip()
                if req_scope_str:
                    wanted_scopes = [s for s in req_scope_str.split() if s]
                    if not set(wanted_scopes).issubset(parent_scopes):
                        return (
                            400,
                            {
                                "error": "invalid_scope",
                                "error_description": f"Requested scope {wanted_scopes} exceeds parent scope {sorted(parent_scopes)}",
                            },
                            {},
                        )
                    out_scope = " ".join(wanted_scopes)
                else:
                    out_scope = " ".join(s for s in str(subj_claims.get("scope") or "").split() if s)

                target_aud = form.get("audience", "").strip() or form.get("resource", "").strip() or client_id
                eff_actor = explicit_actor_sub or actor_id
                prev_act = subj_claims.get("act")
                new_act: Dict[str, Any] = {"sub": eff_actor}
                if isinstance(prev_act, Mapping) and prev_act.get("sub"):
                    new_act["act"] = dict(prev_act)

                sub_val = str(subj_claims.get("sub") or "")
                pref_user = str(subj_claims.get("preferred_username") or sub_val)
                ex_jwt, ex_claims = self._mint_jwt(
                    issuer=iss,
                    sub=sub_val,
                    preferred_username=pref_user,
                    aud=target_aud,
                    azp=client_id,
                    scope=out_scope,
                    act=new_act,
                )
                with self._lock:
                    self._exchange_logs.append(
                        {
                            "timestamp": round(time.time(), 4),
                            "sts_domain": self.trust_domain,
                            "client_id": client_id,
                            "actor": eff_actor,
                            "sub": pref_user,
                            "upstream_issuer": subj_claims.get("iss"),
                            "audience": target_aud,
                            "scope": out_scope,
                            "subject_jti_sha256": sha256_hex(subj_tok.encode("ascii"))[:16],
                            "issued_jti": ex_claims["jti"],
                            "has_task_correlation_id": False,
                            "has_parent_block_hash": False,
                        }
                    )
                return (
                    200,
                    {
                        "access_token": ex_jwt,
                        "issued_token_type": TOKEN_TYPE_ACCESS,
                        "token_type": "Bearer",
                        "expires_in": int(self.token_ttl_seconds),
                        "scope": out_scope,
                    },
                    {},
                )

            return (
                400,
                {
                    "error": "unsupported_grant_type",
                    "error_description": f"Unsupported grant_type {grant_type!r}",
                },
                {},
            )

        if req.method == "POST" and path in (
            f"{realm_prefix}/protocol/openid-connect/token/introspect",
            f"{realm_prefix}/protocol/openid-connect/introspect",
        ):
            try:
                form = _parse_form_body(req.body)
                self._authenticate_client(req, form)
            except Exception as exc:
                return 401, {"error": "invalid_client", "error_description": str(exc)}, {}
            tok = form.get("token", "").strip()
            if not tok:
                return 200, {"active": False}, {}
            try:
                claims = self._verify_subject_jwt(tok, allow_federated=False)
                return 200, {"active": True, **claims}, {}
            except Exception:
                return 200, {"active": False}, {}

        if req.method == "POST" and path == f"{realm_prefix}/protocol/openid-connect/revoke":
            try:
                form = _parse_form_body(req.body)
                self._authenticate_client(req, form)
            except Exception as exc:
                return 401, {"error": "invalid_client", "error_description": str(exc)}, {}
            tok = form.get("token", "").strip()
            if tok:
                try:
                    _, claims_ver = jws_verify_compact(
                        tok, self.keypair.public_jwk(), expected_typ=None
                    )
                    jti = str(claims_ver.get("jti") or "")
                    if jti and len(jti) <= 128:
                        with self._lock:
                            self._revoked_jtis[jti] = time.time()
                            self._revoked_jtis.move_to_end(jti)
                            while len(self._revoked_jtis) > MAX_REVOKED_JTIS:
                                self._revoked_jtis.popitem(last=False)
                except Exception:
                    pass
            return 200, {"revoked": True}, {}

        return 404, {"error": "route_not_found", "path": path}, {}
