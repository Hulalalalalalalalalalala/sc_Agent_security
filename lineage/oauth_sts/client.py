"""OIDC / OAuth 2.0 RS256 Token Verifier & RFC 8693 Token Exchange Client.

Supports both:
1. Real `quay.io/keycloak/keycloak:26.5.2` (`/realms/lct/protocol/openid-connect/*`), and
2. Lightweight `OAuthSTSService` (`/realms/lct/protocol/openid-connect/*`).
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import httpx

from lineage.common.crypto import (
    CryptoError,
    jws_parse_unverified,
    jws_verify_compact,
    require_finite_timestamp,
)
from lineage.oauth_sts.keycloak_realm import DEFAULT_REALM_NAME, spiffe_id_to_oauth_client_id
from lineage.oauth_sts.service import (
    CLIENT_ASSERTION_JWT_SPIFFE,
    GRANT_TOKEN_EXCHANGE,
    TOKEN_TYPE_ACCESS,
    OAuthSTSError,
)


@dataclass(frozen=True)
class VerifiedOIDCToken:
    """Verified OIDC / OAuth 2.0 JWT claims bridged at Hop 0 or verified at an inbound Sidecar."""

    raw_claims: Dict[str, Any]
    issuer: str
    raw_sub: str
    username: str
    canonical_lct_sub: str
    audiences: Tuple[str, ...]
    scopes: Tuple[str, ...]
    azp: str
    act: Optional[Dict[str, Any]]
    jti: str
    expires_at: float


class OIDCTokenVerifier:
    """Thread-safe RS256/ES256 JWKS verifier for Keycloak / OAuth 2.0 STS tokens."""

    def __init__(
        self,
        jwks_urls: Iterable[str] = (),
        jwks_urls_provider: Optional[Callable[[], Sequence[str]]] = None,
        expected_issuer: Optional[str] = None,
        allowed_issuers: Optional[Iterable[str]] = None,
        allowed_issuers_provider: Optional[Callable[[], Sequence[str]]] = None,
        default_user_domain: str = "org-alpha.io",
        static_jwks: Optional[Iterable[Mapping[str, Any]]] = None,
        cache_ttl_sec: float = 30.0,
        timeout: float = 3.5,
    ) -> None:
        self._static_urls: Tuple[str, ...] = tuple(
            str(u).strip() for u in jwks_urls if str(u).strip()
        )
        self._jwks_urls_provider = jwks_urls_provider
        self.expected_issuer = expected_issuer.rstrip("/") if expected_issuer else None
        self.allowed_issuers = (
            frozenset(str(x).rstrip("/") for x in allowed_issuers if str(x).strip())
            if allowed_issuers is not None
            else None
        )
        self._allowed_issuers_provider = allowed_issuers_provider
        self.default_user_domain = default_user_domain.strip().lower()
        self.cache_ttl_sec = max(1.0, float(cache_ttl_sec))
        self.timeout = float(timeout)
        self._lock = threading.RLock()
        self._keys_by_kid: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._last_refresh: float = 0.0
        if static_jwks:
            for k in static_jwks:
                if isinstance(k, Mapping) and k.get("kid"):
                    kid_s = str(k["kid"])
                    if len(kid_s) <= 128:
                        self._keys_by_kid[kid_s] = dict(k)

    def _candidate_jwks_urls(self) -> List[str]:
        urls = list(self._static_urls)
        if self._jwks_urls_provider is not None:
            for u in list(self._jwks_urls_provider() or ())[:32]:
                s = str(u).strip()
                if s and s not in urls:
                    urls.append(s)
        return urls

    def refresh_jwks(self, force: bool = False) -> None:
        now_ts = time.time()
        with self._lock:
            if not force and self._keys_by_kid and (now_ts - self._last_refresh) < self.cache_ttl_sec:
                return
        urls = self._candidate_jwks_urls()
        fetched: Dict[str, Dict[str, Any]] = {}
        for url in urls:
            try:
                resp = httpx.get(url, timeout=self.timeout, follow_redirects=False, trust_env=False)
                if resp.status_code == 200:
                    for k in (resp.json().get("keys") or [])[:32]:
                        if isinstance(k, Mapping) and k.get("kid"):
                            kid_s = str(k["kid"])
                            if len(kid_s) <= 128:
                                fetched[kid_s] = dict(k)
            except Exception:
                continue
        with self._lock:
            if fetched:
                for k_id, k_doc in fetched.items():
                    self._keys_by_kid[k_id] = k_doc
                    self._keys_by_kid.move_to_end(k_id)
                while len(self._keys_by_kid) > 128:
                    self._keys_by_kid.popitem(last=False)
            self._last_refresh = now_ts

    def verify_jwt(
        self,
        raw_jwt: str,
        *,
        expected_audience: Optional[str | Iterable[str]] = None,
        required_scopes: Iterable[str] = (),
        now: Optional[float] = None,
    ) -> VerifiedOIDCToken:
        if not isinstance(raw_jwt, str) or not raw_jwt.strip():
            raise OAuthSTSError("empty_oidc_jwt")
        tok = raw_jwt.strip()
        try:
            hdr, _, _, _ = jws_parse_unverified(tok)
        except CryptoError as exc:
            raise OAuthSTSError(f"malformed_oidc_jwt:{exc}") from exc

        kid = str(hdr.get("kid") or "")
        with self._lock:
            jwk = self._keys_by_kid.get(kid)
        if jwk is None:
            self.refresh_jwks(force=True)
            with self._lock:
                jwk = self._keys_by_kid.get(kid)
        if jwk is None:
            raise OAuthSTSError(f"unknown_oidc_signing_kid:{kid}")

        try:
            _, claims = jws_verify_compact(tok, jwk, expected_typ=None)
        except CryptoError as exc:
            raise OAuthSTSError(f"invalid_oidc_signature:{exc}") from exc

        now_ts = require_finite_timestamp(time.time() if now is None else now, "now")
        if "exp" not in claims or claims.get("exp") is None:
            raise OAuthSTSError("missing_exp_claim")
        exp_ts = require_finite_timestamp(claims.get("exp"), "exp")
        if exp_ts <= now_ts - 2.0:
            raise OAuthSTSError("oidc_token_expired")
        if "iat" in claims and claims.get("iat") is not None:
            iat_ts = require_finite_timestamp(claims.get("iat"), "iat")
            if iat_ts > now_ts + 30.0:
                raise OAuthSTSError("oidc_token_iat_in_future")
        if "nbf" in claims and claims.get("nbf") is not None:
            nbf_ts = require_finite_timestamp(claims.get("nbf"), "nbf")
            if nbf_ts > now_ts + 30.0:
                raise OAuthSTSError("oidc_token_nbf_in_future")

        iss = str(claims.get("iss") or "").rstrip("/")
        if not iss:
            raise OAuthSTSError("missing_iss_claim")
        if self.expected_issuer is not None and iss != self.expected_issuer:
            raise OAuthSTSError(
                f"oidc_issuer_mismatch: got {iss!r}, expected {self.expected_issuer!r}"
            )
        if self.allowed_issuers is not None and iss not in self.allowed_issuers:
            raise OAuthSTSError(f"oidc_issuer_not_allowed: {iss!r}")
        if self._allowed_issuers_provider is not None:
            dyn_allowed = {
                str(x).rstrip("/")
                for x in (self._allowed_issuers_provider() or ())
                if str(x).strip()
            }
            if dyn_allowed and iss not in dyn_allowed:
                raise OAuthSTSError(f"oidc_issuer_not_allowed: {iss!r} not in {sorted(dyn_allowed)}")

        raw_aud = claims.get("aud")
        if isinstance(raw_aud, str):
            aud_tuple: Tuple[str, ...] = (raw_aud,)
        elif isinstance(raw_aud, list):
            aud_tuple = tuple(str(x) for x in raw_aud if str(x).strip())
        else:
            aud_tuple = ()

        if expected_audience is not None:
            wanted_auds = (
                {expected_audience}
                if isinstance(expected_audience, str)
                else {str(a) for a in expected_audience if str(a).strip()}
            )
            if wanted_auds and not (set(aud_tuple) & wanted_auds):
                raise OAuthSTSError(
                    f"oidc_audience_mismatch: token aud={list(aud_tuple)} does not intersect {sorted(wanted_auds)}"
                )

        scope_str = str(claims.get("scope") or "")
        scopes_tuple = tuple(s for s in scope_str.split() if s)
        req_sc = {str(s).strip() for s in required_scopes if str(s).strip()}
        if req_sc and not req_sc.issubset(set(scopes_tuple)):
            raise OAuthSTSError(
                f"insufficient_oauth_scope: required={sorted(req_sc)}, present={list(scopes_tuple)}"
            )

        raw_sub = str(claims.get("sub") or "").strip()
        pref_user = str(claims.get("preferred_username") or "").strip()
        if not raw_sub and not pref_user:
            raise OAuthSTSError("missing_sub_claim")

        uname = pref_user or raw_sub
        if uname.startswith("user:") and "@" in uname:
            canonical_sub = uname
        elif "@" in uname:
            canonical_sub = f"user:{uname}"
        else:
            canonical_sub = f"user:{uname}@{self.default_user_domain}"

        act_raw = claims.get("act")
        act_dict = dict(act_raw) if isinstance(act_raw, Mapping) else None
        return VerifiedOIDCToken(
            raw_claims=dict(claims),
            issuer=iss,
            raw_sub=raw_sub or uname,
            username=uname,
            canonical_lct_sub=canonical_sub,
            audiences=aud_tuple,
            scopes=scopes_tuple,
            azp=str(claims.get("azp") or ""),
            act=act_dict,
            jti=str(claims.get("jti") or ""),
            expires_at=exp_ts,
        )


@dataclass(frozen=True)
class TokenExchangeOutcome:
    """Result + network telemetry of a live RFC 8693 Token Exchange call."""

    access_token: str
    token_type: str
    expires_in: int
    scope: str
    sts_endpoint: str
    rtt_ms: float


class OAuthTokenExchangeClient:
    """HTTP client for Hop-0 OIDC human login and Hop-k RFC 8693 Token Exchange."""

    def __init__(
        self,
        realm: str = DEFAULT_REALM_NAME,
        client_secrets: Optional[Mapping[str, str]] = None,
        timeout: float = 6.0,
    ) -> None:
        self.realm = realm.strip() or DEFAULT_REALM_NAME
        self._client_secrets: Dict[str, str] = dict(client_secrets or {})
        self.timeout = float(timeout)

    def _split_origin_and_host(self, sts_origin: str) -> Tuple[str, Dict[str, str], str]:
        """Support `http://in-cluster:8095#host=10.29.77.23:30105` for zero-hairpin in-cluster calls."""
        raw = sts_origin.strip()
        if "#host=" in raw:
            connect_base, host_hdr = raw.split("#host=", 1)
            connect_base = connect_base.rstrip("/")
            host_hdr = host_hdr.strip()
            canonical_base = f"http://{host_hdr}"
            return connect_base, ({"Host": host_hdr} if host_hdr else {}), canonical_base
        clean = raw.rstrip("/")
        return clean, {}, clean

    def token_endpoint(self, sts_origin: str) -> str:
        base, _, _ = self._split_origin_and_host(sts_origin)
        if "/protocol/openid-connect/token" in base:
            return base
        if f"/realms/{self.realm}" in base:
            return f"{base}/protocol/openid-connect/token"
        return f"{base}/realms/{self.realm}/protocol/openid-connect/token"

    def jwks_endpoint(self, sts_origin: str) -> str:
        base, _, _ = self._split_origin_and_host(sts_origin)
        if "/protocol/openid-connect/certs" in base:
            return base
        if f"/realms/{self.realm}" in base:
            return f"{base}/protocol/openid-connect/certs"
        return f"{base}/realms/{self.realm}/protocol/openid-connect/certs"

    def login_user_password(
        self,
        sts_origins: Sequence[str] | str,
        username: str,
        password: str,
        client_id: str = "lct-gateway",
        client_secret: Optional[str] = None,
        scope: str = "openid travel:book travel:pay",
    ) -> Dict[str, Any]:
        origins = [sts_origins] if isinstance(sts_origins, str) else list(sts_origins)
        eff_secret = client_secret or self._client_secrets.get(client_id, "")
        last_err: Optional[Exception] = None
        for orig in origins:
            _, extra_hdrs, canonical_base = self._split_origin_and_host(orig)
            tok_url = self.token_endpoint(orig)
            reported_url = f"{canonical_base}/realms/{self.realm}/protocol/openid-connect/token"
            t0 = time.perf_counter()
            try:
                resp = httpx.post(
                    tok_url,
                    data={
                        "grant_type": "password",
                        "client_id": client_id,
                        "client_secret": eff_secret,
                        "username": username,
                        "password": password,
                        "scope": scope,
                    },
                    headers=extra_hdrs,
                    timeout=self.timeout,
                    follow_redirects=False,
                    trust_env=False,
                )
                rtt_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                if resp.status_code != 200:
                    raise OAuthSTSError(f"OIDC login HTTP {resp.status_code}: {resp.text}")
                data = dict(resp.json())
                data["sts_endpoint"] = reported_url
                data["rtt_ms"] = rtt_ms
                return data
            except Exception as exc:
                last_err = exc
                continue
        raise OAuthSTSError(f"All OIDC login endpoints failed ({origins}): {last_err}")

    def exchange_token(
        self,
        sts_origins: Sequence[str] | str,
        subject_token: str,
        target_audience: str,
        *,
        caller_spiffe_id: Optional[str] = None,
        caller_workload_svid: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        requested_scope: Optional[str] = None,
    ) -> TokenExchangeOutcome:
        origins = [sts_origins] if isinstance(sts_origins, str) else list(sts_origins)
        if not origins:
            raise OAuthSTSError("No OAuth STS locator endpoints available for token exchange")

        eff_cid = client_id or (
            spiffe_id_to_oauth_client_id(caller_spiffe_id) if caller_spiffe_id else "lct-gateway"
        )
        eff_secret = client_secret or self._client_secrets.get(eff_cid, "")

        # Resolve audience to both SPIFFE ID or Keycloak client_id depending on STS type
        aud_client_id = spiffe_id_to_oauth_client_id(target_audience)

        last_err: Optional[Exception] = None
        for orig in origins:
            _, extra_hdrs, canonical_base = self._split_origin_and_host(orig)
            tok_url = self.token_endpoint(orig)
            reported_url = f"{canonical_base}/realms/{self.realm}/protocol/openid-connect/token"
            form_data: Dict[str, str] = {
                "grant_type": GRANT_TOKEN_EXCHANGE,
                "client_id": eff_cid,
                "subject_token": subject_token,
                "subject_token_type": TOKEN_TYPE_ACCESS,
                "requested_token_type": TOKEN_TYPE_ACCESS,
                "audience": aud_client_id,
            }
            if requested_scope:
                form_data["scope"] = requested_scope
            if eff_secret:
                form_data["client_secret"] = eff_secret
            elif caller_workload_svid:
                form_data["client_assertion_type"] = CLIENT_ASSERTION_JWT_SPIFFE
                form_data["client_assertion"] = caller_workload_svid

            t0 = time.perf_counter()
            try:
                resp = httpx.post(
                    tok_url,
                    data=form_data,
                    headers=extra_hdrs,
                    timeout=self.timeout,
                    follow_redirects=False,
                    trust_env=False,
                )
                rtt_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                if resp.status_code == 401 and eff_secret and caller_workload_svid:
                    # If confidential secret wasn't loaded on federated lightweight STS, retry with SPIFFE assertion
                    alt_form = dict(form_data)
                    alt_form.pop("client_secret", None)
                    alt_form["client_assertion_type"] = CLIENT_ASSERTION_JWT_SPIFFE
                    alt_form["client_assertion"] = caller_workload_svid
                    t1 = time.perf_counter()
                    resp_spiffe = httpx.post(
                        tok_url,
                        data=alt_form,
                        headers=extra_hdrs,
                        timeout=self.timeout,
                        follow_redirects=False,
                        trust_env=False,
                    )
                    if resp_spiffe.status_code == 200:
                        resp = resp_spiffe
                        rtt_ms = round((time.perf_counter() - t1) * 1000.0, 2)
                if resp.status_code != 200:
                    raise OAuthSTSError(f"RFC 8693 exchange HTTP {resp.status_code} at {reported_url}: {resp.text}")
                body = resp.json()
                return TokenExchangeOutcome(
                    access_token=str(body["access_token"]),
                    token_type=str(body.get("token_type", "Bearer")),
                    expires_in=int(body.get("expires_in", 900)),
                    scope=str(body.get("scope", "")),
                    sts_endpoint=reported_url,
                    rtt_ms=rtt_ms,
                )
            except Exception as exc:
                last_err = exc
                continue
        raise OAuthSTSError(f"RFC 8693 token exchange failed across {origins}: {last_err}")

    def revoke_token(
        self,
        sts_origin: str,
        token: str,
        client_id: str = "lct-gateway",
        client_secret: Optional[str] = None,
    ) -> int:
        base = sts_origin.rstrip("/")
        rev_url = (
            f"{base}/protocol/openid-connect/revoke"
            if f"/realms/{self.realm}" in base
            else f"{base}/realms/{self.realm}/protocol/openid-connect/revoke"
        )
        eff_secret = client_secret or self._client_secrets.get(client_id, "")
        resp = httpx.post(
            rev_url,
            data={"client_id": client_id, "client_secret": eff_secret, "token": token},
            timeout=self.timeout,
            follow_redirects=False,
            trust_env=False,
        )
        return resp.status_code
