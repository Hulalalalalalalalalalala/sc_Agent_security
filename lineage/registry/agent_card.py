"""Official A2A v1.0 Cryptographically Signed AgentCard Preventing Agent Card Poisoning.

Serializes a 100% compliant A2A v1.0 `AgentCard` (`name`, `description`, `url`,
`protocolVersion: "1.0"`, `version`, `provider`, `capabilities`, `defaultInputModes`,
`defaultOutputModes`, structured `skills` objects, `securitySchemes` declaring `lct_dpop`,
and `signatures`) while cryptographically binding every field to a SPIFFE WorkloadIdentity
(`JWT-SVID` + `a2a-agent-card+jwt` JWS).
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union
from urllib.parse import urlsplit

from lineage.common.crypto import (
    CryptoError,
    canonical_json_bytes,
    compute_jwk_thumbprint,
    jws_sign_compact,
    jws_verify_compact,
    require_finite_timestamp,
    sha256_b64url,
)
from lineage.common.locators import (
    LocatorError,
    ServiceLocator,
    sort_and_dedup_locators,
    validate_locator_host,
)
from lineage.identity.spiffe import IdentityError, SpiffeId, WorkloadIdentity
from lineage.identity.trust_bundle import TrustBundleResolver


class AgentCardError(Exception):
    """Raised when an AgentCard fails structural or cryptographic verification."""


class AgentStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"
    QUARANTINED = "QUARANTINED"


@dataclass(frozen=True)
class AgentSkill:
    """Official A2A v1.0 `AgentSkill` descriptor."""

    id: str
    name: str
    description: str = ""
    tags: Tuple[str, ...] = ()
    input_modes: Tuple[str, ...] = ("text/plain", "application/json")
    output_modes: Tuple[str, ...] = ("text/plain", "application/json")

    @classmethod
    def coerce(cls, item: Union[str, "AgentSkill", Mapping[str, Any]]) -> "AgentSkill":
        if isinstance(item, AgentSkill):
            return item
        if isinstance(item, str):
            sid = item.strip()
            if not sid:
                raise AgentCardError("Skill id cannot be empty")
            parts = [p for p in sid.replace("-", ".").split(".") if p]
            human_name = " ".join(p.capitalize() for p in parts) or sid
            return cls(
                id=sid,
                name=human_name,
                description=f"A2A v1.0 capability skill '{sid}'",
                tags=tuple(parts) if parts else (sid,),
            )
        if isinstance(item, Mapping):
            sid = str(item.get("id") or "").strip()
            if not sid:
                raise AgentCardError("Structured AgentSkill missing non-empty 'id'")
            name = str(item.get("name") or sid).strip()
            desc = str(item.get("description") or "").strip()
            tags_raw = item.get("tags")
            tags = (
                tuple(str(t) for t in tags_raw)
                if isinstance(tags_raw, (list, tuple))
                else tuple(p for p in sid.replace("-", ".").split(".") if p)
            )
            in_raw = item.get("inputModes")
            in_modes = (
                tuple(str(m) for m in in_raw)
                if isinstance(in_raw, (list, tuple)) and in_raw
                else ("text/plain", "application/json")
            )
            out_raw = item.get("outputModes")
            out_modes = (
                tuple(str(m) for m in out_raw)
                if isinstance(out_raw, (list, tuple)) and out_raw
                else ("text/plain", "application/json")
            )
            return cls(
                id=sid,
                name=name,
                description=desc,
                tags=tags,
                input_modes=in_modes,
                output_modes=out_modes,
            )
        raise AgentCardError(f"Unsupported skill specification: {item!r}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "tags": list(self.tags),
            "inputModes": list(self.input_modes),
            "outputModes": list(self.output_modes),
        }


def _validate_http_endpoint(url: str, field_name: str) -> str:
    if not isinstance(url, str):
        raise AgentCardError(f"Invalid {field_name} URL: must be a string")
    s = url.strip()
    if (
        not s
        or "\\" in s
        or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in s)
    ):
        raise AgentCardError(
            f"Invalid {field_name} URL {url!r}: contains illegal whitespace or control chars"
        )
    sp = urlsplit(s)
    if sp.scheme not in ("http", "https") or not sp.netloc or not sp.hostname:
        raise AgentCardError(f"Invalid {field_name} URL: {url!r}")
    if "@" in sp.netloc or sp.username is not None or sp.password is not None:
        raise AgentCardError(
            f"Invalid {field_name} URL {url!r}: userinfo '@' not allowed"
        )
    if sp.path not in ("", "/") or sp.query != "" or sp.fragment != "":
        raise AgentCardError(
            f"Invalid {field_name} URL {url!r}: must be a clean http(s)://host[:port] origin without path, query, or fragment"
        )
    try:
        _ = sp.port
    except ValueError as exc:
        raise AgentCardError(f"Invalid port in {field_name} URL {url!r}") from exc
    return f"{sp.scheme.lower()}://{sp.netloc}"


def _default_security_schemes() -> Dict[str, Any]:
    return {
        "lct_dpop": {
            "type": "http",
            "scheme": "DPoP",
            "bearerFormat": "LCT",
            "description": (
                "Lineage Capability Tree (LCT) Capability Token + RFC 9449 DPoP proof "
                "over federated SPIFFE X.509-SVID mTLS"
            ),
        }
    }


@dataclass(frozen=True)
class AgentCard:
    """Official A2A v1.0 Superset AgentCard bound to a SPIFFE WorkloadIdentity."""

    spiffe_id: str
    trust_domain: str
    name: str
    description: str
    endpoint: str
    return_endpoint: str
    skills: Tuple[str, ...]
    supported_tools: Tuple[str, ...]
    public_jwk: Dict[str, Any]
    jkt: str
    workload_svid: str
    status: AgentStatus
    version: int
    priority: int
    issued_at: float
    expires_at: float
    jws_signature: str
    protocol_version: str = "1.0"
    skill_objects: Tuple[AgentSkill, ...] = ()
    default_input_modes: Tuple[str, ...] = ("text/plain", "application/json")
    default_output_modes: Tuple[str, ...] = ("text/plain", "application/json")
    streaming_supported: bool = True
    locators: Tuple[ServiceLocator, ...] = ()

    @property
    def url(self) -> str:
        return self.endpoint

    def candidate_origins(self) -> List[str]:
        """Return prioritized clean origin URLs (`scheme://host:port`) for outbound routing."""
        if self.locators:
            return [loc.origin_url for loc in self.locators]
        return [self.endpoint]

    def candidate_return_origins(self) -> List[str]:
        """Return prioritized clean origin URLs (`scheme://host:port`) for upward return routing."""
        if self.locators:
            return [loc.origin_url for loc in self.locators]
        return [self.return_endpoint]

    def _resolved_skill_objects(self) -> List[Dict[str, Any]]:
        if self.skill_objects:
            return [sk.to_dict() for sk in self.skill_objects]
        return [AgentSkill.coerce(sid).to_dict() for sid in self.skills]

    def core_claims(self) -> Dict[str, Any]:
        """Deterministic claim body covered by `jws_signature` & `signatures`."""
        claims: Dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "url": self.endpoint,
            "endpoint": self.endpoint,
            "return_endpoint": self.return_endpoint,
            "protocolVersion": self.protocol_version,
            "version": str(self.version),
            "provider": {
                "organization": self.trust_domain,
                "url": f"https://{self.trust_domain}",
            },
            "capabilities": {
                "streaming": bool(self.streaming_supported),
                "pushNotifications": False,
                "stateTransitionHistory": True,
            },
            "defaultInputModes": list(self.default_input_modes),
            "defaultOutputModes": list(self.default_output_modes),
            "skills": self._resolved_skill_objects(),
            "securitySchemes": _default_security_schemes(),
            "security": [{"lct_dpop": []}],
            "spiffe_id": self.spiffe_id,
            "trust_domain": self.trust_domain,
            "supported_tools": list(self.supported_tools),
            "public_jwk": self.public_jwk,
            "jkt": self.jkt,
            "workload_svid_sha256": sha256_b64url(self.workload_svid.encode("ascii")),
            "status": self.status.value,
            "priority": self.priority,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }
        if self.locators:
            claims["locators"] = [loc.to_dict() for loc in self.locators]
            claims["supportedInterfaces"] = [
                {
                    "url": loc.origin_url,
                    "protocolBinding": "JSONRPC",
                    "protocolVersion": self.protocol_version,
                }
                for loc in self.locators
            ]
        return claims

    def to_dict(self) -> Dict[str, Any]:
        data = self.core_claims()
        data.pop("workload_svid_sha256", None)
        data["workload_svid"] = self.workload_svid
        data["jws_signature"] = self.jws_signature
        data["signatures"] = [
            {
                "protected_typ": "a2a-agent-card+jwt",
                "jws": self.jws_signature,
                "workload_svid": self.workload_svid,
                "spiffe_id": self.spiffe_id,
                "jkt": self.jkt,
            }
        ]
        return data

    @classmethod
    def sign_and_create(
        cls,
        identity: WorkloadIdentity,
        name: str,
        endpoint: Optional[str] = None,
        skills: Iterable[Union[str, AgentSkill, Mapping[str, Any]]] = (),
        description: str = "",
        return_endpoint: Optional[str] = None,
        supported_tools: Iterable[str] = (),
        status: AgentStatus = AgentStatus.ACTIVE,
        version: int = 1,
        priority: int = 100,
        ttl_seconds: float = 3600.0,
        streaming_supported: bool = True,
        locators: Iterable[Union[ServiceLocator, Mapping[str, Any]]] = (),
        allowed_locator_cidrs: Optional[Iterable[str] | str] = None,
        now: Optional[float] = None,
    ) -> "AgentCard":
        spiffe = SpiffeId.parse(identity.spiffe_id)

        parsed_locs: List[ServiceLocator] = []
        for raw_loc in locators:
            try:
                loc = (
                    raw_loc
                    if isinstance(raw_loc, ServiceLocator)
                    else ServiceLocator.from_dict(
                        raw_loc, allowed_cidrs=allowed_locator_cidrs
                    )
                )
                validate_locator_host(loc.host, allowed_cidrs=allowed_locator_cidrs)
            except LocatorError as exc:
                raise AgentCardError(f"Invalid AgentCard locator: {exc}") from exc
            if loc.spiffe_id is not None and loc.spiffe_id != spiffe.uri:
                raise AgentCardError(
                    f"AgentCard locator spiffe_id {loc.spiffe_id!r} != card spiffe_id {spiffe.uri!r}"
                )
            parsed_locs.append(loc)
        loc_tuple = sort_and_dedup_locators(parsed_locs) if parsed_locs else ()

        if loc_tuple:
            derived_origin = loc_tuple[0].origin_url
            if endpoint is not None:
                norm_ep_check = _validate_http_endpoint(endpoint, "endpoint")
                if norm_ep_check != derived_origin:
                    raise AgentCardError(
                        f"AgentCard endpoint {norm_ep_check!r} must match primary signed locator {derived_origin!r}"
                    )
            norm_endpoint = derived_origin
            norm_ret = (
                _validate_http_endpoint(return_endpoint, "return_endpoint")
                if return_endpoint
                else derived_origin
            )
        else:
            if not endpoint:
                raise AgentCardError("AgentCard requires either locators or endpoint")
            norm_endpoint = _validate_http_endpoint(endpoint, "endpoint")
            norm_ret = _validate_http_endpoint(
                return_endpoint if return_endpoint else norm_endpoint, "return_endpoint"
            )

        by_id: Dict[str, AgentSkill] = {}
        for s_item in skills:
            sk_obj = AgentSkill.coerce(s_item)
            by_id[sk_obj.id] = sk_obj
        if not by_id:
            raise AgentCardError("AgentCard must advertise at least one non-empty skill")
        sorted_skill_objs = tuple(by_id[k] for k in sorted(by_id.keys()))
        skill_tuple = tuple(sk.id for sk in sorted_skill_objs)

        tool_tuple = tuple(
            sorted({str(t).strip() for t in supported_tools if str(t).strip()})
        )
        if version < 1:
            raise AgentCardError("AgentCard version must be >= 1")

        ts = time.time() if now is None else float(now)
        exp = min(ts + float(ttl_seconds), identity.expires_at)
        if exp <= ts:
            raise AgentCardError("WorkloadIdentity has already expired")

        pub_jwk = identity.public_jwk()
        jkt = identity.jkt
        resolved_desc = description or f"{name} ({spiffe.trust_domain})"

        provisional = cls(
            spiffe_id=spiffe.uri,
            trust_domain=spiffe.trust_domain,
            name=name,
            description=resolved_desc,
            endpoint=norm_endpoint,
            return_endpoint=norm_ret,
            skills=skill_tuple,
            supported_tools=tool_tuple,
            public_jwk=pub_jwk,
            jkt=jkt,
            workload_svid=identity.workload_svid,
            status=AgentStatus(status),
            version=int(version),
            priority=int(priority),
            issued_at=ts,
            expires_at=exp,
            jws_signature="",
            protocol_version="1.0",
            skill_objects=sorted_skill_objs,
            streaming_supported=bool(streaming_supported),
            locators=loc_tuple,
        )
        sig = jws_sign_compact(
            payload=provisional.core_claims(),
            keypair=identity.keypair,
            typ="a2a-agent-card+jwt",
        )
        return cls(**{**provisional.__dict__, "jws_signature": sig})

    @classmethod
    def verify_and_parse(
        cls,
        raw: Mapping[str, Any],
        trust_resolver: TrustBundleResolver,
        now: Optional[float] = None,
        allowed_locator_cidrs: Optional[Iterable[str] | str] = None,
    ) -> "AgentCard":
        """Alias for `from_dict_and_verify` matching `SignedDomainDescriptor.verify_and_parse`."""
        return cls.from_dict_and_verify(
            raw=raw,
            trust_resolver=trust_resolver,
            now=now,
            allowed_locator_cidrs=allowed_locator_cidrs,
        )

    @classmethod
    def from_dict_and_verify(
        cls,
        raw: Mapping[str, Any],
        trust_resolver: TrustBundleResolver,
        now: Optional[float] = None,
        allowed_locator_cidrs: Optional[Iterable[str] | str] = None,
    ) -> "AgentCard":
        """Parse and cryptographically verify an A2A v1.0 AgentCard against the Trust Bundle."""
        if not isinstance(raw, Mapping):
            raise AgentCardError("AgentCard payload must be a JSON object")

        try:
            spiffe = SpiffeId.parse(str(raw.get("spiffe_id", "")))
        except IdentityError as exc:
            raise AgentCardError(f"Invalid AgentCard spiffe_id: {exc}") from exc

        if raw.get("trust_domain") != spiffe.trust_domain:
            raise AgentCardError(
                f"AgentCard trust_domain mismatch: {raw.get('trust_domain')!r} != {spiffe.trust_domain!r}"
            )

        provider = raw.get("provider")
        if isinstance(provider, Mapping):
            if provider.get("organization") != spiffe.trust_domain:
                raise AgentCardError("AgentCard provider.organization mismatches trust_domain")

        pub_jwk = raw.get("public_jwk")
        if not isinstance(pub_jwk, Mapping):
            raise AgentCardError("AgentCard missing public_jwk")

        try:
            computed_jkt = compute_jwk_thumbprint(pub_jwk)
        except CryptoError as exc:
            raise AgentCardError(f"Invalid AgentCard public_jwk: {exc}") from exc

        if raw.get("jkt") != computed_jkt:
            raise AgentCardError("AgentCard jkt does not match public_jwk thumbprint")

        sigs_list = raw.get("signatures")
        sig_entry = (
            sigs_list[0]
            if isinstance(sigs_list, list) and sigs_list and isinstance(sigs_list[0], Mapping)
            else None
        )
        workload_svid = str(
            raw.get("workload_svid")
            or (sig_entry.get("workload_svid") if sig_entry else "")
            or ""
        )
        if not workload_svid:
            raise AgentCardError("AgentCard missing workload_svid")

        jws_sig = str(
            raw.get("jws_signature")
            or (sig_entry.get("jws") if sig_entry else "")
            or ""
        )
        if not jws_sig:
            raise AgentCardError("AgentCard missing jws_signature")
        if (
            sig_entry is not None
            and "jws_signature" in raw
            and str(sig_entry.get("jws", "")) != str(raw["jws_signature"])
        ):
            raise AgentCardError("AgentCard jws_signature conflicts with signatures[0].jws")

        # 1. Verify CA-signed Workload SVID binds spiffe_id <-> computed_jkt
        try:
            trust_resolver.verify_workload_svid(
                workload_svid,
                expected_spiffe_id=spiffe.uri,
                expected_jkt=computed_jkt,
                now=now,
            )
        except IdentityError as exc:
            raise AgentCardError(f"AgentCard SVID verification failed: {exc}") from exc

        # 2. Reconstruct card structure (including signed locators when present)
        try:
            status = AgentStatus(str(raw.get("status", "ACTIVE")))
            ver_raw = raw["version"]
            if isinstance(ver_raw, bool):
                raise AgentCardError("Invalid boolean version")
            version = int(str(ver_raw))
            priority = int(raw.get("priority", 100))
            issued_at = require_finite_timestamp(raw["issued_at"], "AgentCard.issued_at")
            expires_at = require_finite_timestamp(raw["expires_at"], "AgentCard.expires_at")

            locators_raw = raw.get("locators")
            loc_tuple: Tuple[ServiceLocator, ...] = ()
            if locators_raw is not None:
                if not isinstance(locators_raw, list) or not locators_raw:
                    raise AgentCardError("AgentCard locators must be a non-empty list when present")
                parsed_locs: List[ServiceLocator] = []
                for l_item in locators_raw:
                    loc_obj = ServiceLocator.from_dict(
                        l_item, allowed_cidrs=allowed_locator_cidrs
                    )
                    if loc_obj.spiffe_id is not None and loc_obj.spiffe_id != spiffe.uri:
                        raise AgentCardError(
                            f"AgentCard locator spiffe_id {loc_obj.spiffe_id!r} != {spiffe.uri!r}"
                        )
                    parsed_locs.append(loc_obj)
                loc_tuple = sort_and_dedup_locators(parsed_locs)

            raw_ep = raw.get("endpoint") if "endpoint" in raw else raw.get("url")
            endpoint = _validate_http_endpoint(str(raw_ep), "endpoint")
            if "url" in raw and "endpoint" in raw:
                norm_url = _validate_http_endpoint(str(raw["url"]), "url")
                if norm_url != endpoint:
                    raise AgentCardError(
                        f"AgentCard url {norm_url!r} conflicts with endpoint {endpoint!r}"
                    )
            if loc_tuple and endpoint != loc_tuple[0].origin_url:
                raise AgentCardError(
                    f"AgentCard endpoint {endpoint!r} mismatches primary signed locator {loc_tuple[0].origin_url!r}"
                )
            return_endpoint = _validate_http_endpoint(
                str(raw.get("return_endpoint") or endpoint), "return_endpoint"
            )

            proto_ver = str(raw.get("protocolVersion") or "1.0")
            if proto_ver != "1.0":
                raise AgentCardError(f"Unsupported AgentCard protocolVersion: {proto_ver!r}")

            caps = raw.get("capabilities")
            streaming_ok = (
                bool(caps.get("streaming", True))
                if isinstance(caps, Mapping)
                else True
            )
            in_modes_raw = raw.get("defaultInputModes")
            in_modes = (
                tuple(str(m) for m in in_modes_raw)
                if isinstance(in_modes_raw, list) and in_modes_raw
                else ("text/plain", "application/json")
            )
            out_modes_raw = raw.get("defaultOutputModes")
            out_modes = (
                tuple(str(m) for m in out_modes_raw)
                if isinstance(out_modes_raw, list) and out_modes_raw
                else ("text/plain", "application/json")
            )

            skills_raw = raw.get("skills")
            if not isinstance(skills_raw, list) or not skills_raw:
                raise AgentCardError("AgentCard skills must be a non-empty list")
            skill_objs = tuple(AgentSkill.coerce(s) for s in skills_raw)
            skills = tuple(sk.id for sk in skill_objs)

            tools_raw = raw.get("supported_tools", [])
            if not isinstance(tools_raw, list):
                raise AgentCardError("AgentCard supported_tools must be a list")
            supported_tools = tuple(str(t) for t in tools_raw)
        except AgentCardError:
            raise
        except LocatorError as exc:
            raise AgentCardError(f"Invalid AgentCard locator: {exc}") from exc
        except Exception as exc:
            raise AgentCardError(f"Malformed AgentCard fields: {exc}") from exc

        if version < 1:
            raise AgentCardError("AgentCard version must be >= 1")

        ts = require_finite_timestamp(time.time() if now is None else now, "now")
        if issued_at > ts + 5.0:
            raise AgentCardError("AgentCard issued_at is in the future")
        if expires_at <= ts - 5.0:
            raise AgentCardError("AgentCard has expired")

        card = cls(
            spiffe_id=spiffe.uri,
            trust_domain=spiffe.trust_domain,
            name=str(raw.get("name", "")),
            description=str(raw.get("description", "")),
            endpoint=endpoint,
            return_endpoint=return_endpoint,
            skills=skills,
            supported_tools=supported_tools,
            public_jwk=dict(pub_jwk),
            jkt=computed_jkt,
            workload_svid=workload_svid,
            status=status,
            version=version,
            priority=priority,
            issued_at=issued_at,
            expires_at=expires_at,
            jws_signature=jws_sig,
            protocol_version=proto_ver,
            skill_objects=skill_objs,
            default_input_modes=in_modes,
            default_output_modes=out_modes,
            streaming_supported=streaming_ok,
            locators=loc_tuple,
        )

        # 3. Verify workload's JWS signature over canonical core_claims
        try:
            _, signed_claims = jws_verify_compact(
                jws_sig, pub_jwk, expected_typ="a2a-agent-card+jwt"
            )
        except CryptoError as exc:
            raise AgentCardError(
                f"AgentCard signature verification failed (Poisoning attempt blocked): {exc}"
            ) from exc

        if canonical_json_bytes(signed_claims) != canonical_json_bytes(card.core_claims()):
            raise AgentCardError(
                "AgentCard payload tampering detected: signed claims do not match card body"
            )

        return card
