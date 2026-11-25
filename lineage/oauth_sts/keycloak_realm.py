"""Keycloak 26.5.2 Realm Configuration & Ephemeral Credential Generator (`lct-realm.json`).

Generates a complete, zero-hardcoded-secret realm definition for `quay.io/keycloak/keycloak:26.5.2`
(`start-dev --import-realm --features=token-exchange,token-exchange-standard:v2`) supporting:
1. Hop-0 OIDC human user authentication (`alice`, `bob`, `carol`) with `sub` & `preferred_username`
   protocol mappers present in both `id_token` and `access_token`;
2. Standard RFC 8693 Token Exchange v2 (`standard.token.exchange.enabled=true`) across all LCT
   agent and MCP tool clients (`lct-gateway`, `orchestrator-alpha`, `flight-specialist`,
   `hotel-specialist-primary`, `hotel-specialist-backup`, `settlement-converger`,
   `travel-ops-mcp`, `payment-vault-mcp`);
3. Flat OAuth 2.0 client scopes (`travel:book`, `travel:pay`) for empirical comparison against
   LCT's fine-grained `PermissionLattice`.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import secrets
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

KEYCLOAK_IMAGE: str = "quay.io/keycloak/keycloak:26.5.2"
DEFAULT_REALM_NAME: str = "lct"

STANDARD_OAUTH_CLIENT_IDS: Tuple[str, ...] = (
    "lct-gateway",
    "beta-user-gateway",
    "orchestrator-alpha",
    "flight-specialist",
    "hotel-specialist-primary",
    "hotel-specialist-backup",
    "settlement-converger",
    "travel-ops-mcp",
    "payment-vault-mcp",
    "assistant-alice",
    "assistant-bob",
    "assistant-bob-standby",
    "assistant-dave",
    "assistant-carol",
    "assistant-carol-standby",
    "assistant-vault",
)

SPIFFE_SUFFIX_TO_CLIENT_ID: Dict[str, str] = {
    "/sa/e2e-user-gateway": "lct-gateway",
    "/sa/beta-user-gateway": "beta-user-gateway",
    "/sa/orchestrator-alpha": "orchestrator-alpha",
    "/sa/flight-specialist": "flight-specialist",
    "/sa/hotel-specialist-primary": "hotel-specialist-primary",
    "/sa/hotel-specialist-backup": "hotel-specialist-backup",
    "/sa/settlement-converger": "settlement-converger",
    "/sa/travel-ops-mcp": "travel-ops-mcp",
    "/sa/payment-vault-mcp": "payment-vault-mcp",
    "/sa/assistant-alice": "assistant-alice",
    "/sa/assistant-bob": "assistant-bob",
    "/sa/assistant-bob-standby": "assistant-bob-standby",
    "/sa/assistant-dave": "assistant-dave",
    "/sa/assistant-carol": "assistant-carol",
    "/sa/assistant-carol-standby": "assistant-carol-standby",
    "/sa/assistant-vault": "assistant-vault",
}

DEFAULT_USER_HOME_DOMAINS: Dict[str, str] = {
    "alice": "org-alpha.io",
    "bob": "org-beta.io",
    "dave": "org-beta.io",
    "carol": "org-payment.io",
}

DEFAULT_FLAT_OAUTH_SCOPES: Tuple[str, ...] = ("travel:book", "travel:pay")


def spiffe_id_to_oauth_client_id(spiffe_id: str) -> str:
    """Map a workload SPIFFE ID (`spiffe://<td >/ns/<ns>/sa/<sa>`) to its OAuth client_id."""
    s = str(spiffe_id or "").strip()
    for suffix, cid in SPIFFE_SUFFIX_TO_CLIENT_ID.items():
        if s.endswith(suffix):
            return cid
    if "/sa/" in s:
        return s.rsplit("/sa/", 1)[1].strip() or "lct-workload"
    return s or "lct-workload"


@dataclass(frozen=True)
class GeneratedRealmBundle:
    """In-memory generated Keycloak realm + ephemeral credentials (never written to host disk)."""

    realm_name: str
    admin_username: str
    admin_password: str
    user_passwords: Dict[str, str]
    client_secrets: Dict[str, str]
    realm_dict: Dict[str, Any]

    def realm_json(self) -> str:
        return json.dumps(self.realm_dict, indent=2)

    def runtime_credentials_json(self) -> str:
        """Compact JSON mounted into authorized pods (`defaultMode: 0440`) for STS exchange."""
        return json.dumps(
            {
                "realm": self.realm_name,
                "users": dict(self.user_passwords),
                "clients": dict(self.client_secrets),
            },
            indent=2,
        )


def _audience_mapper(target_client_id: str) -> Dict[str, Any]:
    return {
        "name": f"aud-{target_client_id}",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "consentRequired": False,
        "config": {
            "included.client.audience": target_client_id,
            "id.token.claim": "false",
            "access.token.claim": "true",
        },
    }


def generate_keycloak_realm_bundle(
    realm_name: str = DEFAULT_REALM_NAME,
    users: Iterable[str] = ("alice", "bob", "dave", "carol"),
    client_ids: Iterable[str] = STANDARD_OAUTH_CLIENT_IDS,
    explicit_user_passwords: Optional[Mapping[str, str]] = None,
    explicit_client_secrets: Optional[Mapping[str, str]] = None,
    access_token_lifespan_sec: int = 900,
    realm_trust_domain: Optional[str] = None,
) -> GeneratedRealmBundle:
    """Build a valid Keycloak 26.5.2 realm import payload with fresh random secrets."""
    c_ids = list(dict.fromkeys(str(c).strip() for c in client_ids if str(c).strip()))
    u_names = list(dict.fromkeys(str(u).strip() for u in users if str(u).strip()))

    user_pw_map: Dict[str, str] = {}
    for uname in u_names:
        if explicit_user_passwords and uname in explicit_user_passwords:
            user_pw_map[uname] = str(explicit_user_passwords[uname])
        else:
            user_pw_map[uname] = secrets.token_urlsafe(20)

    client_sec_map: Dict[str, str] = {}
    for cid in c_ids:
        if explicit_client_secrets and cid in explicit_client_secrets:
            client_sec_map[cid] = str(explicit_client_secrets[cid])
        else:
            client_sec_map[cid] = secrets.token_urlsafe(24)

    sub_mapper: Dict[str, Any] = {
        "name": "sub-claim-mapper",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-sub-mapper",
        "consentRequired": False,
        "config": {
            "access.token.claim": "true",
            "introspection.token.claim": "true",
        },
    }
    username_mapper: Dict[str, Any] = {
        "name": "preferred-username-mapper",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-property-mapper",
        "consentRequired": False,
        "config": {
            "user.attribute": "username",
            "claim.name": "preferred_username",
            "jsonType.label": "String",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
        },
    }
    lct_sub_mapper: Dict[str, Any] = {
        "name": "lct-sub-attribute-mapper",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-attribute-mapper",
        "consentRequired": False,
        "config": {
            "user.attribute": "lct_sub",
            "claim.name": "lct_sub",
            "jsonType.label": "String",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
        },
    }

    client_scopes: List[Dict[str, Any]] = [
        {
            "name": sc_name,
            "description": f"Flat OAuth 2.0 capability scope {sc_name}",
            "protocol": "openid-connect",
            "attributes": {
                "include.in.token.scope": "true",
                "display.on.consent.screen": "false",
            },
        }
        for sc_name in DEFAULT_FLAT_OAUTH_SCOPES
    ]

    kc_clients: List[Dict[str, Any]] = []
    for cid in c_ids:
        mappers = [sub_mapper, username_mapper, lct_sub_mapper] + [
            _audience_mapper(other) for other in c_ids
        ]
        kc_clients.append(
            {
                "clientId": cid,
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": False,
                "secret": client_sec_map[cid],
                "directAccessGrantsEnabled": True,
                "serviceAccountsEnabled": True,
                "standardFlowEnabled": False,
                "fullScopeAllowed": True,
                "defaultClientScopes": [
                    "openid",
                    *DEFAULT_FLAT_OAUTH_SCOPES,
                ],
                "optionalClientScopes": ["offline_access"],
                "attributes": {
                    "standard.token.exchange.enabled": "true",
                },
                "protocolMappers": mappers,
            }
        )

    kc_users: List[Dict[str, Any]] = []
    clean_realm_td = realm_trust_domain.strip().lower() if realm_trust_domain else None
    for uname in u_names:
        home_td = DEFAULT_USER_HOME_DOMAINS.get(uname, clean_realm_td or "org-alpha.io")
        if clean_realm_td and home_td != clean_realm_td:
            continue
        kc_users.append(
            {
                "username": uname,
                "enabled": True,
                "emailVerified": True,
                "firstName": uname.capitalize(),
                "lastName": "User",
                "email": f"{uname}@{home_td}",
                "attributes": {
                    "lct_sub": [f"user:{uname}@{home_td}"],
                },
                "credentials": [
                    {
                        "type": "password",
                        "value": user_pw_map[uname],
                        "temporary": False,
                    }
                ],
            }
        )

    realm_doc: Dict[str, Any] = {
        "realm": realm_name,
        "enabled": True,
        "sslRequired": "none",
        "accessTokenLifespan": int(access_token_lifespan_sec),
        "clientScopes": client_scopes,
        "users": kc_users,
        "clients": kc_clients,
    }
    return GeneratedRealmBundle(
        realm_name=realm_name,
        admin_username="kcadmin",
        admin_password=secrets.token_urlsafe(24),
        user_passwords=user_pw_map,
        client_secrets=client_sec_map,
        realm_dict=realm_doc,
    )
