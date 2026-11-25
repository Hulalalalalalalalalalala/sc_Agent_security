"""OAuth 2.0 RFC 8693 Token Exchange & Hop-0 OIDC/Keycloak Bridge Package."""

from lineage.oauth_sts.client import (
    OAuthTokenExchangeClient,
    OIDCTokenVerifier,
    TokenExchangeOutcome,
    VerifiedOIDCToken,
)
from lineage.oauth_sts.keycloak_realm import (
    DEFAULT_FLAT_OAUTH_SCOPES,
    DEFAULT_REALM_NAME,
    DEFAULT_USER_HOME_DOMAINS,
    KEYCLOAK_IMAGE,
    STANDARD_OAUTH_CLIENT_IDS,
    GeneratedRealmBundle,
    generate_keycloak_realm_bundle,
    spiffe_id_to_oauth_client_id,
)
from lineage.oauth_sts.service import (
    CLIENT_ASSERTION_JWT_BEARER,
    CLIENT_ASSERTION_JWT_SPIFFE,
    GRANT_TOKEN_EXCHANGE,
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_ID,
    OAuthSTSError,
    OAuthSTSService,
)

__all__ = [
    "CLIENT_ASSERTION_JWT_BEARER",
    "CLIENT_ASSERTION_JWT_SPIFFE",
    "DEFAULT_FLAT_OAUTH_SCOPES",
    "DEFAULT_REALM_NAME",
    "DEFAULT_USER_HOME_DOMAINS",
    "GRANT_TOKEN_EXCHANGE",
    "GeneratedRealmBundle",
    "KEYCLOAK_IMAGE",
    "OAuthSTSError",
    "OAuthSTSService",
    "OAuthTokenExchangeClient",
    "OIDCTokenVerifier",
    "STANDARD_OAUTH_CLIENT_IDS",
    "TOKEN_TYPE_ACCESS",
    "TOKEN_TYPE_ID",
    "TokenExchangeOutcome",
    "VerifiedOIDCToken",
    "generate_keycloak_realm_bundle",
    "spiffe_id_to_oauth_client_id",
]
