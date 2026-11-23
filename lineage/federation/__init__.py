"""Physical Multi-Domain Autonomous Control Plane & Cross-Organization Federation."""

from lineage.federation.anchors import (
    TrustAnchorPinError,
    TrustAnchorPinStore,
    compute_bundle_trust_anchor,
    extract_canonical_bundle_root_pem,
    format_domain_trust_anchor_line,
    parse_env_trust_anchors,
    parse_trust_anchor_value,
)
from lineage.federation.domain_ca import AutonomousDomainCAService
from lineage.federation.sync import (
    FederationBundleSyncer,
    FederationSecurityError,
    WorkloadIdentityRenewer,
    bootstrap_autonomous_workload,
    parse_domain_url_map,
)

__all__ = [
    "AutonomousDomainCAService",
    "FederationBundleSyncer",
    "FederationSecurityError",
    "TrustAnchorPinError",
    "TrustAnchorPinStore",
    "WorkloadIdentityRenewer",
    "bootstrap_autonomous_workload",
    "compute_bundle_trust_anchor",
    "extract_canonical_bundle_root_pem",
    "format_domain_trust_anchor_line",
    "parse_domain_url_map",
    "parse_env_trust_anchors",
    "parse_trust_anchor_value",
]
