"""Physical Multi-Domain Autonomous Control Plane & Cross-Organization Federation."""

from lineage.federation.domain_ca import AutonomousDomainCAService
from lineage.federation.sync import (
    FederationBundleSyncer,
    FederationSecurityError,
    bootstrap_autonomous_workload,
    parse_domain_url_map,
)

__all__ = [
    "AutonomousDomainCAService",
    "FederationBundleSyncer",
    "FederationSecurityError",
    "bootstrap_autonomous_workload",
    "parse_domain_url_map",
]
