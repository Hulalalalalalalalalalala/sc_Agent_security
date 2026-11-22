"""Multi-domain SPIFFE workload identities and federated Trust Bundle resolution."""

from lineage.identity.spiffe import (
    IdentityError,
    SpiffeId,
    TrustDomainCA,
    WorkloadIdentity,
)
from lineage.identity.trust_bundle import TrustBundleResolver

__all__ = [
    "IdentityError",
    "SpiffeId",
    "TrustDomainCA",
    "WorkloadIdentity",
    "TrustBundleResolver",
]
