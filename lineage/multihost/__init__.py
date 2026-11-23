"""Multi-Host Physical Federation Configuration, CoreDNS, Secret & CLI Utilities."""

from __future__ import annotations

from typing import Any

__all__ = [
    "FORBIDDEN_HOST_PORTS",
    "ROLE_ORDER",
    "ROLE_SPECS",
    "RoleSpec",
    "build_fqdn_ip_map",
    "evaluate_http_date_clock_skew",
    "generate_domain_ca_secret_bundle",
    "parse_roles_csv",
    "patch_coredns_corefile",
    "render_e2e_sync_service_manifest",
    "render_kind_cluster_config",
    "render_role_k8s_manifests",
    "validate_ipv4_address",
]


def __getattr__(name: str) -> Any:
    if name in __all__:
        from lineage.multihost import config_gen

        return getattr(config_gen, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
