"""Multi-Host Identity-Addressed Federation Configuration, Port Allocator, Secret & CLI Utilities."""

from __future__ import annotations

from typing import Any

__all__ = [
    "FORBIDDEN_HOST_PORTS",
    "NODEPORT_MAX",
    "NODEPORT_MIN",
    "ROLE_ORDER",
    "ROLE_SPECS",
    "RoleSpec",
    "allocate_role_ports",
    "evaluate_http_date_clock_skew",
    "generate_domain_ca_secret_bundle",
    "is_host_tcp_port_free",
    "parse_port_overrides",
    "parse_roles_csv",
    "read_cluster_role_ports",
    "read_kind_node_published_ports",
    "render_e2e_sync_service_manifest",
    "render_kind_cluster_config",
    "render_role_k8s_manifests",
    "sanitize_coredns_corefile",
    "validate_ipv4_address",
]


def __getattr__(name: str) -> Any:
    if name in __all__:
        from lineage.multihost import config_gen

        return getattr(config_gen, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
