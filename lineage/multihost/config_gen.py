"""Multi-Host Kind Config, CoreDNS Zone Patcher, Role Manifests & In-Memory CA Bootstrapper.

Covers:
1. Per-role Kind cluster configs (`lctmh-alpha`, `lctmh-beta`, `lctmh-pay`, `lctmh-audit`)
   with `extraPortMappings` (`containerPort == hostPort == NodePort`, `listenAddress: 0.0.0.0`)
   and strictly disjoint Pod/Service CIDRs; internal issuance/registration ports (`8090`,
   `8091`, `8092`, `9001`, `8081`) are NEVER host-published.
2. Strict IPv4 validation and idempotent CoreDNS `hosts { ... fallthrough }` patching
   preserving `cluster.local` isolation and `host.docker.internal` entries.
3. Parameterized multi-host Kubernetes manifests with startup-order-independent `/healthz`
   liveness vs `/readyz` readiness probes, ConfigMap `lct-trust-anchors` hot-reload mounts,
   TLS 1.3 `audit-collector`, and configurable SVID renewal TTL.
4. Pure in-memory Domain CA root key generation streamed directly to `kubectl apply -f -`
   via stdin without touching host disk or logs.
5. RFC 9110 HTTP `Date` clock-skew evaluation (`warn > 10s`, `fail > 25s`).
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import email.utils
import ipaddress
import json
import re
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import yaml

from lineage.common.crypto import KeyPair
from lineage.common.mtls import X509DomainAuthority
from lineage.federation.anchors import (
    compute_bundle_trust_anchor,
    format_domain_trust_anchor_line,
)
from lineage.identity.spiffe import TrustDomainCA

FORBIDDEN_HOST_PORTS: Tuple[int, ...] = (8080, 8081, 8090, 8091, 8092, 8093, 8094, 8443, 8491, 8492, 9001)
ROLE_ORDER: Tuple[str, ...] = ("alpha", "beta", "pay", "audit")


@dataclass(frozen=True)
class RoleSpec:
    role: str
    cluster_name: str
    kube_context: str
    namespace: str
    trust_domain: str
    ca_short_prefix: str
    pod_cidr: str
    service_cidr: str
    host_ports: Tuple[int, ...]
    ca_fed_nodeport: Optional[int]


ROLE_SPECS: Dict[str, RoleSpec] = {
    "alpha": RoleSpec(
        role="alpha",
        cluster_name="lctmh-alpha",
        kube_context="kind-lctmh-alpha",
        namespace="lineage-alpha",
        trust_domain="org-alpha.io",
        ca_short_prefix="alpha",
        pod_cidr="10.241.0.0/16",
        service_cidr="10.97.0.0/16",
        host_ports=(30094, 30491, 30492, 30441, 30990),
        ca_fed_nodeport=30094,
    ),
    "beta": RoleSpec(
        role="beta",
        cluster_name="lctmh-beta",
        kube_context="kind-lctmh-beta",
        namespace="lineage-beta",
        trust_domain="org-beta.io",
        ca_short_prefix="beta",
        pod_cidr="10.242.0.0/16",
        service_cidr="10.98.0.0/16",
        host_ports=(31094, 31491, 31492, 31441, 31442, 31443),
        ca_fed_nodeport=31094,
    ),
    "pay": RoleSpec(
        role="pay",
        cluster_name="lctmh-pay",
        kube_context="kind-lctmh-pay",
        namespace="lineage-pay",
        trust_domain="org-payment.io",
        ca_short_prefix="payment",
        pod_cidr="10.243.0.0/16",
        service_cidr="10.99.0.0/16",
        host_ports=(32094, 32491, 32492, 32441, 32442, 32443),
        ca_fed_nodeport=32094,
    ),
    "audit": RoleSpec(
        role="audit",
        cluster_name="lctmh-audit",
        kube_context="kind-lctmh-audit",
        namespace="lineage-audit",
        trust_domain="org-audit.io",
        ca_short_prefix="audit",
        pod_cidr="10.244.0.0/16",
        service_cidr="10.100.0.0/16",
        host_ports=(30893,),
        ca_fed_nodeport=30893,
    ),
}

DOMAIN_FQDNS: Dict[str, Tuple[str, ...]] = {
    "alpha": (
        "alpha-ca.org-alpha.io",
        "alpha-directory.org-alpha.io",
        "alpha-revocation.org-alpha.io",
        "orchestrator-alpha.org-alpha.io",
        "e2e-user-gateway.org-alpha.io",
    ),
    "beta": (
        "beta-ca.org-beta.io",
        "beta-directory.org-beta.io",
        "beta-revocation.org-beta.io",
        "flight-specialist.org-beta.io",
        "hotel-specialist-primary.org-beta.io",
        "hotel-specialist-backup.org-beta.io",
    ),
    "pay": (
        "payment-ca.org-payment.io",
        "payment-directory.org-payment.io",
        "payment-revocation.org-payment.io",
        "settlement-converger.org-payment.io",
        "travel-ops-mcp.org-payment.io",
        "payment-vault-mcp.org-payment.io",
    ),
    "audit": ("audit-collector.org-audit.io",),
}

_ALL_LCT_FQDNS = frozenset(h for hosts in DOMAIN_FQDNS.values() for h in hosts)
_STRICT_IPV4_RE = re.compile(r"^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$")


def parse_roles_csv(roles_spec: str) -> Tuple[str, ...]:
    """Parse `--roles alpha,audit|beta|pay|all` into deduplicated canonical role names."""
    if not isinstance(roles_spec, str) or not roles_spec.strip():
        raise ValueError("--roles must be a non-empty comma-separated list (e.g., alpha,audit)")
    raw_items = [r.strip().lower() for r in roles_spec.split(",") if r.strip()]
    if not raw_items:
        raise ValueError("--roles must contain at least one role")
    if "all" in raw_items:
        return ROLE_ORDER
    seen: List[str] = []
    for item in raw_items:
        if item not in ROLE_SPECS:
            raise ValueError(
                f"Unknown role {item!r}; valid roles are { ','.join(ROLE_ORDER) } or 'all'"
            )
        if item not in seen:
            seen.append(item)
    return tuple(seen)


def validate_ipv4_address(
    ip_str: str, flag_name: str = "ip", allow_loopback: bool = False
) -> str:
    """Strictly validate dotted-quad IPv4 host address (rejecting IPv6, CIDR, 0.0.0.0, 127/8)."""
    if not isinstance(ip_str, str):
        raise ValueError(f"{flag_name} must be an IPv4 address string, got {ip_str!r}")
    s = ip_str.strip()
    if not _STRICT_IPV4_RE.match(s):
        raise ValueError(
            f"Invalid {flag_name}={ip_str!r}: must be strict dotted-quad IPv4 without leading zeros or CIDR"
        )
    try:
        addr = ipaddress.IPv4Address(s)
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"Invalid {flag_name}={ip_str!r}: {exc}") from exc
    if addr.is_unspecified or str(addr) == "255.255.255.255" or addr.is_multicast:
        raise ValueError(
            f"Invalid {flag_name}={s!r}: unspecified, broadcast, and multicast addresses are forbidden"
        )
    if addr.is_loopback and not allow_loopback:
        raise ValueError(
            f"Invalid {flag_name}={s!r}: loopback 127.0.0.0/8 resolves inside container netns, not host NIC; pass the machine's LAN/VPN IPv4"
        )
    return str(addr)


def render_kind_cluster_config(role: str) -> str:
    """Generate Kind `v1alpha4` YAML with exact `extraPortMappings` and disjoint CIDRs."""
    if role not in ROLE_SPECS:
        raise ValueError(f"Unknown role: {role!r}")
    spec = ROLE_SPECS[role]
    port_mappings = []
    for p in spec.host_ports:
        if p in FORBIDDEN_HOST_PORTS:
            raise AssertionError(f"Internal port {p} must never be host-published")
        port_mappings.append(
            {
                "containerPort": p,
                "hostPort": p,
                "listenAddress": "0.0.0.0",
                "protocol": "TCP",
            }
        )
    doc = {
        "kind": "Cluster",
        "apiVersion": "kind.x-k8s.io/v1alpha4",
        "networking": {
            "podSubnet": spec.pod_cidr,
            "serviceSubnet": spec.service_cidr,
        },
        "nodes": [
            {
                "role": "control-plane",
                "extraPortMappings": port_mappings,
            }
        ],
    }
    return yaml.safe_dump(doc, sort_keys=False)


def build_fqdn_ip_map(
    alpha_ip: str,
    beta_ip: str,
    pay_ip: str,
    audit_ip: Optional[str] = None,
) -> Dict[str, str]:
    """Build validated `FQDN -> machine IPv4` mapping across all 4 autonomous domains."""
    a_ip = validate_ipv4_address(alpha_ip, "--alpha-ip")
    b_ip = validate_ipv4_address(beta_ip, "--beta-ip")
    p_ip = validate_ipv4_address(pay_ip, "--pay-ip")
    aud_ip = (
        validate_ipv4_address(audit_ip, "--audit-ip")
        if (audit_ip and audit_ip.strip())
        else a_ip
    )
    mapping: Dict[str, str] = {}
    for fqdn in DOMAIN_FQDNS["alpha"]:
        mapping[fqdn] = a_ip
    for fqdn in DOMAIN_FQDNS["beta"]:
        mapping[fqdn] = b_ip
    for fqdn in DOMAIN_FQDNS["pay"]:
        mapping[fqdn] = p_ip
    for fqdn in DOMAIN_FQDNS["audit"]:
        mapping[fqdn] = aud_ip
    return mapping


def patch_coredns_corefile(
    existing_corefile: str,
    alpha_ip: str,
    beta_ip: str,
    pay_ip: str,
    audit_ip: Optional[str] = None,
) -> str:
    """Idempotently inject/update LCT multi-host FQDN lines inside CoreDNS `hosts { ... }`.

    Guarantees:
    - At most ONE `hosts { ... }` plugin block in `.:53` (preventing CoreDNS duplicate
      plugin errors when Kind pre-populates `host.docker.internal`).
    - Any pre-existing non-LCT host entries (such as `host.docker.internal`) are preserved.
    - `kubernetes cluster.local` remains untouched and isolated per cluster.
    """
    a_ip = validate_ipv4_address(alpha_ip, "--alpha-ip")
    b_ip = validate_ipv4_address(beta_ip, "--beta-ip")
    p_ip = validate_ipv4_address(pay_ip, "--pay-ip")
    aud_ip = (
        validate_ipv4_address(audit_ip, "--audit-ip")
        if (audit_ip and audit_ip.strip())
        else a_ip
    )
    if "kubernetes cluster.local" not in existing_corefile:
        raise ValueError(f"Unexpected CoreDNS Corefile missing 'kubernetes cluster.local':\n{existing_corefile}")

    lct_lines = [
        f"        {a_ip} {' '.join(DOMAIN_FQDNS['alpha'])}",
        f"        {b_ip} {' '.join(DOMAIN_FQDNS['beta'])}",
        f"        {p_ip} {' '.join(DOMAIN_FQDNS['pay'])}",
        f"        {aud_ip} {' '.join(DOMAIN_FQDNS['audit'])}",
    ]

    hosts_match = re.search(r"(^[ \t]*hosts\s*\{)([^}]*)(\})", existing_corefile, flags=re.MULTILINE | re.DOTALL)
    if hosts_match:
        preserved_lines: List[str] = []
        for raw_ln in hosts_match.group(2).splitlines():
            stripped = raw_ln.strip()
            if not stripped or stripped == "fallthrough" or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) >= 2:
                ip_tok = parts[0]
                kept_names = [n for n in parts[1:] if n.lower() not in _ALL_LCT_FQDNS]
                if kept_names:
                    preserved_lines.append(f"        {ip_tok} {' '.join(kept_names)}")
        merged_body = "\n".join([*preserved_lines, *lct_lines, "        fallthrough"])
        new_block = f"    hosts {{\n{merged_body}\n    }}"
        return (
            existing_corefile[: hosts_match.start()]
            + new_block
            + existing_corefile[hosts_match.end() :]
        )

    new_hosts_block = "    hosts {\n" + "\n".join([*lct_lines, "        fallthrough"]) + "\n    }"
    return re.sub(
        r"([ \t]*kubernetes\s+cluster\.local)",
        new_hosts_block + r"\n\1",
        existing_corefile,
        count=1,
    )


def evaluate_http_date_clock_skew(
    http_date_header: str,
    local_epoch: Optional[float] = None,
    warn_threshold_sec: float = 10.0,
    fail_threshold_sec: float = 25.0,
) -> Dict[str, Any]:
    """Compare peer RFC 9110 HTTP `Date` header against local UTC wall clock."""
    if not isinstance(http_date_header, str) or not http_date_header.strip():
        raise ValueError("Empty HTTP Date header")
    parsed_dt = email.utils.parsedate_to_datetime(http_date_header.strip())
    if parsed_dt.tzinfo is None:
        parsed_dt = parsed_dt.replace(tzinfo=dt.timezone.utc)
    peer_epoch = parsed_dt.timestamp()
    now_ts = time.time() if local_epoch is None else float(local_epoch)
    skew = peer_epoch - now_ts
    abs_skew = abs(skew)
    if abs_skew > fail_threshold_sec:
        status = "FAIL"
    elif abs_skew > warn_threshold_sec:
        status = "WARN"
    else:
        status = "OK"
    return {
        "status": status,
        "ok": status != "FAIL",
        "peer_epoch": round(peer_epoch, 3),
        "local_epoch": round(now_ts, 3),
        "skew_seconds": round(skew, 3),
        "abs_skew_seconds": round(abs_skew, 3),
        "warn_threshold_sec": warn_threshold_sec,
        "fail_threshold_sec": fail_threshold_sec,
    }


def generate_domain_ca_secret_bundle(role: str) -> Tuple[List[Dict[str, Any]], str, str]:
    """Generate stable per-deployment CA root K8s Secret manifest(s) purely in RAM.

    Returns `(secret_manifests_list, trust_domain, formatted_anchor_line)`.
    Note: for `audit`, generates `audit-ca-keys` (X.509-only, zero JWKS signing keys,
    mounted ONLY into `audit-ca`) + `audit-csr-auth` (random bootstrap token for
    `audit-collector`, holding zero CA keys and zero K8s SA tokens).
    """
    if role not in ROLE_SPECS:
        raise ValueError(f"Unknown role: {role!r}")
    spec = ROLE_SPECS[role]

    if role == "audit":
        x509_ca = X509DomainAuthority(
            spec.trust_domain,
            allowed_dns_suffixes=(
                f".{spec.namespace}.svc.cluster.local",
                f".{spec.namespace}.svc",
                f".{spec.trust_domain}",
                spec.trust_domain,
                "localhost",
            ),
        )
        root_pem = x509_ca.export_root_pem()
        pub_bundle = {
            "trust_domain": spec.trust_domain,
            "keys": [],
            "x509_root_pem": root_pem,
        }
        anchor_val = compute_bundle_trust_anchor(pub_bundle, allow_keyless_jwks=True)
        anchor_line = format_domain_trust_anchor_line(spec.trust_domain, anchor_val)
        ca_sec = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "audit-ca-keys",
                "namespace": spec.namespace,
                "annotations": {"lct.io/trust-anchor": anchor_val},
            },
            "type": "Opaque",
            "stringData": {
                "x509_private_key.pem": x509_ca.export_private_key_pem(),
                "x509_root_cert.pem": root_pem,
            },
        }
        csr_sec = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "audit-csr-auth",
                "namespace": spec.namespace,
            },
            "type": "Opaque",
            "stringData": {
                "csr_token": secrets.token_urlsafe(36),
            },
        }
        return [ca_sec, csr_sec], spec.trust_domain, anchor_line

    ca = TrustDomainCA(spec.trust_domain, alg="ES256")
    x509_ca = X509DomainAuthority(
        spec.trust_domain,
        allowed_dns_suffixes=(
            f".{spec.namespace}.svc.cluster.local",
            f".{spec.namespace}.svc",
            f".{spec.trust_domain}",
            spec.trust_domain,
            "localhost",
        ),
    )
    root_pem = x509_ca.export_root_pem()
    pub_bundle = ca.export_public_bundle()
    pub_bundle["x509_root_pem"] = root_pem
    anchor_val = compute_bundle_trust_anchor(pub_bundle)
    anchor_line = format_domain_trust_anchor_line(spec.trust_domain, anchor_val)
    sec_manifest = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": f"{spec.ca_short_prefix}-ca-keys",
            "namespace": spec.namespace,
            "annotations": {"lct.io/trust-anchor": anchor_val},
        },
        "type": "Opaque",
        "stringData": {
            "ca_private_key.pem": ca.active_keypair.export_private_pem(),
            "x509_private_key.pem": x509_ca.export_private_key_pem(),
            "x509_root_cert.pem": root_pem,
        },
    }
    return [sec_manifest], spec.trust_domain, anchor_line


def _agent_or_tool_deployment_docs(
    *,
    namespace: str,
    trust_domain: str,
    name: str,
    image: str,
    app_role: str,
    local_ca_url: str,
    peer_ca_urls: str,
    dir_url: str,
    rev_url: str,
    audit_url: str,
    public_origin: str,
    node_port: int,
    svid_ttl_seconds: int,
    require_pinned_anchors: bool,
    llm_url: Optional[str] = None,
    llm_model: Optional[str] = None,
    is_tool_server: bool = False,
    agent_skills: Optional[str] = None,
    agent_priority: Optional[int] = None,
    agent_display_name: Optional[str] = None,
    enable_fault_injection: bool = False,
    specialist_instance: Optional[str] = None,
    travel_mcp_url: Optional[str] = None,
    payment_mcp_url: Optional[str] = None,
) -> List[Dict[str, Any]]:
    sa_doc = {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"name": name, "namespace": namespace},
    }
    app_env: List[Dict[str, str]] = []
    if specialist_instance:
        app_env.append({"name": "SPECIALIST_INSTANCE", "value": specialist_instance})
    if llm_url:
        app_env.append({"name": "OLLAMA_BASE_URL", "value": llm_url})
    if llm_model:
        app_env.append({"name": "LLM_MODEL", "value": llm_model})
    if travel_mcp_url:
        app_env.append({"name": "TRAVEL_MCP_URL", "value": travel_mcp_url})
    if payment_mcp_url:
        app_env.append({"name": "PAYMENT_MCP_URL", "value": payment_mcp_url})
    if enable_fault_injection:
        app_env.append({"name": "LCT_ENABLE_FAULT_INJECTION", "value": "true"})

    sidecar_env: List[Dict[str, str]] = [
        {"name": "LOCAL_CA_URL", "value": local_ca_url},
        {"name": "PEER_CA_URLS", "value": peer_ca_urls},
        {"name": "DIRECTORY_URL", "value": dir_url},
        {"name": "REVOCATION_URL", "value": rev_url},
        {"name": "AUDIT_COLLECTOR_URL", "value": audit_url},
        {"name": "PUBLIC_ORIGIN", "value": public_origin},
        {"name": "SIDECAR_INBOUND_PORT", "value": "8443"},
        {"name": "LCT_MTLS_RAM_DIR", "value": "/var/run/lct-mtls-ram"},
        {"name": "LCT_TRUST_ANCHORS_DIR", "value": "/etc/lct-anchors"},
        {
            "name": "LCT_REQUIRE_PINNED_ANCHORS",
            "value": "true" if require_pinned_anchors else "false",
        },
        {"name": "LCT_WAIT_FOR_PEERS_ON_BOOT", "value": "false"},
        {"name": "LCT_SVID_TTL_SECONDS", "value": str(int(svid_ttl_seconds))},
    ]
    if is_tool_server:
        sidecar_env.append({"name": "IS_TOOL_SERVER", "value": "true"})
        sidecar_env.append({"name": "VERIFICATION_MODE", "value": "ADAPTIVE_RISK_ANCHORED"})
    else:
        sidecar_env.append({"name": "AGENT_SKILLS", "value": agent_skills or "agent.generic"})
        sidecar_env.append({"name": "AGENT_PRIORITY", "value": str(agent_priority or 50)})
        sidecar_env.append({"name": "AGENT_DISPLAY_NAME", "value": agent_display_name or name})
    if enable_fault_injection:
        sidecar_env.append({"name": "LCT_ENABLE_FAULT_INJECTION", "value": "true"})

    app_container: Dict[str, Any] = {
        "name": "app",
        "image": image,
        "imagePullPolicy": "Never",
        "args": ["--role", app_role],
        "volumeMounts": [
            {"name": "lct-loopback", "mountPath": "/var/run/lct-loopback", "readOnly": True}
        ],
        "livenessProbe": {
            "exec": {
                "command": [
                    "/app/.venv/bin/python3",
                    "-c",
                    "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9001/healthz', timeout=2)",
                ]
            },
            "initialDelaySeconds": 15,
            "periodSeconds": 10,
            "failureThreshold": 5,
        },
    }
    if app_env:
        app_container["env"] = app_env

    dep_doc = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {
                    "labels": {"app": name, "lct.io/trust-domain": trust_domain}
                },
                "spec": {
                    "serviceAccountName": name,
                    "automountServiceAccountToken": False,
                    "volumes": [
                        {"name": "lct-loopback", "emptyDir": {"medium": "Memory"}},
                        {"name": "lct-mtls-ram", "emptyDir": {"medium": "Memory"}},
                        {
                            "name": "lct-trust-anchors",
                            "configMap": {"name": "lct-trust-anchors", "optional": True},
                        },
                        {
                            "name": "lct-sa-token",
                            "projected": {
                                "sources": [
                                    {
                                        "serviceAccountToken": {
                                            "path": "token",
                                            "expirationSeconds": 600,
                                            "audience": "lct-federation-ca",
                                        }
                                    },
                                    {
                                        "configMap": {
                                            "name": "kube-root-ca.crt",
                                            "items": [{"key": "ca.crt", "path": "ca.crt"}],
                                        }
                                    },
                                ]
                            },
                        },
                    ],
                    "containers": [
                        app_container,
                        {
                            "name": "lct-sidecar",
                            "image": image,
                            "imagePullPolicy": "Never",
                            "args": ["--role", "sidecar"],
                            "env": sidecar_env,
                            "ports": [{"containerPort": 8443, "name": "lct-mtls"}],
                            "volumeMounts": [
                                {"name": "lct-loopback", "mountPath": "/var/run/lct-loopback"},
                                {"name": "lct-mtls-ram", "mountPath": "/var/run/lct-mtls-ram"},
                                {
                                    "name": "lct-trust-anchors",
                                    "mountPath": "/etc/lct-anchors",
                                    "readOnly": True,
                                },
                                {
                                    "name": "lct-sa-token",
                                    "mountPath": "/var/run/lct-sa",
                                    "readOnly": True,
                                },
                            ],
                            "livenessProbe": {
                                "exec": {
                                    "command": [
                                        "/app/.venv/bin/python3",
                                        "-c",
                                        "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8081/healthz', timeout=2)",
                                    ]
                                },
                                "initialDelaySeconds": 15,
                                "periodSeconds": 10,
                                "failureThreshold": 5,
                            },
                            "readinessProbe": {
                                "exec": {
                                    "command": [
                                        "/app/.venv/bin/python3",
                                        "-c",
                                        "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8081/readyz', timeout=2)",
                                    ]
                                },
                                "initialDelaySeconds": 2,
                                "periodSeconds": 2,
                            },
                        },
                    ],
                },
            },
        },
    }
    svc_doc = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "type": "NodePort",
            "selector": {"app": name},
            "ports": [
                {
                    "name": "lct-mtls",
                    "port": 8443,
                    "targetPort": 8443,
                    "nodePort": node_port,
                }
            ],
        },
    }
    return [sa_doc, dep_doc, svc_doc]


def _domain_control_plane_docs(
    *,
    spec: RoleSpec,
    image: str,
    peer_ca_urls: str,
    peer_dir_urls: str,
    peer_rev_urls: str,
    audit_url: str,
    dir_fed_nodeport: int,
    rev_fed_nodeport: int,
    svid_ttl_seconds: int,
    require_pinned_anchors: bool,
    authorized_gateway_sa: Optional[str] = None,
) -> List[Dict[str, Any]]:
    ns = spec.namespace
    td = spec.trust_domain
    pfx = spec.ca_short_prefix
    ca_name = f"{pfx}-ca"
    rev_name = f"{pfx}-revocation"
    dir_name = f"{pfx}-directory"
    local_ca_url = f"http://{ca_name}.{ns}.svc.cluster.local:8090"
    local_rev_url = f"http://{rev_name}.{ns}.svc.cluster.local:8092"

    ca_env = [
        {"name": "TRUST_DOMAIN", "value": td},
        {"name": "ALLOWED_K8S_NAMESPACE", "value": ns},
        {"name": "CA_FEDERATION_PORT", "value": "8094"},
        {"name": "CA_KEY_MATERIAL_DIR", "value": "/var/run/lct-ca-keys"},
        {"name": "AUDIT_COLLECTOR_URL", "value": audit_url},
        {"name": "LCT_TRUST_ANCHORS_DIR", "value": "/etc/lct-anchors"},
        {
            "name": "LCT_REQUIRE_PINNED_ANCHORS",
            "value": "true" if require_pinned_anchors else "false",
        },
        {"name": "LCT_WAIT_FOR_PEERS_ON_BOOT", "value": "false"},
    ]
    if authorized_gateway_sa:
        ca_env.append({"name": "AUTHORIZED_GATEWAY_SA", "value": authorized_gateway_sa})

    docs: List[Dict[str, Any]] = [
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": ca_name, "namespace": ns},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": ca_name, "namespace": ns},
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": ca_name}},
                "template": {
                    "metadata": {"labels": {"app": ca_name, "lct.io/trust-domain": td}},
                    "spec": {
                        "serviceAccountName": ca_name,
                        "automountServiceAccountToken": False,
                        "securityContext": {"fsGroup": 2000},
                        "volumes": [
                            {
                                "name": "ca-root-keys",
                                "secret": {
                                    "secretName": f"{pfx}-ca-keys",
                                    "defaultMode": 0o440,
                                },
                            },
                            {
                                "name": "lct-trust-anchors",
                                "configMap": {"name": "lct-trust-anchors", "optional": True},
                            },
                            {
                                "name": "lct-sa-token",
                                "projected": {
                                    "sources": [
                                        {
                                            "serviceAccountToken": {
                                                "path": "k8s-api-token",
                                                "expirationSeconds": 600,
                                            }
                                        },
                                        {
                                            "configMap": {
                                                "name": "kube-root-ca.crt",
                                                "items": [{"key": "ca.crt", "path": "ca.crt"}],
                                            }
                                        },
                                    ]
                                },
                            },
                        ],
                        "containers": [
                            {
                                "name": ca_name,
                                "image": image,
                                "imagePullPolicy": "Never",
                                "args": ["--role", "domain-ca"],
                                "env": ca_env,
                                "ports": [
                                    {"containerPort": 8090, "name": "ca-internal"},
                                    {"containerPort": 8094, "name": "ca-fed-ro"},
                                ],
                                "volumeMounts": [
                                    {
                                        "name": "ca-root-keys",
                                        "mountPath": "/var/run/lct-ca-keys",
                                        "readOnly": True,
                                    },
                                    {
                                        "name": "lct-trust-anchors",
                                        "mountPath": "/etc/lct-anchors",
                                        "readOnly": True,
                                    },
                                    {
                                        "name": "lct-sa-token",
                                        "mountPath": "/var/run/lct-sa",
                                        "readOnly": True,
                                    },
                                ],
                                "livenessProbe": {
                                    "httpGet": {"path": "/healthz", "port": 8090},
                                    "initialDelaySeconds": 2,
                                    "periodSeconds": 5,
                                },
                                "readinessProbe": {
                                    "httpGet": {"path": "/healthz", "port": 8090},
                                    "initialDelaySeconds": 1,
                                    "periodSeconds": 2,
                                },
                            }
                        ],
                    },
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": ca_name, "namespace": ns},
            "spec": {
                "type": "ClusterIP",
                "selector": {"app": ca_name},
                "ports": [{"name": "ca-internal", "port": 8090, "targetPort": 8090}],
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": f"{ca_name}-federation", "namespace": ns},
            "spec": {
                "type": "NodePort",
                "selector": {"app": ca_name},
                "ports": [
                    {
                        "name": "ca-fed-ro",
                        "port": 8094,
                        "targetPort": 8094,
                        "nodePort": int(spec.ca_fed_nodeport or 30094),
                    }
                ],
            },
        },
        # Revocation
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": rev_name, "namespace": ns},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": rev_name, "namespace": ns},
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": rev_name}},
                "template": {
                    "metadata": {"labels": {"app": rev_name, "lct.io/trust-domain": td}},
                    "spec": {
                        "serviceAccountName": rev_name,
                        "automountServiceAccountToken": False,
                        "volumes": [
                            {"name": "lct-mtls-ram", "emptyDir": {"medium": "Memory"}},
                            {
                                "name": "lct-trust-anchors",
                                "configMap": {"name": "lct-trust-anchors", "optional": True},
                            },
                            {
                                "name": "lct-sa-token",
                                "projected": {
                                    "sources": [
                                        {
                                            "serviceAccountToken": {
                                                "path": "token",
                                                "expirationSeconds": 600,
                                                "audience": "lct-federation-ca",
                                            }
                                        },
                                        {
                                            "configMap": {
                                                "name": "kube-root-ca.crt",
                                                "items": [{"key": "ca.crt", "path": "ca.crt"}],
                                            }
                                        },
                                    ]
                                },
                            },
                        ],
                        "containers": [
                            {
                                "name": rev_name,
                                "image": image,
                                "imagePullPolicy": "Never",
                                "args": ["--role", "domain-revocation"],
                                "env": [
                                    {"name": "LOCAL_CA_URL", "value": local_ca_url},
                                    {"name": "PEER_CA_URLS", "value": peer_ca_urls},
                                    {"name": "PEER_REVOCATION_URLS", "value": peer_rev_urls},
                                    {"name": "REVOCATION_FEDERATION_PORT", "value": "8492"},
                                    {"name": "LCT_MTLS_RAM_DIR", "value": "/var/run/lct-mtls-ram"},
                                    {"name": "LCT_TRUST_ANCHORS_DIR", "value": "/etc/lct-anchors"},
                                    {
                                        "name": "LCT_REQUIRE_PINNED_ANCHORS",
                                        "value": "true" if require_pinned_anchors else "false",
                                    },
                                    {"name": "LCT_WAIT_FOR_PEERS_ON_BOOT", "value": "false"},
                                    {"name": "LCT_SVID_TTL_SECONDS", "value": str(int(svid_ttl_seconds))},
                                ],
                                "ports": [
                                    {"containerPort": 8092, "name": "rev-internal"},
                                    {"containerPort": 8492, "name": "rev-fed-mtls"},
                                ],
                                "volumeMounts": [
                                    {"name": "lct-sa-token", "mountPath": "/var/run/lct-sa", "readOnly": True},
                                    {"name": "lct-mtls-ram", "mountPath": "/var/run/lct-mtls-ram"},
                                    {
                                        "name": "lct-trust-anchors",
                                        "mountPath": "/etc/lct-anchors",
                                        "readOnly": True,
                                    },
                                ],
                                "livenessProbe": {
                                    "httpGet": {"path": "/healthz", "port": 8092},
                                    "initialDelaySeconds": 15,
                                    "periodSeconds": 10,
                                    "failureThreshold": 5,
                                },
                                "readinessProbe": {
                                    "httpGet": {"path": "/readyz", "port": 8092},
                                    "initialDelaySeconds": 1,
                                    "periodSeconds": 2,
                                },
                            }
                        ],
                    },
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": rev_name, "namespace": ns},
            "spec": {
                "type": "ClusterIP",
                "publishNotReadyAddresses": True,
                "selector": {"app": rev_name},
                "ports": [{"name": "rev-internal", "port": 8092, "targetPort": 8092}],
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": f"{rev_name}-federation", "namespace": ns},
            "spec": {
                "type": "NodePort",
                "selector": {"app": rev_name},
                "ports": [
                    {
                        "name": "rev-fed-mtls",
                        "port": 8492,
                        "targetPort": 8492,
                        "nodePort": rev_fed_nodeport,
                    }
                ],
            },
        },
        # Directory
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": dir_name, "namespace": ns},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": dir_name, "namespace": ns},
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": dir_name}},
                "template": {
                    "metadata": {"labels": {"app": dir_name, "lct.io/trust-domain": td}},
                    "spec": {
                        "serviceAccountName": dir_name,
                        "automountServiceAccountToken": False,
                        "volumes": [
                            {"name": "lct-mtls-ram", "emptyDir": {"medium": "Memory"}},
                            {
                                "name": "lct-trust-anchors",
                                "configMap": {"name": "lct-trust-anchors", "optional": True},
                            },
                            {
                                "name": "lct-sa-token",
                                "projected": {
                                    "sources": [
                                        {
                                            "serviceAccountToken": {
                                                "path": "token",
                                                "expirationSeconds": 600,
                                                "audience": "lct-federation-ca",
                                            }
                                        },
                                        {
                                            "configMap": {
                                                "name": "kube-root-ca.crt",
                                                "items": [{"key": "ca.crt", "path": "ca.crt"}],
                                            }
                                        },
                                    ]
                                },
                            },
                        ],
                        "containers": [
                            {
                                "name": dir_name,
                                "image": image,
                                "imagePullPolicy": "Never",
                                "args": ["--role", "domain-directory"],
                                "env": [
                                    {"name": "LOCAL_CA_URL", "value": local_ca_url},
                                    {"name": "PEER_CA_URLS", "value": peer_ca_urls},
                                    {"name": "PEER_DIRECTORY_URLS", "value": peer_dir_urls},
                                    {"name": "REVOCATION_URL", "value": local_rev_url},
                                    {"name": "DIRECTORY_FEDERATION_PORT", "value": "8491"},
                                    {"name": "LCT_MTLS_RAM_DIR", "value": "/var/run/lct-mtls-ram"},
                                    {"name": "LCT_TRUST_ANCHORS_DIR", "value": "/etc/lct-anchors"},
                                    {
                                        "name": "LCT_REQUIRE_PINNED_ANCHORS",
                                        "value": "true" if require_pinned_anchors else "false",
                                    },
                                    {"name": "LCT_WAIT_FOR_PEERS_ON_BOOT", "value": "false"},
                                    {"name": "LCT_SVID_TTL_SECONDS", "value": str(int(svid_ttl_seconds))},
                                ],
                                "ports": [
                                    {"containerPort": 8091, "name": "dir-internal"},
                                    {"containerPort": 8491, "name": "dir-fed-mtls"},
                                ],
                                "volumeMounts": [
                                    {"name": "lct-sa-token", "mountPath": "/var/run/lct-sa", "readOnly": True},
                                    {"name": "lct-mtls-ram", "mountPath": "/var/run/lct-mtls-ram"},
                                    {
                                        "name": "lct-trust-anchors",
                                        "mountPath": "/etc/lct-anchors",
                                        "readOnly": True,
                                    },
                                ],
                                "livenessProbe": {
                                    "httpGet": {"path": "/healthz", "port": 8091},
                                    "initialDelaySeconds": 15,
                                    "periodSeconds": 10,
                                    "failureThreshold": 5,
                                },
                                "readinessProbe": {
                                    "httpGet": {"path": "/readyz", "port": 8091},
                                    "initialDelaySeconds": 1,
                                    "periodSeconds": 2,
                                },
                            }
                        ],
                    },
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": dir_name, "namespace": ns},
            "spec": {
                "type": "ClusterIP",
                "publishNotReadyAddresses": True,
                "selector": {"app": dir_name},
                "ports": [{"name": "dir-internal", "port": 8091, "targetPort": 8091}],
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": f"{dir_name}-federation", "namespace": ns},
            "spec": {
                "type": "NodePort",
                "selector": {"app": dir_name},
                "ports": [
                    {
                        "name": "dir-fed-mtls",
                        "port": 8491,
                        "targetPort": 8491,
                        "nodePort": dir_fed_nodeport,
                    }
                ],
            },
        },
    ]
    return docs


def render_e2e_sync_service_manifest(namespace: str = "lineage-alpha") -> Dict[str, Any]:
    """Render the transient NodePort `30990` Service created ONLY around Scenario 3B."""
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "e2e-user-gateway-sync", "namespace": namespace},
        "spec": {
            "type": "NodePort",
            "selector": {"app": "e2e-user-gateway"},
            "ports": [
                {
                    "name": "sync-hook",
                    "port": 19090,
                    "targetPort": 19090,
                    "nodePort": 30990,
                }
            ],
        },
    }


def render_role_k8s_manifests(
    role: str,
    image: str = "lineage-lct:m6",
    llm_url: str = "http://host.docker.internal:11434/v1",
    llm_model: str = "qwen2.5:3b",
    svid_ttl_seconds: int = 1800,
    require_pinned_anchors: bool = True,
    initial_anchors: Optional[Mapping[str, str]] = None,
    include_namespace_and_configmap: bool = True,
) -> str:
    """Render complete multi-document YAML manifest for a single multi-host role."""
    if role not in ROLE_SPECS:
        raise ValueError(f"Unknown role: {role!r}")
    spec = ROLE_SPECS[role]
    ns = spec.namespace
    audit_https_url = "https://audit-collector.org-audit.io:30893"
    travel_mcp_https = "https://travel-ops-mcp.org-payment.io:32442/mcp"
    payment_mcp_https = "https://payment-vault-mcp.org-payment.io:32443/mcp"

    docs: List[Dict[str, Any]] = []
    if include_namespace_and_configmap:
        docs.append(
            {
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": ns,
                    "labels": {"lct.io/trust-domain": spec.trust_domain},
                },
            }
        )
        docs.append(
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "lct-trust-anchors", "namespace": ns},
                "data": dict(initial_anchors or {}),
            }
        )

    if role == "audit":
        docs.extend(
            [
                {
                    "apiVersion": "v1",
                    "kind": "ServiceAccount",
                    "metadata": {"name": "audit-ca", "namespace": ns},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "audit-ca", "namespace": ns},
                    "spec": {
                        "replicas": 1,
                        "selector": {"matchLabels": {"app": "audit-ca"}},
                        "template": {
                            "metadata": {"labels": {"app": "audit-ca"}},
                            "spec": {
                                "serviceAccountName": "audit-ca",
                                "automountServiceAccountToken": False,
                                "securityContext": {"fsGroup": 2000},
                                "volumes": [
                                    {
                                        "name": "audit-ca-keys",
                                        "secret": {
                                            "secretName": "audit-ca-keys",
                                            "defaultMode": 0o440,
                                        },
                                    },
                                    {
                                        "name": "audit-csr-auth",
                                        "secret": {
                                            "secretName": "audit-csr-auth",
                                            "defaultMode": 0o440,
                                        },
                                    },
                                ],
                                "containers": [
                                    {
                                        "name": "audit-ca",
                                        "image": image,
                                        "imagePullPolicy": "Never",
                                        "args": ["--role", "audit-tls-ca"],
                                        "env": [
                                            {
                                                "name": "CA_KEY_MATERIAL_DIR",
                                                "value": "/var/run/lct-audit-ca-keys",
                                            },
                                            {
                                                "name": "AUDIT_CSR_TOKEN_FILE",
                                                "value": "/var/run/lct-audit-csr/csr_token",
                                            },
                                        ],
                                        "ports": [{"containerPort": 8090, "name": "ca-internal"}],
                                        "volumeMounts": [
                                            {
                                                "name": "audit-ca-keys",
                                                "mountPath": "/var/run/lct-audit-ca-keys",
                                                "readOnly": True,
                                            },
                                            {
                                                "name": "audit-csr-auth",
                                                "mountPath": "/var/run/lct-audit-csr",
                                                "readOnly": True,
                                            },
                                        ],
                                        "livenessProbe": {
                                            "httpGet": {"path": "/healthz", "port": 8090},
                                            "initialDelaySeconds": 1,
                                            "periodSeconds": 5,
                                        },
                                        "readinessProbe": {
                                            "httpGet": {"path": "/healthz", "port": 8090},
                                            "initialDelaySeconds": 1,
                                            "periodSeconds": 2,
                                        },
                                    }
                                ],
                            },
                        },
                    },
                },
                {
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": {"name": "audit-ca", "namespace": ns},
                    "spec": {
                        "type": "ClusterIP",
                        "selector": {"app": "audit-ca"},
                        "ports": [{"name": "ca-internal", "port": 8090, "targetPort": 8090}],
                    },
                },
                # Keyless `audit-collector`: ZERO CA keys and ZERO K8s SA tokens!
                {
                    "apiVersion": "v1",
                    "kind": "ServiceAccount",
                    "metadata": {"name": "audit-collector", "namespace": ns},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "audit-collector", "namespace": ns},
                    "spec": {
                        "replicas": 1,
                        "selector": {"matchLabels": {"app": "audit-collector"}},
                        "template": {
                            "metadata": {"labels": {"app": "audit-collector"}},
                            "spec": {
                                "serviceAccountName": "audit-collector",
                                "automountServiceAccountToken": False,
                                "securityContext": {"fsGroup": 2000},
                                "volumes": [
                                    {"name": "lct-mtls-ram", "emptyDir": {"medium": "Memory"}},
                                    {
                                        "name": "lct-trust-anchors",
                                        "configMap": {
                                            "name": "lct-trust-anchors",
                                            "optional": True,
                                        },
                                    },
                                    {
                                        "name": "audit-csr-auth",
                                        "secret": {
                                            "secretName": "audit-csr-auth",
                                            "defaultMode": 0o440,
                                        },
                                    },
                                ],
                                "containers": [
                                    {
                                        "name": "audit-collector",
                                        "image": image,
                                        "imagePullPolicy": "Never",
                                        "args": ["--role", "federated-audit-collector"],
                                        "env": [
                                            {
                                                "name": "PEER_CA_URLS",
                                                "value": (
                                                    "org-alpha.io=http://alpha-ca.org-alpha.io:30094,"
                                                    "org-beta.io=http://beta-ca.org-beta.io:31094,"
                                                    "org-payment.io=http://payment-ca.org-payment.io:32094"
                                                ),
                                            },
                                            {
                                                "name": "AUDIT_TLS_CA_URL",
                                                "value": f"http://audit-ca.{ns}.svc.cluster.local:8090",
                                            },
                                            {
                                                "name": "AUDIT_CSR_TOKEN_FILE",
                                                "value": "/var/run/lct-audit-csr/csr_token",
                                            },
                                            {
                                                "name": "LCT_MTLS_RAM_DIR",
                                                "value": "/var/run/lct-mtls-ram",
                                            },
                                            {
                                                "name": "LCT_TRUST_ANCHORS_DIR",
                                                "value": "/etc/lct-anchors",
                                            },
                                            {
                                                "name": "LCT_REQUIRE_PINNED_ANCHORS",
                                                "value": "true" if require_pinned_anchors else "false",
                                            },
                                            {"name": "LCT_WAIT_FOR_PEERS_ON_BOOT", "value": "false"},
                                            {
                                                "name": "LCT_SVID_TTL_SECONDS",
                                                "value": str(int(svid_ttl_seconds)),
                                            },
                                        ],
                                        "ports": [{"containerPort": 8093, "name": "https-audit"}],
                                        "volumeMounts": [
                                            {
                                                "name": "lct-mtls-ram",
                                                "mountPath": "/var/run/lct-mtls-ram",
                                            },
                                            {
                                                "name": "lct-trust-anchors",
                                                "mountPath": "/etc/lct-anchors",
                                                "readOnly": True,
                                            },
                                            {
                                                "name": "audit-csr-auth",
                                                "mountPath": "/var/run/lct-audit-csr",
                                                "readOnly": True,
                                            },
                                        ],
                                        "livenessProbe": {
                                            "httpGet": {
                                                "path": "/healthz",
                                                "port": 8093,
                                                "scheme": "HTTPS",
                                            },
                                            "initialDelaySeconds": 15,
                                            "periodSeconds": 10,
                                            "failureThreshold": 5,
                                        },
                                        "readinessProbe": {
                                            "httpGet": {
                                                "path": "/readyz",
                                                "port": 8093,
                                                "scheme": "HTTPS",
                                            },
                                            "initialDelaySeconds": 2,
                                            "periodSeconds": 2,
                                        },
                                    }
                                ],
                            },
                        },
                    },
                },
                {
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": {"name": "audit-collector", "namespace": ns},
                    "spec": {
                        "type": "NodePort",
                        "publishNotReadyAddresses": True,
                        "selector": {"app": "audit-collector"},
                        "ports": [
                            {
                                "name": "https-audit",
                                "port": 8093,
                                "targetPort": 8093,
                                "nodePort": 30893,
                            }
                        ],
                    },
                },
            ]
        )
        return yaml.safe_dump_all(docs, sort_keys=False)

    if role == "alpha":
        peer_ca = "org-beta.io=http://beta-ca.org-beta.io:31094,org-payment.io=http://payment-ca.org-payment.io:32094"
        peer_dir = "org-beta.io=https://beta-directory.org-beta.io:31491,org-payment.io=https://payment-directory.org-payment.io:32491"
        peer_rev = "org-beta.io=https://beta-revocation.org-beta.io:31492,org-payment.io=https://payment-revocation.org-payment.io:32492"
        local_ca = f"http://alpha-ca.{ns}.svc.cluster.local:8090"
        local_dir = f"http://alpha-directory.{ns}.svc.cluster.local:8091"
        local_rev = f"http://alpha-revocation.{ns}.svc.cluster.local:8092"
        docs.extend(
            _domain_control_plane_docs(
                spec=spec,
                image=image,
                peer_ca_urls=peer_ca,
                peer_dir_urls=peer_dir,
                peer_rev_urls=peer_rev,
                audit_url=audit_https_url,
                dir_fed_nodeport=30491,
                rev_fed_nodeport=30492,
                svid_ttl_seconds=svid_ttl_seconds,
                require_pinned_anchors=require_pinned_anchors,
                authorized_gateway_sa="e2e-user-gateway",
            )
        )
        docs.extend(
            _agent_or_tool_deployment_docs(
                namespace=ns,
                trust_domain=spec.trust_domain,
                name="orchestrator-alpha",
                image=image,
                app_role="app-orchestrator",
                local_ca_url=local_ca,
                peer_ca_urls=peer_ca,
                dir_url=local_dir,
                rev_url=local_rev,
                audit_url=audit_https_url,
                public_origin="https://orchestrator-alpha.org-alpha.io:30441",
                node_port=30441,
                svid_ttl_seconds=svid_ttl_seconds,
                require_pinned_anchors=require_pinned_anchors,
                llm_url=llm_url,
                llm_model=llm_model,
                agent_skills="travel.orchestrate",
                agent_priority=10,
                agent_display_name="Orchestrator Alpha",
                enable_fault_injection=True,
            )
        )
        # User / Operator CLI Gateway
        docs.extend(
            [
                {
                    "apiVersion": "v1",
                    "kind": "ServiceAccount",
                    "metadata": {"name": "e2e-user-gateway", "namespace": ns},
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "e2e-user-gateway", "namespace": ns},
                    "spec": {
                        "replicas": 1,
                        "selector": {"matchLabels": {"app": "e2e-user-gateway"}},
                        "template": {
                            "metadata": {
                                "labels": {
                                    "app": "e2e-user-gateway",
                                    "lct.io/trust-domain": spec.trust_domain,
                                }
                            },
                            "spec": {
                                "serviceAccountName": "e2e-user-gateway",
                                "automountServiceAccountToken": False,
                                "volumes": [
                                    {"name": "lct-mtls-ram", "emptyDir": {"medium": "Memory"}},
                                    {
                                        "name": "lct-trust-anchors",
                                        "configMap": {
                                            "name": "lct-trust-anchors",
                                            "optional": True,
                                        },
                                    },
                                    {
                                        "name": "lct-sa-token",
                                        "projected": {
                                            "sources": [
                                                {
                                                    "serviceAccountToken": {
                                                        "path": "token",
                                                        "expirationSeconds": 600,
                                                        "audience": "lct-federation-ca",
                                                    }
                                                },
                                                {
                                                    "configMap": {
                                                        "name": "kube-root-ca.crt",
                                                        "items": [
                                                            {"key": "ca.crt", "path": "ca.crt"}
                                                        ],
                                                    }
                                                },
                                            ]
                                        },
                                    },
                                ],
                                "containers": [
                                    {
                                        "name": "gateway",
                                        "image": image,
                                        "imagePullPolicy": "Never",
                                        "command": ["/bin/sh", "-c", "sleep 86400"],
                                        "env": [
                                            {"name": "OLLAMA_BASE_URL", "value": llm_url},
                                            {"name": "LLM_MODEL", "value": llm_model},
                                            {
                                                "name": "LCT_MTLS_RAM_DIR",
                                                "value": "/var/run/lct-mtls-ram",
                                            },
                                            {
                                                "name": "LCT_TRUST_ANCHORS_DIR",
                                                "value": "/etc/lct-anchors",
                                            },
                                            {
                                                "name": "LCT_REQUIRE_PINNED_ANCHORS",
                                                "value": (
                                                    "true" if require_pinned_anchors else "false"
                                                ),
                                            },
                                            {
                                                "name": "LCT_SVID_TTL_SECONDS",
                                                "value": str(int(svid_ttl_seconds)),
                                            },
                                            {"name": "ALPHA_CA_URL", "value": local_ca},
                                            {
                                                "name": "BETA_CA_URL",
                                                "value": "http://beta-ca.org-beta.io:31094",
                                            },
                                            {
                                                "name": "PAYMENT_CA_URL",
                                                "value": "http://payment-ca.org-payment.io:32094",
                                            },
                                            {"name": "PEER_CA_URLS", "value": peer_ca},
                                            {"name": "ALPHA_DIR_URL", "value": local_dir},
                                            {"name": "ALPHA_REV_URL", "value": local_rev},
                                            {
                                                "name": "BETA_REV_FED_URL",
                                                "value": "https://beta-revocation.org-beta.io:31492",
                                            },
                                            {
                                                "name": "PAYMENT_REV_FED_URL",
                                                "value": "https://payment-revocation.org-payment.io:32492",
                                            },
                                            {
                                                "name": "AUDIT_COLLECTOR_URL",
                                                "value": audit_https_url,
                                            },
                                            {
                                                "name": "ORCH_URL",
                                                "value": "https://orchestrator-alpha.org-alpha.io:30441",
                                            },
                                            {
                                                "name": "FLIGHT_URL",
                                                "value": "https://flight-specialist.org-beta.io:31441",
                                            },
                                            {
                                                "name": "HOTEL_PRIMARY_URL",
                                                "value": "https://hotel-specialist-primary.org-beta.io:31442",
                                            },
                                            {
                                                "name": "HOTEL_BACKUP_URL",
                                                "value": "https://hotel-specialist-backup.org-beta.io:31443",
                                            },
                                            {
                                                "name": "CONVERGER_URL",
                                                "value": "https://settlement-converger.org-payment.io:32441",
                                            },
                                            {
                                                "name": "TRAVEL_MCP_SVC_URL",
                                                "value": travel_mcp_https,
                                            },
                                            {
                                                "name": "PAYMENT_MCP_SVC_URL",
                                                "value": payment_mcp_https,
                                            },
                                            {
                                                "name": "SYNC_HOOK_URL",
                                                "value": "http://e2e-user-gateway.org-alpha.io:30990/sync",
                                            },
                                        ],
                                        "ports": [{"containerPort": 19090, "name": "sync-hook"}],
                                        "volumeMounts": [
                                            {
                                                "name": "lct-sa-token",
                                                "mountPath": "/var/run/lct-sa",
                                                "readOnly": True,
                                            },
                                            {
                                                "name": "lct-mtls-ram",
                                                "mountPath": "/var/run/lct-mtls-ram",
                                            },
                                            {
                                                "name": "lct-trust-anchors",
                                                "mountPath": "/etc/lct-anchors",
                                                "readOnly": True,
                                            },
                                        ],
                                    }
                                ],
                            },
                        },
                    },
                },
            ]
        )
        return yaml.safe_dump_all(docs, sort_keys=False)

    if role == "beta":
        peer_ca = "org-alpha.io=http://alpha-ca.org-alpha.io:30094,org-payment.io=http://payment-ca.org-payment.io:32094"
        peer_dir = "org-alpha.io=https://alpha-directory.org-alpha.io:30491,org-payment.io=https://payment-directory.org-payment.io:32491"
        peer_rev = "org-alpha.io=https://alpha-revocation.org-alpha.io:30492,org-payment.io=https://payment-revocation.org-payment.io:32492"
        local_ca = f"http://beta-ca.{ns}.svc.cluster.local:8090"
        local_dir = f"http://beta-directory.{ns}.svc.cluster.local:8091"
        local_rev = f"http://beta-revocation.{ns}.svc.cluster.local:8092"
        docs.extend(
            _domain_control_plane_docs(
                spec=spec,
                image=image,
                peer_ca_urls=peer_ca,
                peer_dir_urls=peer_dir,
                peer_rev_urls=peer_rev,
                audit_url=audit_https_url,
                dir_fed_nodeport=31491,
                rev_fed_nodeport=31492,
                svid_ttl_seconds=svid_ttl_seconds,
                require_pinned_anchors=require_pinned_anchors,
            )
        )
        docs.extend(
            _agent_or_tool_deployment_docs(
                namespace=ns,
                trust_domain=spec.trust_domain,
                name="flight-specialist",
                image=image,
                app_role="app-flight",
                local_ca_url=local_ca,
                peer_ca_urls=peer_ca,
                dir_url=local_dir,
                rev_url=local_rev,
                audit_url=audit_https_url,
                public_origin="https://flight-specialist.org-beta.io:31441",
                node_port=31441,
                svid_ttl_seconds=svid_ttl_seconds,
                require_pinned_anchors=require_pinned_anchors,
                llm_url=llm_url,
                llm_model=llm_model,
                agent_skills="travel.flight",
                agent_priority=10,
                agent_display_name="Flight Specialist B1",
                travel_mcp_url=travel_mcp_https,
            )
        )
        docs.extend(
            _agent_or_tool_deployment_docs(
                namespace=ns,
                trust_domain=spec.trust_domain,
                name="hotel-specialist-primary",
                image=image,
                app_role="app-hotel",
                local_ca_url=local_ca,
                peer_ca_urls=peer_ca,
                dir_url=local_dir,
                rev_url=local_rev,
                audit_url=audit_https_url,
                public_origin="https://hotel-specialist-primary.org-beta.io:31442",
                node_port=31442,
                svid_ttl_seconds=svid_ttl_seconds,
                require_pinned_anchors=require_pinned_anchors,
                llm_url=llm_url,
                llm_model=llm_model,
                agent_skills="travel.hotel",
                agent_priority=10,
                agent_display_name="Hotel Specialist Primary B2",
                enable_fault_injection=True,
                specialist_instance="primary",
                travel_mcp_url=travel_mcp_https,
            )
        )
        docs.extend(
            _agent_or_tool_deployment_docs(
                namespace=ns,
                trust_domain=spec.trust_domain,
                name="hotel-specialist-backup",
                image=image,
                app_role="app-hotel",
                local_ca_url=local_ca,
                peer_ca_urls=peer_ca,
                dir_url=local_dir,
                rev_url=local_rev,
                audit_url=audit_https_url,
                public_origin="https://hotel-specialist-backup.org-beta.io:31443",
                node_port=31443,
                svid_ttl_seconds=svid_ttl_seconds,
                require_pinned_anchors=require_pinned_anchors,
                llm_url=llm_url,
                llm_model=llm_model,
                agent_skills="travel.hotel",
                agent_priority=20,
                agent_display_name="Hotel Specialist Backup B2-Sub",
                enable_fault_injection=True,
                specialist_instance="backup",
                travel_mcp_url=travel_mcp_https,
            )
        )
        return yaml.safe_dump_all(docs, sort_keys=False)

    # role == "pay"
    peer_ca = "org-alpha.io=http://alpha-ca.org-alpha.io:30094,org-beta.io=http://beta-ca.org-beta.io:31094"
    peer_dir = "org-alpha.io=https://alpha-directory.org-alpha.io:30491,org-beta.io=https://beta-directory.org-beta.io:31491"
    peer_rev = "org-alpha.io=https://alpha-revocation.org-alpha.io:30492,org-beta.io=https://beta-revocation.org-beta.io:31492"
    local_ca = f"http://payment-ca.{ns}.svc.cluster.local:8090"
    local_dir = f"http://payment-directory.{ns}.svc.cluster.local:8091"
    local_rev = f"http://payment-revocation.{ns}.svc.cluster.local:8092"
    docs.extend(
        _domain_control_plane_docs(
            spec=spec,
            image=image,
            peer_ca_urls=peer_ca,
            peer_dir_urls=peer_dir,
            peer_rev_urls=peer_rev,
            audit_url=audit_https_url,
            dir_fed_nodeport=32491,
            rev_fed_nodeport=32492,
            svid_ttl_seconds=svid_ttl_seconds,
            require_pinned_anchors=require_pinned_anchors,
        )
    )
    docs.extend(
        _agent_or_tool_deployment_docs(
            namespace=ns,
            trust_domain=spec.trust_domain,
            name="settlement-converger",
            image=image,
            app_role="app-converger",
            local_ca_url=local_ca,
            peer_ca_urls=peer_ca,
            dir_url=local_dir,
            rev_url=local_rev,
            audit_url=audit_https_url,
            public_origin="https://settlement-converger.org-payment.io:32441",
            node_port=32441,
            svid_ttl_seconds=svid_ttl_seconds,
            require_pinned_anchors=require_pinned_anchors,
            llm_url=llm_url,
            llm_model=llm_model,
            agent_skills="settlement.converge",
            agent_priority=10,
            agent_display_name="Settlement Converger C",
            enable_fault_injection=True,
            payment_mcp_url=payment_mcp_https,
        )
    )
    docs.extend(
        _agent_or_tool_deployment_docs(
            namespace=ns,
            trust_domain=spec.trust_domain,
            name="travel-ops-mcp",
            image=image,
            app_role="app-travel-mcp",
            local_ca_url=local_ca,
            peer_ca_urls=peer_ca,
            dir_url=local_dir,
            rev_url=local_rev,
            audit_url=audit_https_url,
            public_origin="https://travel-ops-mcp.org-payment.io:32442",
            node_port=32442,
            svid_ttl_seconds=svid_ttl_seconds,
            require_pinned_anchors=require_pinned_anchors,
            is_tool_server=True,
        )
    )
    docs.extend(
        _agent_or_tool_deployment_docs(
            namespace=ns,
            trust_domain=spec.trust_domain,
            name="payment-vault-mcp",
            image=image,
            app_role="app-payment-mcp",
            local_ca_url=local_ca,
            peer_ca_urls=peer_ca,
            dir_url=local_dir,
            rev_url=local_rev,
            audit_url=audit_https_url,
            public_origin="https://payment-vault-mcp.org-payment.io:32443",
            node_port=32443,
            svid_ttl_seconds=svid_ttl_seconds,
            require_pinned_anchors=require_pinned_anchors,
            is_tool_server=True,
        )
    )
    return yaml.safe_dump_all(docs, sort_keys=False)


def _apply_coredns_in_cluster(
    kube_context: str,
    alpha_ip: str,
    beta_ip: str,
    pay_ip: str,
    audit_ip: Optional[str] = None,
) -> None:
    raw = subprocess.check_output(
        [
            "kubectl",
            "--context",
            kube_context,
            "-n",
            "kube-system",
            "get",
            "configmap",
            "coredns",
            "-o",
            "json",
        ],
        text=True,
    )
    cm = json.loads(raw)
    updated_corefile = patch_coredns_corefile(
        cm["data"]["Corefile"],
        alpha_ip=alpha_ip,
        beta_ip=beta_ip,
        pay_ip=pay_ip,
        audit_ip=audit_ip,
    )
    patched = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "coredns", "namespace": "kube-system"},
        "data": {"Corefile": updated_corefile},
    }
    subprocess.run(
        ["kubectl", "--context", kube_context, "apply", "-f", "-"],
        input=json.dumps(patched),
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            "kubectl",
            "--context",
            kube_context,
            "-n",
            "kube-system",
            "rollout",
            "restart",
            "deploy/coredns",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            "kubectl",
            "--context",
            kube_context,
            "-n",
            "kube-system",
            "rollout",
            "status",
            "deploy/coredns",
            "--timeout=60s",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def _ensure_in_memory_ca_secret(role: str, regenerate: bool = False) -> str:
    """Create or reuse the role's CA root Secret directly in K8s without writing to host disk."""
    spec = ROLE_SPECS[role]
    sec_name = "audit-ca-keys" if role == "audit" else f"{spec.ca_short_prefix}-ca-keys"

    ns_doc = {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": spec.namespace,
            "labels": {"lct.io/trust-domain": spec.trust_domain},
        },
    }
    subprocess.run(
        ["kubectl", "--context", spec.kube_context, "apply", "-f", "-"],
        input=json.dumps(ns_doc),
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
    )

    if not regenerate:
        probe = subprocess.run(
            [
                "kubectl",
                "--context",
                spec.kube_context,
                "-n",
                spec.namespace,
                "get",
                "secret",
                sec_name,
                "-o",
                "json",
            ],
            capture_output=True,
            text=True,
        )
        if probe.returncode == 0:
            existing_obj = json.loads(probe.stdout)
            ann = (existing_obj.get("metadata") or {}).get("annotations") or {}
            existing_anchor = ann.get("lct.io/trust-anchor")
            if existing_anchor:
                return format_domain_trust_anchor_line(spec.trust_domain, existing_anchor)
            # Recompute public anchor in memory from existing Secret
            b64_data = existing_obj.get("data") or {}
            root_pem = base64.b64decode(b64_data["x509_root_cert.pem"]).decode("utf-8")
            if role == "audit":
                anc = compute_bundle_trust_anchor(
                    {"trust_domain": spec.trust_domain, "keys": [], "x509_root_pem": root_pem},
                    allow_keyless_jwks=True,
                )
            else:
                priv_pem = base64.b64decode(b64_data["ca_private_key.pem"]).decode("utf-8")
                kp = KeyPair.from_private_pem(priv_pem)
                anc = compute_bundle_trust_anchor(
                    {
                        "trust_domain": spec.trust_domain,
                        "keys": [kp.public_jwk()],
                        "x509_root_pem": root_pem,
                    }
                )
            return format_domain_trust_anchor_line(spec.trust_domain, anc)

    sec_list, _, anchor_line = generate_domain_ca_secret_bundle(role)
    for sec_doc in sec_list:
        subprocess.run(
            ["kubectl", "--context", spec.kube_context, "apply", "-f", "-"],
            input=json.dumps(sec_doc),
            text=True,
            check=True,
            stdout=subprocess.DEVNULL,
        )
    return anchor_line


def _cli_main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="LCT Multi-Host Config & Bootstrap Utility")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_roles = sub.add_parser("parse-roles")
    p_roles.add_argument("--roles", required=True)

    p_ip = sub.add_parser("validate-ips")
    p_ip.add_argument("--alpha-ip", required=True)
    p_ip.add_argument("--beta-ip", required=True)
    p_ip.add_argument("--pay-ip", required=True)
    p_ip.add_argument("--audit-ip", default="")

    p_kind = sub.add_parser("kind-config")
    p_kind.add_argument("--role", required=True)

    p_ports = sub.add_parser("role-ports")
    p_ports.add_argument("--roles", required=True)

    p_dns = sub.add_parser("patch-coredns")
    p_dns.add_argument("--roles", required=True)
    p_dns.add_argument("--alpha-ip", required=True)
    p_dns.add_argument("--beta-ip", required=True)
    p_dns.add_argument("--pay-ip", required=True)
    p_dns.add_argument("--audit-ip", default="")

    p_ca = sub.add_parser("ensure-ca-secret")
    p_ca.add_argument("--role", required=True)
    p_ca.add_argument("--regenerate", action="store_true")

    p_man = sub.add_parser("render-manifest")
    p_man.add_argument("--role", required=True)
    p_man.add_argument("--image", default="lineage-lct:m6")
    p_man.add_argument("--llm-url", default="http://host.docker.internal:11434/v1")
    p_man.add_argument("--llm-model", default="qwen2.5:3b")
    p_man.add_argument("--svid-ttl", type=int, default=1800)
    p_man.add_argument("--no-require-pins", action="store_true")
    p_man.add_argument(
        "--skip-configmap",
        action="store_true",
        help="Do not overwrite existing lct-trust-anchors ConfigMap on re-apply",
    )

    p_skew = sub.add_parser("check-skew")
    p_skew.add_argument("--url", required=True)
    p_skew.add_argument("--timeout", type=float, default=3.0)

    args = parser.parse_args(argv)

    if args.cmd == "parse-roles":
        print(" ".join(parse_roles_csv(args.roles)))
        return 0

    if args.cmd == "validate-ips":
        a = validate_ipv4_address(args.alpha_ip, "--alpha-ip")
        b = validate_ipv4_address(args.beta_ip, "--beta-ip")
        p = validate_ipv4_address(args.pay_ip, "--pay-ip")
        aud = (
            validate_ipv4_address(args.audit_ip, "--audit-ip")
            if args.audit_ip.strip()
            else a
        )
        print(json.dumps({"alpha_ip": a, "beta_ip": b, "pay_ip": p, "audit_ip": aud}))
        return 0

    if args.cmd == "kind-config":
        sys.stdout.write(render_kind_cluster_config(args.role))
        return 0

    if args.cmd == "role-ports":
        roles = parse_roles_csv(args.roles)
        ports: List[int] = []
        for r in roles:
            ports.extend(ROLE_SPECS[r].host_ports)
        print(" ".join(str(p) for p in ports))
        return 0

    if args.cmd == "patch-coredns":
        roles = parse_roles_csv(args.roles)
        for r in roles:
            _apply_coredns_in_cluster(
                ROLE_SPECS[r].kube_context,
                alpha_ip=args.alpha_ip,
                beta_ip=args.beta_ip,
                pay_ip=args.pay_ip,
                audit_ip=args.audit_ip or None,
            )
        return 0

    if args.cmd == "ensure-ca-secret":
        print(_ensure_in_memory_ca_secret(args.role, regenerate=args.regenerate))
        return 0

    if args.cmd == "render-manifest":
        sys.stdout.write(
            render_role_k8s_manifests(
                role=args.role,
                image=args.image,
                llm_url=args.llm_url,
                llm_model=args.llm_model,
                svid_ttl_seconds=args.svid_ttl,
                require_pinned_anchors=(not args.no_require_pins),
                include_namespace_and_configmap=(not args.skip_configmap),
            )
        )
        return 0

    if args.cmd == "check-skew":
        import httpx

        verify_arg: Any = False if args.url.startswith("https://") else True
        try:
            with httpx.Client(verify=verify_arg, timeout=args.timeout, trust_env=False) as cli:
                r = cli.get(f"{args.url.rstrip('/')}/healthz")
        except Exception as exc:
            print(json.dumps({"status": "UNREACHABLE", "ok": True, "detail": str(exc)}))
            return 3
        date_hdr = r.headers.get("date") or r.headers.get("Date") or ""
        if not date_hdr:
            print(json.dumps({"status": "NO_DATE_HEADER", "ok": True}))
            return 3
        res = evaluate_http_date_clock_skew(date_hdr)
        print(json.dumps(res))
        return 0 if res["ok"] else 2

    return 1


if __name__ == "__main__":
    raise SystemExit(_cli_main())
