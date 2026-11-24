"""Multi-Host Kind Config, Dynamic Per-Machine Port Allocator, Role Manifests & CA Bootstrapper.

Covers:
1. Per-role Kind cluster configs (`lctmh-alpha`, `lctmh-beta`, `lctmh-pay`, `lctmh-audit`)
   with dynamic per-machine NodePort allocation (`extraPortMappings`, `containerPort == hostPort`,
   `listenAddress: 0.0.0.0`, automatic local conflict detection & free-port selection) and
   disjoint Pod/Service CIDRs; internal ports (`8090`, `8091`, `8092`, `9001`, `8081`) are
   NEVER host-published.
2. Zero cross-domain IP/port/FQDN hardcoding: manifests contain ONLY local in-cluster service
   names (`*.svc.cluster.local`), `ConfigMap/lct-node-locator` (populated by `locator-agent.py`),
   `ConfigMap/lct-bootstrap-seeds`, `ConfigMap/lct-learned-descriptors`, and
   `ConfigMap/lct-trust-anchors`.
3. CoreDNS sanitization (`sanitize_coredns_corefile`) preserving `host.docker.internal` and
   `kubernetes cluster.local` without any cross-domain `hosts` injection.
4. Pure in-memory Domain CA root key generation streamed directly to `kubectl apply -f -`
   via stdin without touching host disk or logs.
5. RFC 9110 HTTP `Date` clock-skew evaluation (`warn > 10s`, `fail > 25s`).
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import datetime as dt
import email.utils
import ipaddress
import json
import re
import secrets
import socket
import subprocess
import sys
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

import yaml

from lineage.common.crypto import KeyPair
from lineage.common.mtls import X509DomainAuthority
from lineage.federation.anchors import (
    compute_bundle_trust_anchor,
    format_domain_trust_anchor_line,
)
from lineage.identity.spiffe import TrustDomainCA
from lineage.oauth_sts.keycloak_realm import (
    DEFAULT_REALM_NAME,
    KEYCLOAK_IMAGE,
    generate_keycloak_realm_bundle,
)

FORBIDDEN_HOST_PORTS: Tuple[int, ...] = (
    8080,
    8081,
    8090,
    8091,
    8092,
    8093,
    8094,
    8095,
    8443,
    8491,
    8492,
    9001,
    19090,
)
NODEPORT_MIN = 30000
NODEPORT_MAX = 32767
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
    slot_names: Tuple[str, ...]
    default_base_port: int


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
        slot_names=(
            "ca_federation",
            "directory_federation",
            "revocation_federation",
            "orchestrator-alpha",
            "e2e_sync_hook",
            "oauth_sts",
        ),
        default_base_port=30100,
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
        slot_names=(
            "ca_federation",
            "directory_federation",
            "revocation_federation",
            "flight-specialist",
            "hotel-specialist-primary",
            "hotel-specialist-backup",
            "oauth_sts",
        ),
        default_base_port=31100,
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
        slot_names=(
            "ca_federation",
            "directory_federation",
            "revocation_federation",
            "settlement-converger",
            "travel-ops-mcp",
            "payment-vault-mcp",
            "oauth_sts",
        ),
        default_base_port=32100,
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
        slot_names=(
            "ca_federation",
            "audit_collector",
        ),
        default_base_port=30800,
    ),
}

_STRICT_IPV4_RE = re.compile(r"^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$")
_CROSS_DOMAIN_SUFFIXES = (
    ".org-alpha.io",
    ".org-beta.io",
    ".org-payment.io",
    ".org-audit.io",
)


def parse_roles_csv(roles_spec: str) -> Tuple[str, ...]:
    """Parse `--roles alpha,audit|beta|pay|all` into deduplicated canonical role names."""
    if not isinstance(roles_spec, str) or not roles_spec.strip():
        raise ValueError("--roles must be a non-empty comma-separated list (e.g., alpha)")
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
            f"Invalid {flag_name}={s!r}: loopback 127.0.0.0/8 resolves inside container netns, not host NIC; pass the machine's LAN IPv4"
        )
    return str(addr)


def is_host_tcp_port_free(port: int, bind_host: str = "0.0.0.0") -> bool:
    """Return True if `bind_host:port` is currently free to bind on this machine."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((bind_host, int(port)))
        return True
    except OSError:
        return False


def parse_port_overrides(overrides: Optional[Sequence[str]]) -> Dict[str, int]:
    """Parse repeatable `slot=port` or `role.slot=port` strings."""
    result: Dict[str, int] = {}
    for raw in overrides or ():
        if not raw or not raw.strip():
            continue
        if "=" not in raw:
            raise ValueError(
                f"Invalid --port-override {raw!r}; expected '<slot>=<nodeport>' or '<role>.<slot>=<nodeport>'"
            )
        k, v = raw.split("=", 1)
        key = k.strip()
        try:
            port_num = int(v.strip())
        except ValueError as exc:
            raise ValueError(f"Non-integer port in --port-override {raw!r}") from exc
        if port_num < NODEPORT_MIN or port_num > NODEPORT_MAX or port_num in FORBIDDEN_HOST_PORTS:
            raise ValueError(
                f"Port {port_num} in --port-override {raw!r} must be within Kubernetes NodePort range [{NODEPORT_MIN}, {NODEPORT_MAX}] and not an internal port"
            )
        result[key] = port_num
    return result


def allocate_role_ports(
    role: str,
    *,
    base_port: Optional[int] = None,
    port_overrides: Optional[Mapping[str, int]] = None,
    check_host_free: bool = False,
    reserved_ports: Iterable[int] = (),
) -> Dict[str, int]:
    """Allocate per-machine local NodePorts for `role` without any global port convention.

    - Supports explicit `--base-port` and per-slot `--port-override`.
    - When `check_host_free=True`, automatically skips any TCP port already bound on the local
      host and selects the next free NodePort in `[30000, 32767]`.
    """
    if role not in ROLE_SPECS:
        raise ValueError(f"Unknown role: {role!r}")
    spec = ROLE_SPECS[role]
    start_port = int(spec.default_base_port if base_port is None else base_port)
    if start_port < NODEPORT_MIN or start_port > NODEPORT_MAX:
        raise ValueError(
            f"base_port {start_port} outside Kubernetes NodePort range [{NODEPORT_MIN}, {NODEPORT_MAX}]"
        )

    taken: Set[int] = set(int(p) for p in reserved_ports) | set(FORBIDDEN_HOST_PORTS)
    overrides = dict(port_overrides or {})
    allocated: Dict[str, int] = {}
    cursor = start_port

    for slot in spec.slot_names:
        explicit = overrides.get(f"{role}.{slot}", overrides.get(slot))
        if explicit is not None:
            p = int(explicit)
            if p < NODEPORT_MIN or p > NODEPORT_MAX or p in FORBIDDEN_HOST_PORTS:
                raise ValueError(
                    f"Invalid override port {p} for {role}.{slot}; must be in [{NODEPORT_MIN}, {NODEPORT_MAX}]"
                )
            if p in taken:
                raise ValueError(f"Duplicate port {p} assigned to {role}.{slot}")
            if check_host_free and not is_host_tcp_port_free(p):
                raise ValueError(
                    f"Explicitly requested port {p} for {role}.{slot} is already in use on this machine"
                )
            allocated[slot] = p
            taken.add(p)
            continue

        chosen: Optional[int] = None
        for offset in range(NODEPORT_MAX - NODEPORT_MIN + 1):
            cand = NODEPORT_MIN + ((cursor - NODEPORT_MIN + offset) % (NODEPORT_MAX - NODEPORT_MIN + 1))
            if cand in taken:
                continue
            if check_host_free and not is_host_tcp_port_free(cand):
                continue
            chosen = cand
            cursor = cand + 1
            break
        if chosen is None:
            raise RuntimeError(
                f"Unable to find free NodePort in [{NODEPORT_MIN}, {NODEPORT_MAX}] for {role}.{slot}"
            )
        allocated[slot] = chosen
        taken.add(chosen)

    return allocated


def read_cluster_role_ports(role: str) -> Optional[Dict[str, int]]:
    """Read persisted local NodePort map from `Namespace/lineage-<role>` if cluster exists."""
    if role not in ROLE_SPECS:
        raise ValueError(f"Unknown role: {role!r}")
    spec = ROLE_SPECS[role]
    proc = subprocess.run(
        [
            "kubectl",
            "--context",
            spec.kube_context,
            "get",
            "namespace",
            spec.namespace,
            "-o",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        ns_obj = json.loads(proc.stdout)
        raw_json = (
            ((ns_obj.get("metadata") or {}).get("annotations") or {}).get(
                "lct.io/role-ports-json", ""
            )
        )
        if raw_json:
            parsed = json.loads(raw_json)
            if isinstance(parsed, Mapping) and all(s in parsed for s in spec.slot_names):
                return {str(k): int(v) for k, v in parsed.items()}
    except Exception:
        pass
    return None


def read_kind_node_published_ports(role: str) -> List[int]:
    """Inspect Docker hostPort bindings on an existing `lctmh-<role>-control-plane` container."""
    spec = ROLE_SPECS[role]
    proc = subprocess.run(
        [
            "docker",
            "inspect",
            f"{spec.cluster_name}-control-plane",
            "--format",
            "{{json .NetworkSettings.Ports}}",
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    try:
        ports_map = json.loads(proc.stdout)
        out: List[int] = []
        if isinstance(ports_map, Mapping):
            for proto_key, bindings in ports_map.items():
                if not str(proto_key).endswith("/tcp") or not isinstance(bindings, list):
                    continue
                cport = int(str(proto_key).split("/", 1)[0])
                if NODEPORT_MIN <= cport <= NODEPORT_MAX:
                    out.append(cport)
        return sorted(set(out))
    except Exception:
        return []


def render_kind_cluster_config(
    role: str,
    role_ports: Optional[Mapping[str, int]] = None,
) -> str:
    """Generate Kind `v1alpha4` YAML with local `extraPortMappings` and disjoint CIDRs."""
    if role not in ROLE_SPECS:
        raise ValueError(f"Unknown role: {role!r}")
    spec = ROLE_SPECS[role]
    ports_map = dict(role_ports) if role_ports is not None else allocate_role_ports(role)
    port_mappings = []
    seen_ports: Set[int] = set()
    for slot in spec.slot_names:
        if slot not in ports_map:
            raise ValueError(f"Missing allocated port for {role}.{slot}")
        p = int(ports_map[slot])
        if p in FORBIDDEN_HOST_PORTS:
            raise AssertionError(f"Internal port {p} must never be host-published")
        if p < NODEPORT_MIN or p > NODEPORT_MAX:
            raise ValueError(f"NodePort {p} outside [{NODEPORT_MIN}, {NODEPORT_MAX}]")
        if p in seen_ports:
            raise ValueError(f"Duplicate NodePort {p} in role {role!r}")
        seen_ports.add(p)
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


def sanitize_coredns_corefile(existing_corefile: str) -> str:
    """Ensure CoreDNS contains ZERO cross-domain LCT `hosts` entries while preserving `host.docker.internal`."""
    if "kubernetes cluster.local" not in existing_corefile:
        raise ValueError(
            f"Unexpected CoreDNS Corefile missing 'kubernetes cluster.local':\n{existing_corefile}"
        )
    hosts_match = re.search(
        r"(^[ \t]*hosts\s*\{)([^}]*)(\})",
        existing_corefile,
        flags=re.MULTILINE | re.DOTALL,
    )
    if not hosts_match:
        return existing_corefile

    preserved_lines: List[str] = []
    for raw_ln in hosts_match.group(2).splitlines():
        stripped = raw_ln.strip()
        if not stripped or stripped == "fallthrough" or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            ip_tok = parts[0]
            kept_names = [
                n
                for n in parts[1:]
                if not any(
                    n.lower() == sfx.lstrip(".") or n.lower().endswith(sfx)
                    for sfx in _CROSS_DOMAIN_SUFFIXES
                )
            ]
            if kept_names:
                preserved_lines.append(f"        {ip_tok} {' '.join(kept_names)}")

    if not preserved_lines:
        # Remove empty hosts stanza cleanly
        cleaned = (
            existing_corefile[: hosts_match.start()]
            + existing_corefile[hosts_match.end() :]
        )
        return re.sub(r"\n{3,}", "\n\n", cleaned)

    merged_body = "\n".join([*preserved_lines, "        fallthrough"])
    new_block = f"    hosts {{\n{merged_body}\n    }}"
    return (
        existing_corefile[: hosts_match.start()]
        + new_block
        + existing_corefile[hosts_match.end() :]
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


def _identity_addressing_volumes(include_node_locator: bool = True) -> List[Dict[str, Any]]:
    vols: List[Dict[str, Any]] = [
        {
            "name": "lct-trust-anchors",
            "configMap": {"name": "lct-trust-anchors", "optional": True},
        },
        {
            "name": "lct-bootstrap-seeds",
            "configMap": {"name": "lct-bootstrap-seeds", "optional": True},
        },
        {
            "name": "lct-learned-descriptors",
            "configMap": {"name": "lct-learned-descriptors", "optional": True},
        },
    ]
    if include_node_locator:
        vols.append(
            {
                "name": "lct-node-locator",
                "configMap": {"name": "lct-node-locator", "optional": True},
            }
        )
    return vols


def _identity_addressing_mounts(include_node_locator: bool = True) -> List[Dict[str, Any]]:
    mounts: List[Dict[str, Any]] = [
        {"name": "lct-trust-anchors", "mountPath": "/etc/lct-anchors", "readOnly": True},
        {"name": "lct-bootstrap-seeds", "mountPath": "/etc/lct-seeds", "readOnly": True},
        {
            "name": "lct-learned-descriptors",
            "mountPath": "/etc/lct-descriptors",
            "readOnly": True,
        },
    ]
    if include_node_locator:
        mounts.append(
            {
                "name": "lct-node-locator",
                "mountPath": "/etc/lct-node-locator",
                "readOnly": True,
            }
        )
    return mounts


def _agent_or_tool_deployment_docs(
    *,
    namespace: str,
    trust_domain: str,
    name: str,
    image: str,
    app_role: str,
    local_ca_url: str,
    dir_url: str,
    rev_url: str,
    node_port: int,
    svid_ttl_seconds: int,
    require_pinned_anchors: bool,
    llm_url: Optional[str] = None,
    llm_model: Optional[str] = None,
    is_tool_server: bool = False,
    agent_skills: Optional[str] = None,
    supported_tools: Optional[str] = None,
    agent_priority: Optional[int] = None,
    agent_display_name: Optional[str] = None,
    enable_fault_injection: bool = False,
    specialist_instance: Optional[str] = None,
    delegation_mode: str = "dual",
    local_sts_url: Optional[str] = None,
) -> List[Dict[str, Any]]:
    sa_doc = {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"name": name, "namespace": namespace},
    }
    app_env: List[Dict[str, str]] = [
        {"name": "LCT_IDENTITY_ADDRESSING", "value": "true"},
    ]
    if specialist_instance:
        app_env.append({"name": "SPECIALIST_INSTANCE", "value": specialist_instance})
    if llm_url:
        app_env.append({"name": "OLLAMA_BASE_URL", "value": llm_url})
    if llm_model:
        app_env.append({"name": "LLM_MODEL", "value": llm_model})
    if enable_fault_injection:
        app_env.append({"name": "LCT_ENABLE_FAULT_INJECTION", "value": "true"})

    sidecar_env: List[Dict[str, str]] = [
        {"name": "LCT_IDENTITY_ADDRESSING", "value": "true"},
        {"name": "DELEGATION_MODE", "value": delegation_mode},
        {"name": "OAUTH_CREDENTIALS_FILE", "value": "/var/run/lct-oauth/credentials.json"},
        {"name": "LCT_LOCATOR_SLOT", "value": name},
        {"name": "LCT_NODE_LOCATOR_FILE", "value": "/etc/lct-node-locator/locator.json"},
        {"name": "LCT_SEEDS_DIR", "value": "/etc/lct-seeds"},
        {
            "name": "LCT_PERSISTED_DESCRIPTORS_FILE",
            "value": "/etc/lct-descriptors/descriptors.json",
        },
        {"name": "LOCAL_CA_URL", "value": local_ca_url},
        {"name": "DIRECTORY_URL", "value": dir_url},
        {"name": "REVOCATION_URL", "value": rev_url},
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
    if local_sts_url:
        sidecar_env.append({"name": "LOCAL_STS_URL", "value": local_sts_url})
    if is_tool_server:
        sidecar_env.append({"name": "IS_TOOL_SERVER", "value": "true"})
        sidecar_env.append({"name": "VERIFICATION_MODE", "value": "ADAPTIVE_RISK_ANCHORED"})
    if agent_skills:
        sidecar_env.append({"name": "AGENT_SKILLS", "value": agent_skills})
    elif not is_tool_server:
        sidecar_env.append({"name": "AGENT_SKILLS", "value": "agent.generic"})
    if supported_tools:
        sidecar_env.append({"name": "SUPPORTED_TOOLS", "value": supported_tools})
    sidecar_env.append({"name": "AGENT_PRIORITY", "value": str(agent_priority or 50)})
    sidecar_env.append({"name": "AGENT_DISPLAY_NAME", "value": agent_display_name or name})
    if enable_fault_injection:
        sidecar_env.append({"name": "LCT_ENABLE_FAULT_INJECTION", "value": "true"})

    app_container: Dict[str, Any] = {
        "name": "app",
        "image": image,
        "imagePullPolicy": "Never",
        "args": ["--role", app_role],
        "env": app_env,
        "volumeMounts": [
            {"name": "lct-loopback", "mountPath": "/var/run/lct-loopback", "readOnly": True}
        ],
        "livenessProbe": {
            "exec": {
                "command": [
                    "/app/.venv/bin/python3",
                    "-c",
                    "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9001/healthz', timeout=4)",
                ]
            },
            "initialDelaySeconds": 15,
            "periodSeconds": 10,
            "timeoutSeconds": 5,
            "failureThreshold": 6,
        },
    }

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
                    "securityContext": {"fsGroup": 2000},
                    "volumes": [
                        {"name": "lct-loopback", "emptyDir": {"medium": "Memory"}},
                        {"name": "lct-mtls-ram", "emptyDir": {"medium": "Memory"}},
                        {
                            "name": "lct-oauth-credentials",
                            "secret": {
                                "secretName": "lct-oauth-credentials",
                                "defaultMode": 0o440,
                                "optional": True,
                            },
                        },
                        *_identity_addressing_volumes(include_node_locator=True),
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
                                    "name": "lct-oauth-credentials",
                                    "mountPath": "/var/run/lct-oauth",
                                    "readOnly": True,
                                },
                                *_identity_addressing_mounts(include_node_locator=True),
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
                                        "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8081/healthz', timeout=4)",
                                    ]
                                },
                                "initialDelaySeconds": 15,
                                "periodSeconds": 10,
                                "timeoutSeconds": 5,
                                "failureThreshold": 6,
                            },
                            "readinessProbe": {
                                "exec": {
                                    "command": [
                                        "/app/.venv/bin/python3",
                                        "-c",
                                        "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8081/readyz', timeout=4)",
                                    ]
                                },
                                "initialDelaySeconds": 2,
                                "periodSeconds": 2,
                                "timeoutSeconds": 5,
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
                    "nodePort": int(node_port),
                }
            ],
        },
    }
    return [sa_doc, dep_doc, svc_doc]


def _oauth_sts_docs(
    *,
    spec: RoleSpec,
    image: str,
    sts_nodeport: int,
    sts_engine: str,
    keycloak_image: str,
    require_pinned_anchors: bool,
) -> List[Dict[str, Any]]:
    """Render Organization OAuth 2.0 / OIDC STS (`quay.io/keycloak/keycloak:26.5.2` or lightweight STS)."""
    eng = (sts_engine or "lightweight").strip().lower()
    if eng == "none":
        return []
    if eng not in ("keycloak", "lightweight"):
        raise ValueError(f"Unsupported sts_engine: {sts_engine!r}")

    ns = spec.namespace
    td = spec.trust_domain
    pfx = spec.ca_short_prefix
    sts_name = f"{pfx}-sts"
    local_ca_url = f"http://{pfx}-ca.{ns}.svc.cluster.local:8090"

    sa_doc = {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"name": sts_name, "namespace": ns},
    }

    if eng == "keycloak":
        pod_spec: Dict[str, Any] = {
            "serviceAccountName": sts_name,
            "automountServiceAccountToken": False,
            "securityContext": {"fsGroup": 2000},
            "volumes": [
                {
                    "name": "keycloak-realm-import",
                    "secret": {
                        "secretName": "lct-keycloak-realm",
                        "defaultMode": 0o440,
                        "items": [{"key": "lct-realm.json", "path": "lct-realm.json"}],
                    },
                }
            ],
            "containers": [
                {
                    "name": sts_name,
                    "image": keycloak_image,
                    "imagePullPolicy": "IfNotPresent",
                    "args": [
                        "start-dev",
                        "--import-realm",
                        "--http-port=8095",
                        "--features=token-exchange,token-exchange-standard:v2",
                    ],
                    "env": [
                        {
                            "name": "KC_BOOTSTRAP_ADMIN_USERNAME",
                            "valueFrom": {
                                "secretKeyRef": {
                                    "name": "lct-keycloak-realm",
                                    "key": "admin_username",
                                }
                            },
                        },
                        {
                            "name": "KC_BOOTSTRAP_ADMIN_PASSWORD",
                            "valueFrom": {
                                "secretKeyRef": {
                                    "name": "lct-keycloak-realm",
                                    "key": "admin_password",
                                }
                            },
                        },
                        {"name": "JAVA_OPTS_APPEND", "value": "-Xms256m -Xmx768m"},
                    ],
                    "ports": [{"containerPort": 8095, "name": "http-sts"}],
                    "volumeMounts": [
                        {
                            "name": "keycloak-realm-import",
                            "mountPath": "/opt/keycloak/data/import",
                            "readOnly": True,
                        }
                    ],
                    "startupProbe": {
                        "httpGet": {
                            "path": f"/realms/{DEFAULT_REALM_NAME}/.well-known/openid-configuration",
                            "port": 8095,
                        },
                        "initialDelaySeconds": 8,
                        "periodSeconds": 5,
                        "timeoutSeconds": 5,
                        "failureThreshold": 48,
                    },
                    "readinessProbe": {
                        "httpGet": {
                            "path": f"/realms/{DEFAULT_REALM_NAME}/.well-known/openid-configuration",
                            "port": 8095,
                        },
                        "initialDelaySeconds": 2,
                        "periodSeconds": 3,
                        "timeoutSeconds": 5,
                        "failureThreshold": 6,
                    },
                    "livenessProbe": {
                        "httpGet": {
                            "path": f"/realms/{DEFAULT_REALM_NAME}/.well-known/openid-configuration",
                            "port": 8095,
                        },
                        "initialDelaySeconds": 10,
                        "periodSeconds": 10,
                        "timeoutSeconds": 5,
                        "failureThreshold": 6,
                    },
                }
            ],
        }
    else:
        pod_spec = {
            "serviceAccountName": sts_name,
            "automountServiceAccountToken": False,
            "securityContext": {"fsGroup": 2000},
            "volumes": [
                {
                    "name": "lct-oauth-credentials",
                    "secret": {
                        "secretName": "lct-oauth-credentials",
                        "defaultMode": 0o440,
                        "optional": True,
                    },
                },
                *_identity_addressing_volumes(include_node_locator=False),
            ],
            "containers": [
                {
                    "name": sts_name,
                    "image": image,
                    "imagePullPolicy": "Never",
                    "args": ["--role", "oauth-sts"],
                    "env": [
                        {"name": "LCT_IDENTITY_ADDRESSING", "value": "true"},
                        {"name": "TRUST_DOMAIN", "value": td},
                        {"name": "OAUTH_REALM", "value": DEFAULT_REALM_NAME},
                        {"name": "OAUTH_ISSUER_ORIGIN", "value": f"http://{pfx}-oidc.lct.local"},
                        {"name": "STS_PORT", "value": "8095"},
                        {"name": "LOCAL_CA_URL", "value": local_ca_url},
                        {
                            "name": "OAUTH_CREDENTIALS_FILE",
                            "value": "/var/run/lct-oauth/credentials.json",
                        },
                        {"name": "LCT_SEEDS_DIR", "value": "/etc/lct-seeds"},
                        {
                            "name": "LCT_PERSISTED_DESCRIPTORS_FILE",
                            "value": "/etc/lct-descriptors/descriptors.json",
                        },
                        {"name": "LCT_TRUST_ANCHORS_DIR", "value": "/etc/lct-anchors"},
                        {
                            "name": "LCT_REQUIRE_PINNED_ANCHORS",
                            "value": "true" if require_pinned_anchors else "false",
                        },
                        {"name": "LCT_WAIT_FOR_PEERS_ON_BOOT", "value": "false"},
                    ],
                    "ports": [{"containerPort": 8095, "name": "http-sts"}],
                    "volumeMounts": [
                        {
                            "name": "lct-oauth-credentials",
                            "mountPath": "/var/run/lct-oauth",
                            "readOnly": True,
                        },
                        *_identity_addressing_mounts(include_node_locator=False),
                    ],
                    "readinessProbe": {
                        "httpGet": {
                            "path": f"/realms/{DEFAULT_REALM_NAME}/.well-known/openid-configuration",
                            "port": 8095,
                        },
                        "initialDelaySeconds": 1,
                        "periodSeconds": 2,
                        "timeoutSeconds": 5,
                    },
                    "livenessProbe": {
                        "httpGet": {"path": "/healthz", "port": 8095},
                        "initialDelaySeconds": 10,
                        "periodSeconds": 10,
                        "timeoutSeconds": 5,
                        "failureThreshold": 6,
                    },
                }
            ],
        }

    dep_doc = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": sts_name,
            "namespace": ns,
            "labels": {"lct.io/sts-engine": eng},
        },
        "spec": {
            "replicas": 1,
            "strategy": {"type": "Recreate"},
            "selector": {"matchLabels": {"app": sts_name}},
            "template": {
                "metadata": {
                    "labels": {
                        "app": sts_name,
                        "lct.io/trust-domain": td,
                        "lct.io/sts-engine": eng,
                    }
                },
                "spec": pod_spec,
            },
        },
    }
    svc_internal = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": sts_name, "namespace": ns},
        "spec": {
            "type": "ClusterIP",
            "selector": {"app": sts_name},
            "ports": [{"name": "http-sts", "port": 8095, "targetPort": 8095}],
        },
    }
    svc_external = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": f"{sts_name}-federation", "namespace": ns},
        "spec": {
            "type": "NodePort",
            "selector": {"app": sts_name},
            "ports": [
                {
                    "name": "http-sts",
                    "port": 8095,
                    "targetPort": 8095,
                    "nodePort": int(sts_nodeport),
                }
            ],
        },
    }
    return [sa_doc, dep_doc, svc_internal, svc_external]


def _domain_control_plane_docs(
    *,
    spec: RoleSpec,
    image: str,
    ca_fed_nodeport: int,
    dir_fed_nodeport: int,
    rev_fed_nodeport: int,
    svid_ttl_seconds: int,
    require_pinned_anchors: bool,
    authorized_gateway_sa: Optional[str] = None,
    sts_enabled: bool = True,
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
        {"name": "LCT_IDENTITY_ADDRESSING", "value": "true"},
        {"name": "LCT_NODE_LOCATOR_FILE", "value": "/etc/lct-node-locator/locator.json"},
        {"name": "LCT_SEEDS_DIR", "value": "/etc/lct-seeds"},
        {
            "name": "LCT_PERSISTED_DESCRIPTORS_FILE",
            "value": "/etc/lct-descriptors/descriptors.json",
        },
        {"name": "TRUST_DOMAIN", "value": td},
        {"name": "ALLOWED_K8S_NAMESPACE", "value": ns},
        {"name": "CA_FEDERATION_PORT", "value": "8094"},
        {"name": "CA_KEY_MATERIAL_DIR", "value": "/var/run/lct-ca-keys"},
        {"name": "LCT_TRUST_ANCHORS_DIR", "value": "/etc/lct-anchors"},
        {
            "name": "LCT_REQUIRE_PINNED_ANCHORS",
            "value": "true" if require_pinned_anchors else "false",
        },
        {"name": "LCT_WAIT_FOR_PEERS_ON_BOOT", "value": "false"},
    ]
    if authorized_gateway_sa:
        ca_env.append({"name": "AUTHORIZED_GATEWAY_SA", "value": authorized_gateway_sa})
    if sts_enabled:
        local_sts_origin = f"http://{pfx}-sts.{ns}.svc.cluster.local:8095"
        ca_env.append({"name": "LOCAL_STS_URL", "value": local_sts_origin})
        ca_env.append({"name": "OAUTH_REALM", "value": DEFAULT_REALM_NAME})
        if spec.role == "alpha":
            ca_env.append(
                {
                    "name": "OIDC_JWKS_URL",
                    "value": f"{local_sts_origin}/realms/{DEFAULT_REALM_NAME}/protocol/openid-connect/certs",
                }
            )

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
                            *_identity_addressing_volumes(include_node_locator=True),
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
                                    *_identity_addressing_mounts(include_node_locator=True),
                                    {
                                        "name": "lct-sa-token",
                                        "mountPath": "/var/run/lct-sa",
                                        "readOnly": True,
                                    },
                                ],
                                "livenessProbe": {
                                    "httpGet": {"path": "/healthz", "port": 8090},
                                    "initialDelaySeconds": 15,
                                    "periodSeconds": 10,
                                    "timeoutSeconds": 5,
                                    "failureThreshold": 6,
                                },
                                "readinessProbe": {
                                    "httpGet": {"path": "/healthz", "port": 8090},
                                    "initialDelaySeconds": 1,
                                    "periodSeconds": 2,
                                    "timeoutSeconds": 5,
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
                        "nodePort": int(ca_fed_nodeport),
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
                            *_identity_addressing_volumes(include_node_locator=False),
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
                                    {"name": "LCT_IDENTITY_ADDRESSING", "value": "true"},
                                    {"name": "LCT_SEEDS_DIR", "value": "/etc/lct-seeds"},
                                    {
                                        "name": "LCT_PERSISTED_DESCRIPTORS_FILE",
                                        "value": "/etc/lct-descriptors/descriptors.json",
                                    },
                                    {"name": "LOCAL_CA_URL", "value": local_ca_url},
                                    {"name": "REVOCATION_FEDERATION_PORT", "value": "8492"},
                                    {"name": "LCT_MTLS_RAM_DIR", "value": "/var/run/lct-mtls-ram"},
                                    {"name": "LCT_TRUST_ANCHORS_DIR", "value": "/etc/lct-anchors"},
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
                                "ports": [
                                    {"containerPort": 8092, "name": "rev-internal"},
                                    {"containerPort": 8492, "name": "rev-fed-mtls"},
                                ],
                                "volumeMounts": [
                                    {
                                        "name": "lct-sa-token",
                                        "mountPath": "/var/run/lct-sa",
                                        "readOnly": True,
                                    },
                                    {"name": "lct-mtls-ram", "mountPath": "/var/run/lct-mtls-ram"},
                                    *_identity_addressing_mounts(include_node_locator=False),
                                ],
                                "livenessProbe": {
                                    "httpGet": {"path": "/healthz", "port": 8092},
                                    "initialDelaySeconds": 15,
                                    "periodSeconds": 10,
                                    "timeoutSeconds": 5,
                                    "failureThreshold": 6,
                                },
                                "readinessProbe": {
                                    "httpGet": {"path": "/readyz", "port": 8092},
                                    "initialDelaySeconds": 1,
                                    "periodSeconds": 2,
                                    "timeoutSeconds": 5,
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
                        "nodePort": int(rev_fed_nodeport),
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
                            *_identity_addressing_volumes(include_node_locator=False),
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
                                    {"name": "LCT_IDENTITY_ADDRESSING", "value": "true"},
                                    {"name": "LCT_SEEDS_DIR", "value": "/etc/lct-seeds"},
                                    {
                                        "name": "LCT_PERSISTED_DESCRIPTORS_FILE",
                                        "value": "/etc/lct-descriptors/descriptors.json",
                                    },
                                    {"name": "LOCAL_CA_URL", "value": local_ca_url},
                                    {"name": "REVOCATION_URL", "value": local_rev_url},
                                    {"name": "DIRECTORY_FEDERATION_PORT", "value": "8491"},
                                    {"name": "LCT_MTLS_RAM_DIR", "value": "/var/run/lct-mtls-ram"},
                                    {"name": "LCT_TRUST_ANCHORS_DIR", "value": "/etc/lct-anchors"},
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
                                "ports": [
                                    {"containerPort": 8091, "name": "dir-internal"},
                                    {"containerPort": 8491, "name": "dir-fed-mtls"},
                                ],
                                "volumeMounts": [
                                    {
                                        "name": "lct-sa-token",
                                        "mountPath": "/var/run/lct-sa",
                                        "readOnly": True,
                                    },
                                    {"name": "lct-mtls-ram", "mountPath": "/var/run/lct-mtls-ram"},
                                    *_identity_addressing_mounts(include_node_locator=False),
                                ],
                                "livenessProbe": {
                                    "httpGet": {"path": "/healthz", "port": 8091},
                                    "initialDelaySeconds": 15,
                                    "periodSeconds": 10,
                                    "timeoutSeconds": 5,
                                    "failureThreshold": 6,
                                },
                                "readinessProbe": {
                                    "httpGet": {"path": "/readyz", "port": 8091},
                                    "initialDelaySeconds": 1,
                                    "periodSeconds": 2,
                                    "timeoutSeconds": 5,
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
                        "nodePort": int(dir_fed_nodeport),
                    }
                ],
            },
        },
    ]
    return docs


def render_e2e_sync_service_manifest(
    namespace: str = "lineage-alpha",
    node_port: Optional[int] = None,
) -> Dict[str, Any]:
    """Render the transient NodePort Service created ONLY around Scenario 3B."""
    eff_port = int(node_port) if node_port is not None else allocate_role_ports("alpha")["e2e_sync_hook"]
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
                    "nodePort": eff_port,
                }
            ],
        },
    }


def render_role_k8s_manifests(
    role: str,
    image: str = "lineage-lct:m7",
    llm_url: str = "http://host.docker.internal:11434/v1",
    llm_model: str = "qwen2.5:3b",
    svid_ttl_seconds: int = 1800,
    require_pinned_anchors: bool = True,
    initial_anchors: Optional[Mapping[str, str]] = None,
    include_namespace_and_configmap: bool = True,
    role_ports: Optional[Mapping[str, int]] = None,
    initial_seeds: Sequence[str] = (),
    initial_locator_json: Optional[str] = None,
    sts_engine: str = "lightweight",
    keycloak_image: str = KEYCLOAK_IMAGE,
    delegation_mode: str = "dual",
) -> str:
    """Render complete multi-document YAML manifest for a single multi-host role (zero peer IPs/ports/FQDNs)."""
    if role not in ROLE_SPECS:
        raise ValueError(f"Unknown role: {role!r}")
    spec = ROLE_SPECS[role]
    ns = spec.namespace
    ports = dict(role_ports) if role_ports is not None else allocate_role_ports(role)
    eff_sts_engine = (sts_engine or "lightweight").strip().lower()
    if eff_sts_engine not in ("keycloak", "lightweight", "none"):
        raise ValueError(f"Unsupported sts_engine: {sts_engine!r}")
    sts_enabled = eff_sts_engine != "none"

    docs: List[Dict[str, Any]] = [
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": ns,
                "labels": {"lct.io/trust-domain": spec.trust_domain},
                "annotations": {
                    "lct.io/role-ports-json": json.dumps(ports, sort_keys=True),
                },
            },
        }
    ]
    if include_namespace_and_configmap:
        docs.append(
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "lct-trust-anchors", "namespace": ns},
                "data": dict(initial_anchors or {}),
            }
        )
        docs.append(
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "lct-bootstrap-seeds", "namespace": ns},
                "data": {"seeds": "\n".join(s for s in initial_seeds if s)},
            }
        )
        docs.append(
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "lct-node-locator", "namespace": ns},
                "data": (
                    {"locator.json": initial_locator_json}
                    if initial_locator_json
                    else {}
                ),
            }
        )
        docs.append(
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "lct-learned-descriptors", "namespace": ns},
                "data": {},
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
                                    *_identity_addressing_volumes(include_node_locator=True),
                                ],
                                "containers": [
                                    {
                                        "name": "audit-ca",
                                        "image": image,
                                        "imagePullPolicy": "Never",
                                        "args": ["--role", "audit-tls-ca"],
                                        "env": [
                                            {"name": "LCT_IDENTITY_ADDRESSING", "value": "true"},
                                            {
                                                "name": "LCT_NODE_LOCATOR_FILE",
                                                "value": "/etc/lct-node-locator/locator.json",
                                            },
                                            {
                                                "name": "CA_FEDERATION_PORT",
                                                "value": "8094",
                                            },
                                            {
                                                "name": "CA_KEY_MATERIAL_DIR",
                                                "value": "/var/run/lct-audit-ca-keys",
                                            },
                                            {
                                                "name": "AUDIT_CSR_TOKEN_FILE",
                                                "value": "/var/run/lct-audit-csr/csr_token",
                                            },
                                            {
                                                "name": "LCT_TRUST_ANCHORS_DIR",
                                                "value": "/etc/lct-anchors",
                                            },
                                            {
                                                "name": "LCT_REQUIRE_PINNED_ANCHORS",
                                                "value": "true" if require_pinned_anchors else "false",
                                            },
                                        ],
                                        "ports": [
                                            {"containerPort": 8090, "name": "ca-internal"},
                                            {"containerPort": 8094, "name": "ca-fed-ro"},
                                        ],
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
                                            *_identity_addressing_mounts(include_node_locator=True),
                                        ],
                                        "livenessProbe": {
                                            "httpGet": {"path": "/healthz", "port": 8090},
                                            "initialDelaySeconds": 15,
                                            "periodSeconds": 10,
                                            "timeoutSeconds": 5,
                                            "failureThreshold": 6,
                                        },
                                        "readinessProbe": {
                                            "httpGet": {"path": "/healthz", "port": 8090},
                                            "initialDelaySeconds": 1,
                                            "periodSeconds": 2,
                                            "timeoutSeconds": 5,
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
                {
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": {"name": "audit-ca-federation", "namespace": ns},
                    "spec": {
                        "type": "NodePort",
                        "selector": {"app": "audit-ca"},
                        "ports": [
                            {
                                "name": "ca-fed-ro",
                                "port": 8094,
                                "targetPort": 8094,
                                "nodePort": int(ports["ca_federation"]),
                            }
                        ],
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
                                    *_identity_addressing_volumes(include_node_locator=False),
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
                                            {"name": "LCT_IDENTITY_ADDRESSING", "value": "true"},
                                            {"name": "LCT_SEEDS_DIR", "value": "/etc/lct-seeds"},
                                            {
                                                "name": "LCT_PERSISTED_DESCRIPTORS_FILE",
                                                "value": "/etc/lct-descriptors/descriptors.json",
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
                                            *_identity_addressing_mounts(include_node_locator=False),
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
                                            "timeoutSeconds": 5,
                                            "failureThreshold": 6,
                                        },
                                        "readinessProbe": {
                                            "httpGet": {
                                                "path": "/readyz",
                                                "port": 8093,
                                                "scheme": "HTTPS",
                                            },
                                            "initialDelaySeconds": 2,
                                            "periodSeconds": 2,
                                            "timeoutSeconds": 5,
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
                                "nodePort": int(ports["audit_collector"]),
                            }
                        ],
                    },
                },
            ]
        )
        return yaml.safe_dump_all(docs, sort_keys=False)

    if role == "alpha":
        local_ca = f"http://alpha-ca.{ns}.svc.cluster.local:8090"
        local_dir = f"http://alpha-directory.{ns}.svc.cluster.local:8091"
        local_rev = f"http://alpha-revocation.{ns}.svc.cluster.local:8092"
        local_sts = (
            f"http://alpha-sts.{ns}.svc.cluster.local:8095" if sts_enabled else None
        )
        docs.extend(
            _oauth_sts_docs(
                spec=spec,
                image=image,
                sts_nodeport=ports["oauth_sts"],
                sts_engine=eff_sts_engine,
                keycloak_image=keycloak_image,
                require_pinned_anchors=require_pinned_anchors,
            )
        )
        docs.extend(
            _domain_control_plane_docs(
                spec=spec,
                image=image,
                ca_fed_nodeport=ports["ca_federation"],
                dir_fed_nodeport=ports["directory_federation"],
                rev_fed_nodeport=ports["revocation_federation"],
                svid_ttl_seconds=svid_ttl_seconds,
                require_pinned_anchors=require_pinned_anchors,
                authorized_gateway_sa="e2e-user-gateway",
                sts_enabled=sts_enabled,
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
                dir_url=local_dir,
                rev_url=local_rev,
                node_port=ports["orchestrator-alpha"],
                svid_ttl_seconds=svid_ttl_seconds,
                require_pinned_anchors=require_pinned_anchors,
                llm_url=llm_url,
                llm_model=llm_model,
                agent_skills="travel.orchestrate",
                agent_priority=10,
                agent_display_name="Orchestrator Alpha",
                enable_fault_injection=True,
                delegation_mode=delegation_mode,
                local_sts_url=local_sts,
            )
        )
        gw_env: List[Dict[str, str]] = [
            {"name": "LCT_IDENTITY_ADDRESSING", "value": "true"},
            {"name": "DELEGATION_MODE", "value": delegation_mode},
            {"name": "OAUTH_REALM", "value": DEFAULT_REALM_NAME},
            {
                "name": "OAUTH_CREDENTIALS_FILE",
                "value": "/var/run/lct-oauth/credentials.json",
            },
            {"name": "LCT_LOCATOR_SLOT", "value": "e2e_sync_hook"},
            {
                "name": "LCT_NODE_LOCATOR_FILE",
                "value": "/etc/lct-node-locator/locator.json",
            },
            {
                "name": "LCT_SEEDS_DIR",
                "value": "/etc/lct-seeds",
            },
            {
                "name": "LCT_PERSISTED_DESCRIPTORS_FILE",
                "value": "/etc/lct-descriptors/descriptors.json",
            },
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
                "value": ("true" if require_pinned_anchors else "false"),
            },
            {
                "name": "LCT_SVID_TTL_SECONDS",
                "value": str(int(svid_ttl_seconds)),
            },
            {"name": "ALPHA_CA_URL", "value": local_ca},
            {"name": "ALPHA_DIR_URL", "value": local_dir},
            {"name": "ALPHA_REV_URL", "value": local_rev},
        ]
        if local_sts:
            gw_env.append({"name": "LOCAL_STS_URL", "value": local_sts})
        # User / Operator CLI Gateway (identity-addressed: ZERO peer URL constants!)
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
                                "securityContext": {"fsGroup": 2000},
                                "volumes": [
                                    {"name": "lct-mtls-ram", "emptyDir": {"medium": "Memory"}},
                                    {
                                        "name": "lct-oauth-credentials",
                                        "secret": {
                                            "secretName": "lct-oauth-credentials",
                                            "defaultMode": 0o440,
                                            "optional": True,
                                        },
                                    },
                                    *_identity_addressing_volumes(include_node_locator=True),
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
                                        "env": gw_env,
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
                                                "name": "lct-oauth-credentials",
                                                "mountPath": "/var/run/lct-oauth",
                                                "readOnly": True,
                                            },
                                            *_identity_addressing_mounts(include_node_locator=True),
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
        local_ca = f"http://beta-ca.{ns}.svc.cluster.local:8090"
        local_dir = f"http://beta-directory.{ns}.svc.cluster.local:8091"
        local_rev = f"http://beta-revocation.{ns}.svc.cluster.local:8092"
        local_sts = (
            f"http://beta-sts.{ns}.svc.cluster.local:8095" if sts_enabled else None
        )
        docs.extend(
            _oauth_sts_docs(
                spec=spec,
                image=image,
                sts_nodeport=ports["oauth_sts"],
                sts_engine=eff_sts_engine,
                keycloak_image=keycloak_image,
                require_pinned_anchors=require_pinned_anchors,
            )
        )
        docs.extend(
            _domain_control_plane_docs(
                spec=spec,
                image=image,
                ca_fed_nodeport=ports["ca_federation"],
                dir_fed_nodeport=ports["directory_federation"],
                rev_fed_nodeport=ports["revocation_federation"],
                svid_ttl_seconds=svid_ttl_seconds,
                require_pinned_anchors=require_pinned_anchors,
                sts_enabled=sts_enabled,
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
                dir_url=local_dir,
                rev_url=local_rev,
                node_port=ports["flight-specialist"],
                svid_ttl_seconds=svid_ttl_seconds,
                require_pinned_anchors=require_pinned_anchors,
                llm_url=llm_url,
                llm_model=llm_model,
                agent_skills="travel.flight",
                agent_priority=10,
                agent_display_name="Flight Specialist B1",
                enable_fault_injection=True,
                delegation_mode=delegation_mode,
                local_sts_url=local_sts,
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
                dir_url=local_dir,
                rev_url=local_rev,
                node_port=ports["hotel-specialist-primary"],
                svid_ttl_seconds=svid_ttl_seconds,
                require_pinned_anchors=require_pinned_anchors,
                llm_url=llm_url,
                llm_model=llm_model,
                agent_skills="travel.hotel",
                agent_priority=10,
                agent_display_name="Hotel Specialist Primary B2",
                enable_fault_injection=True,
                specialist_instance="primary",
                delegation_mode=delegation_mode,
                local_sts_url=local_sts,
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
                dir_url=local_dir,
                rev_url=local_rev,
                node_port=ports["hotel-specialist-backup"],
                svid_ttl_seconds=svid_ttl_seconds,
                require_pinned_anchors=require_pinned_anchors,
                llm_url=llm_url,
                llm_model=llm_model,
                agent_skills="travel.hotel",
                agent_priority=20,
                agent_display_name="Hotel Specialist Backup B2-Sub",
                enable_fault_injection=True,
                specialist_instance="backup",
                delegation_mode=delegation_mode,
                local_sts_url=local_sts,
            )
        )
        return yaml.safe_dump_all(docs, sort_keys=False)

    # role == "pay"
    local_ca = f"http://payment-ca.{ns}.svc.cluster.local:8090"
    local_dir = f"http://payment-directory.{ns}.svc.cluster.local:8091"
    local_rev = f"http://payment-revocation.{ns}.svc.cluster.local:8092"
    local_sts = (
        f"http://payment-sts.{ns}.svc.cluster.local:8095" if sts_enabled else None
    )
    docs.extend(
        _oauth_sts_docs(
            spec=spec,
            image=image,
            sts_nodeport=ports["oauth_sts"],
            sts_engine=eff_sts_engine,
            keycloak_image=keycloak_image,
            require_pinned_anchors=require_pinned_anchors,
        )
    )
    docs.extend(
        _domain_control_plane_docs(
            spec=spec,
            image=image,
            ca_fed_nodeport=ports["ca_federation"],
            dir_fed_nodeport=ports["directory_federation"],
            rev_fed_nodeport=ports["revocation_federation"],
            svid_ttl_seconds=svid_ttl_seconds,
            require_pinned_anchors=require_pinned_anchors,
            sts_enabled=sts_enabled,
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
            dir_url=local_dir,
            rev_url=local_rev,
            node_port=ports["settlement-converger"],
            svid_ttl_seconds=svid_ttl_seconds,
            require_pinned_anchors=require_pinned_anchors,
            llm_url=llm_url,
            llm_model=llm_model,
            agent_skills="settlement.converge",
            agent_priority=10,
            agent_display_name="Settlement Converger C",
            enable_fault_injection=True,
            delegation_mode=delegation_mode,
            local_sts_url=local_sts,
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
            dir_url=local_dir,
            rev_url=local_rev,
            node_port=ports["travel-ops-mcp"],
            svid_ttl_seconds=svid_ttl_seconds,
            require_pinned_anchors=require_pinned_anchors,
            is_tool_server=True,
            agent_skills="mcp.travel-ops",
            supported_tools="book_flight,book_hotel,query_flight,query_hotel",
            agent_priority=10,
            agent_display_name="Travel Ops MCP Server",
            delegation_mode=delegation_mode,
            local_sts_url=local_sts,
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
            dir_url=local_dir,
            rev_url=local_rev,
            node_port=ports["payment-vault-mcp"],
            svid_ttl_seconds=svid_ttl_seconds,
            require_pinned_anchors=require_pinned_anchors,
            is_tool_server=True,
            agent_skills="mcp.payment-vault",
            supported_tools="execute_settlement,audit_ledger",
            agent_priority=10,
            agent_display_name="Payment Vault MCP Server",
            delegation_mode=delegation_mode,
            local_sts_url=local_sts,
        )
    )
    return yaml.safe_dump_all(docs, sort_keys=False)


def _sanitize_coredns_in_cluster(kube_context: str) -> None:
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
    orig_cf = cm["data"]["Corefile"]
    cleaned_cf = sanitize_coredns_corefile(orig_cf)
    if cleaned_cf == orig_cf:
        return
    patched = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "coredns", "namespace": "kube-system"},
        "data": {"Corefile": cleaned_cf},
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


def _read_existing_oauth_creds_from_cluster(role: str) -> Optional[Dict[str, Any]]:
    spec = ROLE_SPECS[role]
    probe = subprocess.run(
        [
            "kubectl",
            "--context",
            spec.kube_context,
            "-n",
            spec.namespace,
            "get",
            "secret",
            "lct-oauth-credentials",
            "-o",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    if probe.returncode != 0:
        return None
    try:
        sec_obj = json.loads(probe.stdout)
        raw_b64 = (sec_obj.get("data") or {}).get("credentials.json")
        if not raw_b64:
            return None
        return json.loads(base64.b64decode(raw_b64).decode("utf-8"))
    except Exception:
        return None


def _ensure_in_memory_oauth_secret(
    role: str,
    sts_engine: str = "lightweight",
    regenerate: bool = False,
    import_creds_json: Optional[str] = None,
) -> Dict[str, Any]:
    """Create or reuse in-memory OAuth 2.0 / Keycloak realm K8s Secrets (never written to host disk)."""
    if role == "audit":
        return {"role": role, "oauth_secret": "skipped_for_audit"}
    spec = ROLE_SPECS[role]
    eng = (sts_engine or "lightweight").strip().lower()
    if eng == "none":
        return {"role": role, "oauth_secret": "disabled"}

    existing_creds = None if regenerate else _read_existing_oauth_creds_from_cluster(role)
    seed_creds: Optional[Dict[str, Any]] = None
    if import_creds_json:
        seed_creds = json.loads(import_creds_json)
    elif existing_creds is not None:
        seed_creds = existing_creds
    elif role in ("beta", "pay"):
        # If `alpha` is co-located on this host (e.g., 4-cluster rehearsal), share client secrets in RAM
        seed_creds = _read_existing_oauth_creds_from_cluster("alpha")

    need_kc_realm = eng == "keycloak"
    kc_exists = False
    if need_kc_realm and not regenerate:
        p_kc = subprocess.run(
            [
                "kubectl",
                "--context",
                spec.kube_context,
                "-n",
                spec.namespace,
                "get",
                "secret",
                "lct-keycloak-realm",
            ],
            capture_output=True,
            text=True,
        )
        kc_exists = p_kc.returncode == 0

    if existing_creds is not None and not import_creds_json and (not need_kc_realm or kc_exists):
        return {"role": role, "sts_engine": eng, "status": "reused"}

    bundle = generate_keycloak_realm_bundle(
        realm_name=str((seed_creds or {}).get("realm") or DEFAULT_REALM_NAME),
        explicit_user_passwords=(seed_creds or {}).get("users"),
        explicit_client_secrets=(seed_creds or {}).get("clients"),
    )

    creds_sec = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "lct-oauth-credentials", "namespace": spec.namespace},
        "type": "Opaque",
        "stringData": {"credentials.json": bundle.runtime_credentials_json()},
    }
    subprocess.run(
        ["kubectl", "--context", spec.kube_context, "apply", "-f", "-"],
        input=json.dumps(creds_sec),
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
    )

    if need_kc_realm and (regenerate or not kc_exists or import_creds_json):
        kc_sec = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "lct-keycloak-realm", "namespace": spec.namespace},
            "type": "Opaque",
            "stringData": {
                "lct-realm.json": bundle.realm_json(),
                "admin_username": bundle.admin_username,
                "admin_password": bundle.admin_password,
            },
        }
        subprocess.run(
            ["kubectl", "--context", spec.kube_context, "apply", "-f", "-"],
            input=json.dumps(kc_sec),
            text=True,
            check=True,
            stdout=subprocess.DEVNULL,
        )
    return {"role": role, "sts_engine": eng, "status": "applied"}


def _cli_main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="LCT Multi-Host Config & Bootstrap Utility")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_roles = sub.add_parser("parse-roles")
    p_roles.add_argument("--roles", required=True)

    p_alloc = sub.add_parser("allocate-ports")
    p_alloc.add_argument("--roles", required=True)
    p_alloc.add_argument("--base-port", type=int, default=None)
    p_alloc.add_argument("--port-override", action="append", default=[])
    p_alloc.add_argument("--check-host-free", action="store_true")

    p_kind = sub.add_parser("kind-config")
    p_kind.add_argument("--role", required=True)
    p_kind.add_argument("--ports-json", default="")

    p_dns = sub.add_parser("sanitize-coredns")
    p_dns.add_argument("--roles", required=True)

    p_ca = sub.add_parser("ensure-ca-secret")
    p_ca.add_argument("--role", required=True)
    p_ca.add_argument("--regenerate", action="store_true")

    p_oauth = sub.add_parser("ensure-oauth-secret")
    p_oauth.add_argument("--role", required=True)
    p_oauth.add_argument("--sts-engine", default="lightweight")
    p_oauth.add_argument("--regenerate", action="store_true")
    p_oauth.add_argument("--oauth-creds-file", default="")

    p_man = sub.add_parser("render-manifest")
    p_man.add_argument("--role", required=True)
    p_man.add_argument("--image", default="lineage-lct:m7")
    p_man.add_argument("--llm-url", default="http://host.docker.internal:11434/v1")
    p_man.add_argument("--llm-model", default="qwen2.5:3b")
    p_man.add_argument("--svid-ttl", type=int, default=1800)
    p_man.add_argument("--no-require-pins", action="store_true")
    p_man.add_argument("--ports-json", default="")
    p_man.add_argument("--seed", action="append", default=[])
    p_man.add_argument("--sts-engine", default="lightweight")
    p_man.add_argument("--keycloak-image", default=KEYCLOAK_IMAGE)
    p_man.add_argument("--delegation-mode", default="dual")
    p_man.add_argument(
        "--skip-configmap",
        action="store_true",
        help="Do not overwrite existing ConfigMaps on re-apply",
    )

    p_skew = sub.add_parser("check-skew")
    p_skew.add_argument("--url", required=True)
    p_skew.add_argument("--timeout", type=float, default=3.0)

    args = parser.parse_args(argv)

    if args.cmd == "parse-roles":
        print(" ".join(parse_roles_csv(args.roles)))
        return 0

    if args.cmd == "allocate-ports":
        roles = parse_roles_csv(args.roles)
        ovr = parse_port_overrides(args.port_override)
        reserved: Set[int] = set()
        out_map: Dict[str, Dict[str, int]] = {}
        for idx, r in enumerate(roles):
            existing = read_cluster_role_ports(r)
            if existing is not None:
                out_map[r] = existing
                reserved.update(existing.values())
                continue
            r_base = (args.base_port + idx * 50) if args.base_port is not None else None
            r_ports = allocate_role_ports(
                r,
                base_port=r_base,
                port_overrides=ovr,
                check_host_free=args.check_host_free,
                reserved_ports=reserved,
            )
            out_map[r] = r_ports
            reserved.update(r_ports.values())
        print(json.dumps(out_map, sort_keys=True))
        return 0

    if args.cmd == "kind-config":
        rp = json.loads(args.ports_json) if args.ports_json.strip() else None
        sys.stdout.write(render_kind_cluster_config(args.role, role_ports=rp))
        return 0

    if args.cmd == "sanitize-coredns":
        roles = parse_roles_csv(args.roles)
        for r in roles:
            _sanitize_coredns_in_cluster(ROLE_SPECS[r].kube_context)
        return 0

    if args.cmd == "ensure-ca-secret":
        print(_ensure_in_memory_ca_secret(args.role, regenerate=args.regenerate))
        return 0

    if args.cmd == "ensure-oauth-secret":
        imp_json: Optional[str] = None
        if args.oauth_creds_file:
            with open(args.oauth_creds_file, "r", encoding="utf-8") as fh:
                imp_json = fh.read()
        res_oauth = _ensure_in_memory_oauth_secret(
            role=args.role,
            sts_engine=args.sts_engine,
            regenerate=args.regenerate,
            import_creds_json=imp_json,
        )
        print(json.dumps(res_oauth))
        return 0

    if args.cmd == "render-manifest":
        from lineage.common.locators import normalize_seed_endpoint

        rp = json.loads(args.ports_json) if args.ports_json.strip() else read_cluster_role_ports(args.role)
        seeds = [normalize_seed_endpoint(s) for s in (args.seed or []) if s and s.strip()]
        sys.stdout.write(
            render_role_k8s_manifests(
                role=args.role,
                image=args.image,
                llm_url=args.llm_url,
                llm_model=args.llm_model,
                svid_ttl_seconds=args.svid_ttl,
                require_pinned_anchors=(not args.no_require_pins),
                include_namespace_and_configmap=(not args.skip_configmap),
                role_ports=rp,
                initial_seeds=seeds,
                sts_engine=args.sts_engine,
                keycloak_image=args.keycloak_image,
                delegation_mode=args.delegation_mode,
            )
        )
        return 0

    if args.cmd == "check-skew":
        import httpx

        clean_u = args.url.strip().rstrip("/")
        if not clean_u.startswith("http://"):
            clean_u = f"http://{clean_u}"
        try:
            with httpx.Client(verify=True, timeout=args.timeout, trust_env=False) as cli:
                r = cli.get(f"{clean_u}/healthz")
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
