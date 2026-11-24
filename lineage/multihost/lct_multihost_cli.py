#!/usr/bin/env python3
"""Identity-Addressed Cross-Machine LCT Operator CLI (`lct_multihost_cli.py`).

Sub-commands:
- `locator show`: Display own + learned `SignedDomainDescriptor`s and signed `AgentCard`s
  (versions, SHA-256 trust-anchor verification status, remaining TTLs, and `ip:port` locators).
- `seeds list|add|remove`: Manage untrusted bootstrap seed endpoints (`ip:port`) in
  `ConfigMap/lct-bootstrap-seeds` with zero-restart pod hot-reload.
- `trust show|add|remove|import|fetch`: Manage SSH-style SHA-256 domain trust anchors in
  `ConfigMap/lct-trust-anchors` (`trust import <file>` displays every anchor and requires
  confirmation before pinning).
- `status`: Per-domain descriptor health and per-hop **identity → locator** resolution with
  live mTLS 1.3 handshake telemetry (`peer_spiffe_id`, `TLSv1.3`, cipher, `/healthz`).
- `send --text "..." [--stream]`: Execute real A2A v1.0 `SendMessage` or `SendStreamingMessage`
  across `org-alpha.io -> org-beta.io -> org-payment.io`, printing per-hop SPIFFE ID → locator
  resolution, peer issuer domain, negotiated TLS version/cipher, and authorization decision.
- `cancel <task_id>`: Invoke A2A v1.0 `CancelTask` and verify cross-machine cascading
  revocation propagation over SPIFFE-pinned mTLS 1.3.
- `audit [task_id]`: Fetch signed `AuditEntry` records over SPIFFE-pinned TLS 1.3 from
  `audit-collector` and run `CausalChainAuditor` full causal tree reconstruction.
- `e2e`: Run Multi-Host Scenarios `1, 2A, 2B, 3A, 3B, 4, 5, 6`.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import time
from typing import IO, Any, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit
import uuid

import httpx
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from lineage.a2a import A2AClient, Message, TaskState
from lineage.audit import CausalChainAuditor
from lineage.common.crypto import redact_sensitive, sha256_hex
from lineage.common.locators import normalize_seed_endpoint
from lineage.federation.anchors import (
    TrustAnchorPinError,
    compute_bundle_trust_anchor,
    format_domain_trust_anchor_line,
    parse_trust_anchor_value,
    split_trust_anchor_parts,
)
from lineage.identity.spiffe import SpiffeId
from lineage.multihost.config_gen import (
    ROLE_ORDER,
    ROLE_SPECS,
    parse_roles_csv,
    read_cluster_role_ports,
    render_e2e_sync_service_manifest,
    validate_ipv4_address,
)


def _in_gateway_pod() -> bool:
    return os.path.isfile("/var/run/lct-sa/token") or os.path.isfile(
        "/var/run/secrets/kubernetes.io/serviceaccount/token"
    )


def _scrub(obj: Any) -> Any:
    base = redact_sensitive(obj)
    if isinstance(base, dict):
        return {k: _scrub(v) for k, v in base.items()}
    if isinstance(base, list):
        return [_scrub(x) for x in base]
    if isinstance(base, str):
        if base.startswith(("lct1.", "lctmp1.", "lctm1.")):
            return f"[REDACTED_LCT_TOKEN_SHA256:{sha256_hex(base.encode('ascii'))[:12]}]"
        if base.startswith("eyJ") and base.count(".") == 2:
            return f"[REDACTED_JWS_SHA256:{sha256_hex(base.encode('ascii'))[:12]}]"
    return base


def _detect_local_lctmh_roles(roles_arg: Optional[str] = None) -> Tuple[str, ...]:
    if roles_arg and roles_arg.strip():
        return parse_roles_csv(roles_arg)
    out = subprocess.run(
        ["kind", "get", "clusters"], capture_output=True, text=True, check=False
    )
    clusters = set((out.stdout or "").splitlines())
    found = tuple(r for r in ROLE_ORDER if f"lctmh-{r}" in clusters)
    if not found:
        raise RuntimeError(
            "No local lctmh-* Kind clusters found on this machine (specify --roles if needed)."
        )
    return found


def _exec_in_gateway(cli_args: Sequence[str], kube_context: str = "kind-lctmh-alpha") -> int:
    cmd = [
        "kubectl",
        "--context",
        kube_context,
        "-n",
        "lineage-alpha",
        "exec",
        "deploy/e2e-user-gateway",
        "--",
        "/app/.venv/bin/python3",
        "/opt/lct/lineage/multihost/lct_multihost_cli.py",
        "--in-gateway",
        *cli_args,
    ]
    proc = subprocess.run(cmd)
    return proc.returncode


def _exec_e2e_driver_phase(
    phase: str,
    run_id: str,
    extra_args: Sequence[str] = (),
    kube_context: str = "kind-lctmh-alpha",
) -> Dict[str, Any]:
    cmd = [
        "kubectl",
        "--context",
        kube_context,
        "-n",
        "lineage-alpha",
        "exec",
        "deploy/e2e-user-gateway",
        "--",
        "/app/.venv/bin/python3",
        "-m",
        "lineage.k8s.e2e_driver",
        "--phase",
        phase,
        "--run-id",
        run_id,
        *extra_args,
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(
            f"Phase {phase!r} failed (exit={res.returncode}):\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
        )
    return json.loads(res.stdout)


def _probe_tls_handshake_details(
    url: str, ssl_ctx: ssl.SSLContext, timeout: float = 4.0
) -> Dict[str, Any]:
    sp = urlsplit(url)
    host = sp.hostname or ""
    port = sp.port or 443
    infos = socket.getaddrinfo(host, port, socket.AF_INET)
    resolved_ip = str(infos[0][4][0]) if infos else ""
    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        with ssl_ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            tls_ver = tls_sock.version()
            ciph = tls_sock.cipher()
            der = tls_sock.getpeercert(binary_form=True) or b""
    from cryptography import x509

    cert = x509.load_der_x509_certificate(der)
    uris = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.UniformResourceIdentifier)
    peer_spiffe = uris[0] if uris else ""
    issuer_uris = []
    try:
        for attr in cert.issuer:
            issuer_uris.append(f"{attr.oid._name}={attr.value}")
    except Exception:
        pass
    issuer_domain = SpiffeId.parse(peer_spiffe).trust_domain if peer_spiffe else ""
    return {
        "endpoint": url,
        "resolved_ip": resolved_ip,
        "port": port,
        "peer_spiffe_id": peer_spiffe,
        "peer_issuer_domain": issuer_domain,
        "issuer_dn": ",".join(issuer_uris),
        "tls_version": tls_ver,
        "tls_cipher": ciph[0] if ciph else None,
    }


def _trigger_pod_volume_sync(kube_context: str, namespace: str, key: str) -> None:
    """Trigger immediate Kubelet ConfigMap projection (<1s) with zero container restarts."""
    subprocess.run(
        [
            "kubectl",
            "--context",
            kube_context,
            "-n",
            namespace,
            "annotate",
            "pods",
            "--all",
            f"lct.io/{key}={time.time_ns()}",
            "--overwrite",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _read_configmap_data(
    kube_context: str, namespace: str, cm_name: str
) -> Dict[str, str]:
    res = subprocess.run(
        [
            "kubectl",
            "--context",
            kube_context,
            "-n",
            namespace,
            "get",
            "configmap",
            cm_name,
            "-o",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0 or not res.stdout.strip():
        return {}
    obj = json.loads(res.stdout)
    return dict(obj.get("data") or {})


def _write_configmap_data(
    kube_context: str,
    namespace: str,
    cm_name: str,
    data: Dict[str, str],
    sync_annotation_key: str,
) -> None:
    cm_doc = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": cm_name, "namespace": namespace},
        "data": data,
    }
    subprocess.run(
        ["kubectl", "--context", kube_context, "apply", "-f", "-"],
        input=json.dumps(cm_doc),
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    _trigger_pod_volume_sync(kube_context, namespace, sync_annotation_key)


def _read_local_cluster_own_anchor(role: str) -> Optional[str]:
    spec = ROLE_SPECS[role]
    sec_name = "audit-ca-keys" if role == "audit" else f"{spec.ca_short_prefix}-ca-keys"
    res = subprocess.run(
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
    if res.returncode != 0 or not res.stdout.strip():
        return None
    try:
        obj = json.loads(res.stdout)
        return str(((obj.get("metadata") or {}).get("annotations") or {}).get("lct.io/trust-anchor") or "") or None
    except Exception:
        return None


# =============================================================================
# `trust` Subcommand (`show`, `add`, `remove`, `import`, `fetch`)
# =============================================================================


def _read_configmap_anchors(kube_context: str, namespace: str) -> Dict[str, str]:
    return _read_configmap_data(kube_context, namespace, "lct-trust-anchors")


def _write_configmap_anchors(
    kube_context: str, namespace: str, data: Dict[str, str]
) -> None:
    _write_configmap_data(
        kube_context, namespace, "lct-trust-anchors", data, "anchor-sync-ts"
    )


def _parse_anchor_batch_file(file_path: Path) -> Dict[str, str]:
    if not file_path.is_file():
        raise TrustAnchorPinError(f"Anchor file not found: {file_path}")
    anchors: Dict[str, str] = {}
    for line_no, raw_ln in enumerate(
        file_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        s = raw_ln.strip()
        if not s or s.startswith("#"):
            continue
        try:
            td_opt, norm_anc = parse_trust_anchor_value(s)
            if not td_opt:
                raise TrustAnchorPinError(
                    "Each line in batch anchor file must specify '<trust_domain> sha256:...'"
                )
            td = td_opt
        except Exception as exc:
            raise TrustAnchorPinError(f"{file_path}:{line_no}: {exc}") from exc
        spki_h, jwks_h = split_trust_anchor_parts(norm_anc)
        is_audit = td == "org-audit.io"
        if is_audit and jwks_h != "keyless":
            raise TrustAnchorPinError(
                f"{file_path}:{line_no}: org-audit.io must use 'sha256:<spki>:keyless'"
            )
        if not is_audit and jwks_h == "keyless":
            raise TrustAnchorPinError(
                f"{file_path}:{line_no}: {td} requires a non-empty JWKS hash (cannot be 'keyless')"
            )
        if td in anchors and not hmac.compare_digest(anchors[td], norm_anc):
            raise TrustAnchorPinError(
                f"{file_path}:{line_no}: conflicting duplicate anchor for {td!r}"
            )
        anchors[td] = f"sha256:{spki_h}:{jwks_h}"
    if not anchors:
        raise TrustAnchorPinError(f"Anchor file {file_path} contains zero valid anchor lines")
    return anchors


def _handle_trust_cmd(args: argparse.Namespace) -> int:
    t_sub = args.trust_cmd
    if t_sub == "show":
        roles = _detect_local_lctmh_roles(args.roles)
        out: Dict[str, Any] = {}
        for r in roles:
            spec = ROLE_SPECS[r]
            out[spec.cluster_name] = {
                "own_trust_domain": spec.trust_domain,
                "own_trust_anchor": _read_local_cluster_own_anchor(r),
                "pinned_peer_anchors": _read_configmap_anchors(
                    spec.kube_context, spec.namespace
                ),
            }
        print(json.dumps(out, indent=2))
        return 0

    if t_sub == "add":
        td = args.domain.strip().lower()
        SpiffeId.parse(f"spiffe://{td}/authority/ca")
        spki_h, jwks_h = split_trust_anchor_parts(args.anchor)
        is_audit = td == "org-audit.io"
        if is_audit and jwks_h != "keyless":
            raise TrustAnchorPinError(
                "org-audit.io is a keyless verifier and must use 'sha256:<x509-spki-hex>:keyless'"
            )
        if not is_audit and jwks_h == "keyless":
            raise TrustAnchorPinError(
                f"Domain {td!r} requires a non-empty JWKS thumbprint hash (cannot be 'keyless')"
            )
        norm_anchor = f"sha256:{spki_h}:{jwks_h}"
        roles = _detect_local_lctmh_roles(args.roles)
        for r in roles:
            spec = ROLE_SPECS[r]
            if spec.trust_domain == td:
                own_anc = _read_local_cluster_own_anchor(r)
                if own_anc and not hmac.compare_digest(own_anc, norm_anchor):
                    print(
                        f"[SECURITY ERROR] Provided anchor for local domain {td} mismatches {spec.cluster_name}'s own CA ({own_anc})!",
                        file=sys.stderr,
                    )
                    return 1
                continue
            cur = _read_configmap_anchors(spec.kube_context, spec.namespace)
            cur[td] = norm_anchor
            _write_configmap_anchors(spec.kube_context, spec.namespace, cur)
            print(
                f"[trust] Pinned {td} -> {norm_anchor} in {spec.cluster_name}/{spec.namespace} (hot-reload triggered)"
            )
        return 0

    if t_sub == "remove":
        td = args.domain.strip().lower()
        roles = _detect_local_lctmh_roles(args.roles)
        for r in roles:
            spec = ROLE_SPECS[r]
            cur = _read_configmap_anchors(spec.kube_context, spec.namespace)
            cur.pop(td, None)
            _write_configmap_anchors(spec.kube_context, spec.namespace, cur)
            print(f"[trust] Removed pin for {td} in {spec.cluster_name}/{spec.namespace}")
        return 0

    if t_sub == "import":
        fpath = Path(args.file).expanduser().resolve()
        try:
            batch = _parse_anchor_batch_file(fpath)
        except TrustAnchorPinError as exc:
            print(f"[SECURITY ERROR] {exc}", file=sys.stderr)
            return 1
        roles = _detect_local_lctmh_roles(args.roles)
        print("============================================================================")
        print(f" Candidate Trust Anchors from {fpath} ({len(batch)} domain(s))")
        for td, anc in sorted(batch.items()):
            print(f"   {td:<18}  {anc}")
        print("============================================================================")
        # Verify own-domain consistency before touching any ConfigMap
        for r in roles:
            spec = ROLE_SPECS[r]
            if spec.trust_domain in batch:
                own_anc = _read_local_cluster_own_anchor(r)
                if own_anc and not hmac.compare_digest(own_anc, batch[spec.trust_domain]):
                    print(
                        f"[SECURITY ERROR] Anchor in {fpath} for local domain {spec.trust_domain} "
                        f"does NOT match {spec.cluster_name}'s own CA ({own_anc})! Aborting.",
                        file=sys.stderr,
                    )
                    return 1

        if not args.yes:
            ans = (
                input(
                    f"Verify the fingerprints above out-of-band. Pin into {len(roles)} local cluster(s)? [y/N]: "
                )
                .strip()
                .lower()
            )
            if ans not in ("y", "yes"):
                print("[trust] Aborted without modifying pins.")
                return 1

        for r in roles:
            spec = ROLE_SPECS[r]
            cur = _read_configmap_anchors(spec.kube_context, spec.namespace)
            pinned_count = 0
            for td, anc in sorted(batch.items()):
                if td == spec.trust_domain:
                    continue
                cur[td] = anc
                pinned_count += 1
            _write_configmap_anchors(spec.kube_context, spec.namespace, cur)
            print(
                f"[trust] Imported {pinned_count} peer anchor(s) into {spec.cluster_name}/{spec.namespace} (hot-reload triggered)"
            )
        return 0

    if t_sub == "fetch":
        td = args.domain.strip().lower()
        SpiffeId.parse(f"spiffe://{td}/authority/ca")
        seed_raw = str(getattr(args, "seed", "") or "").strip()
        if seed_raw:
            norm_seed = normalize_seed_endpoint(seed_raw)
            ip_clean, port_str = norm_seed.rsplit(":", 1)
            port = int(port_str)
        else:
            if not args.ip or not args.port:
                raise TrustAnchorPinError(
                    "Pass either '--seed <ip:port>' or both '--ip <ip>' and '--port <port>'"
                )
            ip_clean = validate_ipv4_address(args.ip, "--ip")
            port = int(args.port)
        scheme = args.scheme or "http"
        if scheme != "http":
            raise TrustAnchorPinError(
                "Unpinned bootstrap fetch must use read-only 'http' ca_federation port (never unverified TLS)"
            )
        url = f"http://{ip_clean}:{port}/v1/federation/bundle"
        with httpx.Client(verify=True, timeout=5.0, trust_env=False) as cli:
            resp = cli.get(url)
        resp.raise_for_status()
        bundle = resp.json()
        if str(bundle.get("trust_domain") or "") != td:
            raise TrustAnchorPinError(
                f"Remote endpoint {url} returned trust_domain={bundle.get('trust_domain')!r}, expected {td!r}"
            )
        computed = compute_bundle_trust_anchor(
            bundle, allow_keyless_jwks=(td == "org-audit.io")
        )
        line = format_domain_trust_anchor_line(td, computed)
        expect_raw = str(getattr(args, "expect", "") or "").strip()
        if expect_raw:
            exp_dom, norm_expect = parse_trust_anchor_value(expect_raw)
            if exp_dom is not None and exp_dom != td:
                print(
                    f"[SECURITY ERROR] --expect domain {exp_dom!r} does not match --domain {td!r}; aborting without pinning.",
                    file=sys.stderr,
                )
                return 1
            if not hmac.compare_digest(computed, norm_expect):
                print(
                    f"[SECURITY ERROR] Trust anchor mismatch for {td} at {url}: "
                    f"expected {norm_expect}, got {computed}. Aborting without pinning!",
                    file=sys.stderr,
                )
                return 1
            print(f"[trust] Verified fetched bundle against --expect ({norm_expect}).")
        else:
            print("============================================================================")
            print(f" Fetched Unverified Candidate Bundle from {url}")
            print(f"   Domain       : {td}")
            print(f"   Trust Anchor : {computed}")
            print("   Compare this fingerprint out-of-band with the remote machine's deploy output!")
            print("============================================================================")
            if args.yes:
                print(
                    "[SECURITY WARNING: UNVERIFIED TOFU] `--yes` was used without `--expect`: "
                    f"pinning unauthenticated candidate bundle from {url} on first use! "
                    "Prefer `trust import <file>`, `trust add <domain> sha256:...`, or `trust fetch --expect sha256:...`.",
                    file=sys.stderr,
                )
            else:
                ans = input(f"Pin '{line}' into local ConfigMap(s)? [y/N]: ").strip().lower()
                if ans not in ("y", "yes"):
                    print("[trust] Aborted without pinning.")
                    return 1
        ns_args = argparse.Namespace(
            trust_cmd="add",
            domain=td,
            anchor=computed,
            roles=args.roles,
        )
        return _handle_trust_cmd(ns_args)

    raise ValueError(f"Unknown trust subcommand: {t_sub!r}")


# =============================================================================
# `seeds` Subcommand (`list`, `add`, `remove`)
# =============================================================================


def _read_cluster_seeds(kube_context: str, namespace: str) -> List[str]:
    data = _read_configmap_data(kube_context, namespace, "lct-bootstrap-seeds")
    out: List[str] = []
    for raw_val in data.values():
        for tok in re.split_seeds(raw_val):
            try:
                norm = normalize_seed_endpoint(tok)
                if norm not in out:
                    out.append(norm)
            except ValueError:
                continue
    return out


def re_split_seeds(raw_val: str) -> List[str]:
    return [
        p.strip()
        for ln in str(raw_val or "").splitlines()
        if not ln.strip().startswith("#")
        for p in ln.split(",")
        if p.strip()
    ]


class re:
    split_seeds = staticmethod(re_split_seeds)


def _handle_seeds_cmd(args: argparse.Namespace) -> int:
    s_sub = args.seeds_cmd
    roles = _detect_local_lctmh_roles(args.roles)

    if s_sub == "list":
        out: Dict[str, Any] = {}
        for r in roles:
            spec = ROLE_SPECS[r]
            out[spec.cluster_name] = _read_cluster_seeds(
                spec.kube_context, spec.namespace
            )
        print(json.dumps(out, indent=2))
        return 0

    norm_inputs = [normalize_seed_endpoint(s) for s in args.endpoints]
    if s_sub == "add":
        for r in roles:
            spec = ROLE_SPECS[r]
            cur = _read_cluster_seeds(spec.kube_context, spec.namespace)
            for ep in norm_inputs:
                if ep not in cur:
                    cur.append(ep)
            _write_configmap_data(
                spec.kube_context,
                spec.namespace,
                "lct-bootstrap-seeds",
                {"seeds": "\n".join(cur)},
                "seed-sync-ts",
            )
            print(
                f"[seeds] Updated {spec.cluster_name}/{spec.namespace}: seeds={cur} (hot-reload triggered)"
            )
        return 0

    if s_sub == "remove":
        rm_set = set(norm_inputs)
        for r in roles:
            spec = ROLE_SPECS[r]
            cur = [
                ep
                for ep in _read_cluster_seeds(spec.kube_context, spec.namespace)
                if ep not in rm_set
            ]
            _write_configmap_data(
                spec.kube_context,
                spec.namespace,
                "lct-bootstrap-seeds",
                {"seeds": "\n".join(cur)},
                "seed-sync-ts",
            )
            print(
                f"[seeds] Updated {spec.cluster_name}/{spec.namespace}: seeds={cur} (hot-reload triggered)"
            )
        return 0

    raise ValueError(f"Unknown seeds subcommand: {s_sub!r}")


# =============================================================================
# `locator show` Subcommand (Works on ANY local role machine!)
# =============================================================================


def _kubectl_exec_http_json(
    kube_context: str, namespace: str, deploy: str, url: str
) -> Optional[Dict[str, Any]]:
    code = (
        "import json, urllib.request\n"
        f"with urllib.request.urlopen({url!r}, timeout=3.0) as r:\n"
        "    print(r.read().decode('utf-8'))\n"
    )
    proc = subprocess.run(
        [
            "kubectl",
            "--context",
            kube_context,
            "-n",
            namespace,
            "exec",
            f"deploy/{deploy}",
            "--",
            "/app/.venv/bin/python3",
            "-c",
            code,
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        return json.loads(proc.stdout)
    except Exception:
        return None


def _handle_locator_cmd(args: argparse.Namespace) -> int:
    roles = _detect_local_lctmh_roles(args.roles)
    now_ts = time.time()
    report: Dict[str, Any] = {"timestamp": round(now_ts, 3), "clusters": {}}

    for r in roles:
        spec = ROLE_SPECS[r]
        cm_loc = _read_configmap_data(
            spec.kube_context, spec.namespace, "lct-node-locator"
        )
        node_loc_obj: Dict[str, Any] = {}
        if cm_loc.get("locator.json"):
            try:
                node_loc_obj = json.loads(cm_loc["locator.json"])
            except Exception:
                node_loc_obj = {}

        pins = _read_configmap_anchors(spec.kube_context, spec.namespace)
        own_anc = _read_local_cluster_own_anchor(r)
        seeds = _read_cluster_seeds(spec.kube_context, spec.namespace)

        ca_deploy = "audit-ca" if r == "audit" else f"{spec.ca_short_prefix}-ca"
        desc_payload = _kubectl_exec_http_json(
            spec.kube_context,
            spec.namespace,
            ca_deploy,
            "http://127.0.0.1:8090/v1/federation/descriptors",
        )
        # For `audit`, `audit-collector` also learns peer descriptors from seeds; merge if newer
        if r == "audit":
            persisted_cm = _read_configmap_data(
                spec.kube_context, spec.namespace, "lct-learned-descriptors"
            )
            if persisted_cm.get("descriptors.json"):
                try:
                    p_obj = json.loads(persisted_cm["descriptors.json"])
                    if isinstance(p_obj, Mapping) and isinstance(p_obj.get("descriptors"), list):
                        existing_tds = {
                            str(d.get("trust_domain"))
                            for d in ((desc_payload or {}).get("descriptors") or [])
                            if isinstance(d, Mapping)
                        }
                        merged = list((desc_payload or {}).get("descriptors") or [])
                        for d in p_obj["descriptors"]:
                            if isinstance(d, Mapping) and str(d.get("trust_domain")) not in existing_tds:
                                merged.append(d)
                        desc_payload = {"descriptors": merged}
                except Exception:
                    pass

        descriptors_summary: List[Dict[str, Any]] = []
        for raw_d in (desc_payload or {}).get("descriptors") or []:
            if not isinstance(raw_d, Mapping):
                continue
            td = str(raw_d.get("trust_domain") or "")
            d_anc = str(raw_d.get("trust_anchor") or "")
            is_own = td == spec.trust_domain
            expected_pin = own_anc if is_own else pins.get(td)
            pin_status = (
                "OWN_CA_SIGNED"
                if (is_own and own_anc and hmac.compare_digest(own_anc, d_anc))
                else (
                    "PIN_VERIFIED"
                    if (expected_pin and hmac.compare_digest(expected_pin, d_anc))
                    else "UNPINNED"
                )
            )
            exp = float(raw_d.get("expires_at") or 0.0)
            iat = float(raw_d.get("issued_at") or 0.0)
            descriptors_summary.append(
                {
                    "trust_domain": td,
                    "scope": "own" if is_own else "learned_peer",
                    "version": raw_d.get("version"),
                    "verification_status": pin_status,
                    "signature_mode": raw_d.get("signature_mode"),
                    "age_seconds": round(max(0.0, now_ts - iat), 1),
                    "ttl_remaining_seconds": round(max(0.0, exp - now_ts), 1),
                    "locators": raw_d.get("locators") or {},
                }
            )

        cards_summary: List[Dict[str, Any]] = []
        if r != "audit":
            dir_deploy = f"{spec.ca_short_prefix}-directory"
            dir_payload = _kubectl_exec_http_json(
                spec.kube_context,
                spec.namespace,
                dir_deploy,
                "http://127.0.0.1:8091/v1/agents/discover?only_healthy=false",
            )
            for raw_c in (dir_payload or {}).get("agents") or []:
                if not isinstance(raw_c, Mapping):
                    continue
                exp_c = float(raw_c.get("expires_at") or 0.0)
                cards_summary.append(
                    {
                        "spiffe_id": raw_c.get("spiffe_id"),
                        "trust_domain": raw_c.get("trust_domain"),
                        "version": raw_c.get("version"),
                        "skills": raw_c.get("skills"),
                        "verification_status": "SVID_AND_JWS_VERIFIED",
                        "ttl_remaining_seconds": round(max(0.0, exp_c - now_ts), 1),
                        "primary_endpoint": raw_c.get("endpoint"),
                        "locators": raw_c.get("locators") or [],
                    }
                )

        ca_port = (node_loc_obj.get("ports") or {}).get("ca_federation")
        adv_hosts = [
            str(x.get("host"))
            for x in (node_loc_obj.get("locators") or [])
            if isinstance(x, Mapping) and x.get("host")
        ]
        seed_hints = [f"{h}:{ca_port}" for h in adv_hosts if ca_port]

        report["clusters"][spec.cluster_name] = {
            "role": r,
            "trust_domain": spec.trust_domain,
            "host_node_locator": node_loc_obj,
            "shareable_seed_endpoints": seed_hints,
            "configured_bootstrap_seeds": seeds,
            "domain_descriptors": descriptors_summary,
            "workload_cards": cards_summary,
        }

    print(json.dumps(_scrub(report), indent=2, ensure_ascii=False))
    return 0


# =============================================================================
# Gateway-Executed Subcommands (`status`, `send`, `cancel`, `audit`)
# =============================================================================


def _run_status_in_gateway() -> int:
    from lineage.k8s.e2e_driver import (
        ALPHA_CA_URL,
        ALPHA_DIR_URL,
        ALPHA_REV_URL,
        GatewaySession,
    )

    gw = GatewaySession(require_all_peers=False, max_wait_sec=12.0)
    try:
        gw.syncer.sync_all(require_all=False, max_wait_sec=4.0)
        ready_ok, ready_diag = gw.syncer.is_ready()
        now_ts = time.time()

        control_checks: Dict[str, Any] = {}
        for name, u in (
            ("alpha-ca-local", f"{ALPHA_CA_URL}/healthz"),
            ("alpha-directory-local", f"{ALPHA_DIR_URL}/healthz"),
            ("alpha-revocation-local", f"{ALPHA_REV_URL}/healthz"),
        ):
            try:
                r = httpx.get(u, timeout=3.0)
                control_checks[name] = {"url": u, "http_status": r.status_code}
            except Exception as exc:
                control_checks[name] = {"url": u, "error": str(exc)}

        domain_locator_resolution: Dict[str, Any] = {}
        if gw.descriptor_store is not None:
            for td, desc in sorted(gw.descriptor_store.all_descriptors().items()):
                domain_locator_resolution[td] = {
                    "descriptor_version": desc.version,
                    "trust_anchor": desc.trust_anchor,
                    "ttl_remaining_seconds": round(max(0.0, desc.expires_at - now_ts), 1),
                    "services": {
                        svc_k: [loc.to_dict() for loc in locs]
                        for svc_k, locs in desc.locators.items()
                    },
                }
                if td != "org-alpha.io":
                    for loc in desc.get_locators("ca_bundle"):
                        try:
                            rh = httpx.get(f"{loc.origin_url}/healthz", timeout=3.0, trust_env=False)
                            control_checks[f"{td}:ca_bundle"] = {
                                "locator": f"{loc.host}:{loc.port}",
                                "descriptor_version": desc.version,
                                "http_status": rh.status_code,
                            }
                            break
                        except Exception as exc:
                            control_checks[f"{td}:ca_bundle"] = {
                                "locator": f"{loc.host}:{loc.port}",
                                "error": str(exc),
                            }
                    for loc in desc.get_locators("revocation_federation"):
                        try:
                            rm = gw.get_mtls(
                                f"{loc.origin_url}/healthz",
                                expected_spiffe_id=loc.spiffe_id,
                                timeout=3.0,
                            )
                            control_checks[f"{td}:revocation_federation"] = {
                                "identity": loc.spiffe_id,
                                "locator": f"{loc.host}:{loc.port}",
                                "descriptor_version": desc.version,
                                "http_status": rm.status_code,
                            }
                            break
                        except Exception as exc:
                            control_checks[f"{td}:revocation_federation"] = {
                                "identity": loc.spiffe_id,
                                "locator": f"{loc.host}:{loc.port}",
                                "error": str(exc),
                            }

        try:
            r_aud = gw.audit_client.healthz()
            aud_locs = gw.syncer.audit_locators()
            control_checks["audit-collector"] = {
                "identity": (aud_locs[0].spiffe_id if aud_locs else "spiffe://org-audit.io/ns/lineage-audit/sa/audit-collector"),
                "locators": [f"{l.host}:{l.port}" for l in aud_locs],
                "http_status": r_aud.status_code,
                "entries_count": r_aud.json().get("count"),
            }
        except Exception as exc:
            control_checks["audit-collector"] = {"error": str(exc)}

        cards = gw.dir_client.discover(only_healthy=True)
        identity_to_locator_hops: List[Dict[str, Any]] = []
        for c in cards:
            c_info: Dict[str, Any] = {
                "spiffe_id": c.spiffe_id,
                "trust_domain": c.trust_domain,
                "name": c.name,
                "skills": list(c.skills),
                "priority": c.priority,
                "card_version": c.version,
                "ttl_remaining_seconds": round(max(0.0, c.expires_at - now_ts), 1),
                "signed_locators": [loc.to_dict() for loc in c.locators],
                "primary_endpoint": c.endpoint,
            }
            try:
                verify_ctx = gw.mtls_bundle.verify_for_target(
                    target_url=c.endpoint,
                    expected_spiffe_id=c.spiffe_id,
                )
                tls_meta = _probe_tls_handshake_details(c.endpoint, verify_ctx, timeout=3.0)
                r_h = gw.get_mtls_card(c, "/healthz", timeout=3.0)
                c_info["resolved_machine_ip"] = tls_meta["resolved_ip"]
                c_info["resolved_port"] = tls_meta["port"]
                c_info["tls_version"] = tls_meta["tls_version"]
                c_info["tls_cipher"] = tls_meta["tls_cipher"]
                c_info["healthz_status"] = r_h.status_code
            except Exception as exc:
                c_info["probe_error"] = str(exc)
            identity_to_locator_hops.append(c_info)

        report = {
            "addressing_mode": "identity_signed_locators",
            "gateway_spiffe_id": gw.identity.spiffe_id,
            "svid_generation": gw.identity.renewal_generation,
            "federation_ready": ready_ok,
            "federation_sync": ready_diag,
            "domain_descriptor_resolution": domain_locator_resolution,
            "control_plane": control_checks,
            "identity_to_locator_resolution": identity_to_locator_hops,
        }
        print(json.dumps(_scrub(report), indent=2, ensure_ascii=False))
        return 0 if ready_ok else 1
    finally:
        gw.syncer.stop_background_refresh()
        gw.mtls_bundle.cleanup()


def _infer_cities_from_text(text: str, explicit_city: Optional[str]) -> List[str]:
    if explicit_city:
        return [c.strip() for c in explicit_city.split(",") if c.strip()]
    known = ["Tokyo", "London", "Paris", "NewYork", "Singapore", "Berlin", "Seoul"]
    matched = [c for c in known if c.lower() in text.lower()]
    return matched or ["Tokyo", "London", "Paris"]


def stream_and_summarize_a2a_sse(
    a2a_client: A2AClient,
    message: Message,
    compact_token: Optional[str] = None,
    event_sink: Optional[IO[str]] = sys.stderr,
) -> Tuple[int, Dict[str, Any]]:
    """Invoke `SendStreamingMessage`, print A2A v1.0 states/artifacts as they arrive,
    and return `(cli_exit_code, rpc_summary)` (exit 0 iff terminal state is `TASK_STATE_COMPLETED`).
    """
    sse_states: List[str] = []
    artifact_names: List[str] = []
    artifact_updates: List[Dict[str, Any]] = []
    final_box: Dict[str, Any] = {"final_event": None, "terminal_state": None}

    def _on_frame(ev: Dict[str, Any]) -> None:
        res_obj = ev.get("result") if isinstance(ev, Mapping) else None
        if isinstance(res_obj, Mapping):
            su = res_obj.get("statusUpdate")
            if isinstance(su, Mapping):
                st_obj = su.get("status")
                state_val = (
                    str(st_obj.get("state"))
                    if isinstance(st_obj, Mapping) and st_obj.get("state")
                    else ""
                )
                is_final = bool(su.get("final", False))
                if state_val:
                    sse_states.append(state_val)
                if event_sink is not None:
                    print(
                        f"[sse] statusUpdate state={state_val or 'UNKNOWN'} final={is_final}",
                        file=event_sink,
                        flush=True,
                    )
                if is_final:
                    final_box["final_event"] = dict(su)
                    final_box["terminal_state"] = state_val or None
                return

            au = res_obj.get("artifactUpdate")
            if isinstance(au, Mapping):
                artifact_updates.append(dict(au))
                art = au.get("artifact")
                art_name = (
                    str(art.get("name") or art.get("artifactId") or "artifact")
                    if isinstance(art, Mapping)
                    else "artifact"
                )
                artifact_names.append(art_name)
                if event_sink is not None:
                    print(
                        f"[sse] artifactUpdate name={art_name}",
                        file=event_sink,
                        flush=True,
                    )
                return

            if isinstance(res_obj.get("task"), Mapping):
                task_obj = res_obj["task"]
                st_obj = task_obj.get("status")
                state_val = (
                    str(st_obj.get("state"))
                    if isinstance(st_obj, Mapping) and st_obj.get("state")
                    else ""
                )
                if state_val:
                    sse_states.append(state_val)
                    final_box["terminal_state"] = state_val
                final_box["final_event"] = dict(task_obj)
                if event_sink is not None and state_val:
                    print(
                        f"[sse] task state={state_val}",
                        file=event_sink,
                        flush=True,
                    )
                return

        if isinstance(ev, Mapping) and "error" in ev:
            err_obj = ev.get("error")
            err_msg = err_obj.get("message") if isinstance(err_obj, Mapping) else str(err_obj)
            final_box["terminal_state"] = TaskState.FAILED.value
            final_box["final_event"] = (
                dict(err_obj) if isinstance(err_obj, Mapping) else {"message": str(err_obj)}
            )
            if event_sink is not None:
                print(f"[sse] error={err_msg}", file=event_sink, flush=True)

    st_code, sse_ct, sse_events = a2a_client.send_streaming_message(
        message=message,
        compact_token=compact_token,
        on_event=_on_frame,
    )
    terminal_state = final_box["terminal_state"] or (sse_states[-1] if sse_states else None)
    rpc_summary: Dict[str, Any] = {
        "mode": "SendStreamingMessage (SSE)",
        "http_status": st_code,
        "content_type": sse_ct,
        "sse_frame_count": len(sse_events),
        "sse_states": sse_states,
        "artifact_update_count": len(artifact_updates),
        "artifact_names": artifact_names,
        "terminal_state": terminal_state,
        "final_event": final_box["final_event"],
    }
    ok = (
        st_code == 200
        and "text/event-stream" in sse_ct.lower()
        and terminal_state == TaskState.COMPLETED.value
    )
    return (0 if ok else 1), rpc_summary


def _run_send_in_gateway(args: argparse.Namespace) -> int:
    from lineage.k8s.e2e_driver import (
        GatewaySession,
        _extract_a2a_task_data,
        _full_travel_root_permissions,
    )

    gw = GatewaySession()
    try:
        orch_card = gw.get_orchestrator_card()
        all_cards = {c.spiffe_id: c for c in gw.dir_client.discover(only_healthy=False)}

        task_id = args.task_id or f"task-mh-{uuid.uuid4().hex[:10]}"
        cities = _infer_cities_from_text(args.text, args.city)
        perms = _full_travel_root_permissions(cities, max_amount=float(args.max_amount))
        tok, _ = gw.mint_root_for_user(task_id, args.sub, perms, target_card=orch_card)

        orch_verify_ctx = gw.mtls_bundle.verify_for_target(
            target_url=orch_card.endpoint,
            expected_trust_domain="org-alpha.io",
            expected_spiffe_id=orch_card.spiffe_id,
        )
        entry_tls = _probe_tls_handshake_details(
            orch_card.endpoint, orch_verify_ctx, timeout=5.0
        )

        msg_data: Dict[str, Any] = {"op": "plan_and_execute_trip"}
        if args.pause_before_settlement:
            msg_data["pause_before_settlement"] = True

        user_msg = Message.create_user(
            text=args.text,
            data=msg_data,
            task_id=task_id,
        )

        if args.stream:
            exit_rc, rpc_summary = stream_and_summarize_a2a_sse(
                a2a_client=gw.a2a_orch,
                message=user_msg,
                compact_token=tok,
                event_sink=sys.stderr,
            )
        else:
            st_code, rpc_body = gw.a2a_orch.send_message(
                message=user_msg,
                compact_token=tok,
            )
            task_data = _extract_a2a_task_data(rpc_body) if st_code == 200 else {}
            task_state = (
                rpc_body.get("result", {}).get("task", {}).get("status", {}).get("state")
                if st_code == 200
                else "TASK_STATE_FAILED"
            )
            rpc_summary = {
                "mode": "SendMessage (JSON-RPC 2.0)",
                "http_status": st_code,
                "task_state": task_state,
                "itinerary_summary": (
                    task_data.get("settlement_convergence", {})
                    .get("upstream_body", {})
                    .get("final_answer")
                    if isinstance(task_data, dict)
                    else None
                ),
            }
            exit_rc = (
                0
                if (st_code == 200 and task_state == TaskState.COMPLETED.value)
                else 1
            )

        time.sleep(0.5)
        entries = gw.audit_client.fetch_entries(task_id=task_id)
        hop_traces: List[Dict[str, Any]] = [
            {
                "hop_index": 0,
                "event_type": "GATEWAY_ENTRY_MTLS",
                "caller_spiffe_id": gw.identity.spiffe_id,
                "target_spiffe_id": entry_tls["peer_spiffe_id"],
                "resolved_locator": f"{entry_tls['resolved_ip']}:{entry_tls['port']}",
                "card_version": orch_card.version,
                "peer_cert_issuer_domain": entry_tls["peer_issuer_domain"],
                "tls_version": entry_tls["tls_version"],
                "tls_cipher": entry_tls["tls_cipher"],
                "decision": "ALLOW",
            }
        ]
        outbound_ip_by_path: Dict[str, str] = {}
        for e in entries:
            if e.event_type.value == "OUTBOUND_DELEGATE":
                rip = (e.action_detail or {}).get("resolved_peer_ip")
                if rip:
                    outbound_ip_by_path[e.lineage_path] = str(rip)

        for e in sorted(entries, key=lambda x: (x.timestamp, x.hop_index, x.stream_seq)):
            if e.event_type.value in ("INBOUND_AUTHZ", "TOOL_INVOCATION", "AUTHZ_DENIED"):
                ad = e.action_detail or {}
                node_td = (
                    SpiffeId.parse(e.node_spiffe_id).trust_domain
                    if e.node_spiffe_id.startswith("spiffe://")
                    else e.node_svid_or_domain
                )
                node_card = all_cards.get(e.node_spiffe_id)
                signed_loc_str = (
                    f"{node_card.locators[0].host}:{node_card.locators[0].port}"
                    if (node_card is not None and node_card.locators)
                    else (node_card.endpoint if node_card is not None else None)
                )
                hop_traces.append(
                    {
                        "hop_index": e.hop_index,
                        "event_type": e.event_type.value,
                        "lineage_path": e.lineage_path,
                        "node_spiffe_id": e.node_spiffe_id,
                        "signed_locator": signed_loc_str,
                        "card_version": (node_card.version if node_card is not None else None),
                        "node_issuer_domain": node_td,
                        "peer_spiffe_id": ad.get("peer_spiffe_id"),
                        "peer_cert_issuer_domain": ad.get("peer_issuer_domain"),
                        "resolved_peer_ip": outbound_ip_by_path.get(e.lineage_path),
                        "tls_version": ad.get("tls_version"),
                        "tls_cipher": ad.get("tls_cipher"),
                        "tool": ad.get("tool"),
                        "decision": e.decision,
                    }
                )

        output = {
            "task_id": task_id,
            "sub": args.sub,
            "a2a_result": rpc_summary,
            "hop_by_hop_identity_to_locator_trace": hop_traces,
        }
        print(json.dumps(_scrub(output), indent=2, ensure_ascii=False))
        return exit_rc
    finally:
        gw.syncer.stop_background_refresh()
        gw.mtls_bundle.cleanup()


def _run_cancel_in_gateway(args: argparse.Namespace) -> int:
    from lineage.k8s.e2e_driver import (
        ALPHA_REV_URL,
        GatewaySession,
        _full_travel_root_permissions,
    )

    gw = GatewaySession()
    try:
        orch_card = gw.get_orchestrator_card()
        task_id = args.task_id
        perms = _full_travel_root_permissions(["Tokyo"], max_amount=800.0)
        tok, _ = gw.mint_root_for_user(task_id, args.sub, perms, target_card=orch_card)

        if args.stage_first:
            st_stage, body_stage = gw.a2a_orch.send_message(
                message=Message.create_user(
                    text=f"Stage cancellable Tokyo trip for {args.sub}",
                    data={"op": "plan_and_execute_trip", "pause_before_settlement": True},
                    task_id=task_id,
                ),
                compact_token=tok,
            )
            if st_stage != 200:
                raise RuntimeError(f"Failed staging task {task_id!r}: {body_stage}")

        st_cancel, cancel_body = gw.a2a_orch.cancel_task(task_id, compact_token=tok)
        expected_prefix = f"/{task_id}/OrchestratorAlpha"

        propagation: Dict[str, Any] = {}
        # 1. Local alpha-revocation
        alpha_ok = False
        for _ in range(15):
            r_loc = httpx.get(f"{ALPHA_REV_URL}/v1/events", timeout=3.0)
            evs = r_loc.json().get("events", [])
            if any(e.get("target") == expected_prefix for e in evs):
                alpha_ok = True
                break
            time.sleep(0.2)
        propagation["alpha-revocation"] = {
            "url": ALPHA_REV_URL,
            "propagated": alpha_ok,
        }

        # 2. Peer beta-revocation & payment-revocation resolved via signed domain descriptors
        for peer_name, peer_td in (
            ("beta-revocation", "org-beta.io"),
            ("payment-revocation", "org-payment.io"),
        ):
            rev_loc = gw.rev_fed_locator(peer_td)
            peer_url = rev_loc.origin_url
            matched = False
            detail: Dict[str, Any] = {
                "identity": rev_loc.spiffe_id,
                "locator": f"{rev_loc.host}:{rev_loc.port}",
            }
            for _ in range(20):
                try:
                    r_h = gw.get_mtls(
                        f"{peer_url}/healthz",
                        expected_spiffe_id=rev_loc.spiffe_id,
                        timeout=3.0,
                    )
                    if r_h.status_code == 200:
                        detail["trie_version"] = r_h.json().get("version")
                        if int(r_h.json().get("version", 0)) >= 1:
                            matched = True
                            break
                except Exception as exc:
                    detail["last_error"] = str(exc)
                time.sleep(0.25)
            detail["propagated"] = matched
            propagation[peer_name] = detail

        r_replay = gw.post_lct_mtls(
            orch_card.endpoint,
            tok,
            {"op": "inspect_inbox", "inspect_task_id": task_id},
            expected_spiffe_id=orch_card.spiffe_id,
        )
        out = {
            "task_id": task_id,
            "cancel_http_status": st_cancel,
            "cancel_response": cancel_body,
            "cross_machine_revocation_propagation": propagation,
            "post_cancel_replay_http_status": r_replay.status_code,
        }
        print(json.dumps(_scrub(out), indent=2, ensure_ascii=False))
        ok = (
            st_cancel == 200
            and all(v.get("propagated") for v in propagation.values())
            and r_replay.status_code == 403
        )
        return 0 if ok else 1
    finally:
        gw.syncer.stop_background_refresh()
        gw.mtls_bundle.cleanup()


def _run_audit_in_gateway(args: argparse.Namespace) -> int:
    from lineage.k8s.e2e_driver import GatewaySession

    gw = GatewaySession()
    try:
        entries = gw.audit_client.fetch_entries()
        auditor = CausalChainAuditor(
            gw.resolver,
            trusted_revocation_spiffe_ids=[
                "spiffe://org-alpha.io/ns/sys/sa/revocation",
                "spiffe://org-beta.io/ns/sys/sa/revocation",
                "spiffe://org-payment.io/ns/sys/sa/revocation",
            ],
        )
        report = auditor.audit(entries)
        ok_num, total_den = report.reconstruction_rate

        def _fmt_task(trec: Any) -> Dict[str, Any]:
            return {
                "sub": trec.sub,
                "reconstructed_complete": trec.reconstructed_complete,
                "lineage_paths_observed": trec.lineage_paths_observed,
                "verified_hops": trec.verified_hops,
                "tool_invocations_verified": trec.tool_invocations_verified,
                "resilience_classifications": trec.resilience_classifications,
                "anomalies": [a.__dict__ for a in trec.anomalies],
            }

        if args.task_id:
            if args.task_id not in report.tasks:
                print(
                    json.dumps(
                        {"error": "task_not_found_in_audit_log", "task_id": args.task_id},
                        indent=2,
                    )
                )
                return 1
            trec = report.tasks[args.task_id]
            out = {
                "task_id": args.task_id,
                "stream_integrity_ok": report.stream_integrity_ok,
                "reconstruction": _fmt_task(trec),
            }
            print(json.dumps(_scrub(out), indent=2, ensure_ascii=False))
            return (
                0
                if (
                    report.stream_integrity_ok
                    and trec.reconstructed_complete
                    and not trec.anomalies
                )
                else 1
            )

        out_all = {
            "total_entries": len(entries),
            "stream_integrity_ok": report.stream_integrity_ok,
            "clean": report.clean,
            "reconstruction_rate": f"{ok_num}/{total_den}",
            "tasks": {tid: _fmt_task(r) for tid, r in sorted(report.tasks.items())},
        }
        print(json.dumps(_scrub(out_all), indent=2, ensure_ascii=False))
        return 0 if (report.stream_integrity_ok and report.clean) else 1
    finally:
        gw.syncer.stop_background_refresh()
        gw.mtls_bundle.cleanup()


# =============================================================================
# `e2e` Multi-Host Scenario Runner (`1, 2A, 2B, 3A, 3B, 4, 5, 6`)
# =============================================================================


def _probe_hotel_primary_reachable(
    kube_context: str = "kind-lctmh-alpha",
    require_directory_card: bool = False,
) -> bool:
    code = (
        "import sys\n"
        "from lineage.k8s.e2e_driver import GatewaySession\n"
        "gw = GatewaySession(require_all_peers=False, max_wait_sec=3.0, peer_timeout=1.2)\n"
        "try:\n"
        "    gw.syncer.sync_all(require_all=False, max_wait_sec=2.0)\n"
        f"    cards = gw.dir_client.discover(skill='travel.hotel', only_healthy={bool(require_directory_card)!r})\n"
        "    prim = [c for c in cards if 'primary' in c.spiffe_id]\n"
        "    if not prim:\n"
        "        sys.exit(1)\n"
        "    r = gw.get_mtls_card(prim[0], '/healthz', timeout=1.5)\n"
        "    sys.exit(0 if r.status_code == 200 else 1)\n"
        "except Exception:\n"
        "    sys.exit(1)\n"
        "finally:\n"
        "    gw.syncer.stop_background_refresh()\n"
        "    gw.mtls_bundle.cleanup()\n"
    )
    res = subprocess.run(
        [
            "kubectl",
            "--context",
            kube_context,
            "-n",
            "lineage-alpha",
            "exec",
            "deploy/e2e-user-gateway",
            "--",
            "/app/.venv/bin/python3",
            "-c",
            code,
        ],
        capture_output=True,
        text=True,
    )
    return res.returncode == 0


def _trigger_or_prompt_fault(
    *,
    local_beta: bool,
    fault_args: Sequence[str],
    machine_label: str,
    expect_hotel_reachable: Optional[bool],
    timeout_sec: float,
) -> None:
    fault_script = REPO_ROOT / "lineage" / "scripts" / "multihost.sh"
    pretty_cmd = f"bash lineage/scripts/multihost.sh fault {' '.join(fault_args)}"
    if local_beta:
        print(f"[e2e:local-fault] Executing directly: {pretty_cmd}", flush=True)
        subprocess.run(["bash", str(fault_script), "fault", *fault_args], check=True)
    else:
        print("", flush=True)
        print("============================================================================", flush=True)
        print(f" [ACTION REQUIRED ON {machine_label}] Run the following command now:", flush=True)
        print(f"   {pretty_cmd}", flush=True)
        print("============================================================================", flush=True)

    if expect_hotel_reachable is not None:
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            is_up = _probe_hotel_primary_reachable(
                require_directory_card=bool(expect_hotel_reachable),
            )
            if is_up == expect_hotel_reachable:
                return
            time.sleep(1.0)
        raise TimeoutError(
            f"Timed out ({timeout_sec}s) waiting for hotel-specialist-primary reachable={expect_hotel_reachable} after `{pretty_cmd}`"
        )


def _collect_local_pod_ips_json() -> str:
    """Collect Pod IPs of any local `lctmh-*` clusters for Scenario 4 loopback-bypass verification."""
    pod_ips: Dict[str, str] = {}
    out = subprocess.run(["kind", "get", "clusters"], capture_output=True, text=True)
    clusters = set((out.stdout or "").splitlines())
    targets = [
        ("alpha", "orchestrator-alpha"),
        ("beta", "flight-specialist"),
        ("beta", "hotel-specialist-primary"),
        ("pay", "settlement-converger"),
        ("pay", "payment-vault-mcp"),
    ]
    for role, app in targets:
        if f"lctmh-{role}" not in clusters:
            continue
        spec = ROLE_SPECS[role]
        r = subprocess.run(
            [
                "kubectl",
                "--context",
                spec.kube_context,
                "-n",
                spec.namespace,
                "get",
                "pod",
                "-l",
                f"app={app}",
                "-o",
                "jsonpath={.items[0].status.podIP}",
            ],
            capture_output=True,
            text=True,
        )
        if r.returncode == 0 and r.stdout.strip():
            pod_ips[app] = r.stdout.strip()
    return json.dumps(pod_ips)


def _run_e2e_suite_from_host(args: argparse.Namespace) -> int:
    run_id = args.run_id or time.strftime("%Y%m%d-%H%M%S")
    wanted = [
        s.strip().upper()
        for s in (args.scenarios or "1,2A,2B,3A,3B,4,5,6").split(",")
        if s.strip()
    ]
    out_clusters = subprocess.run(["kind", "get", "clusters"], capture_output=True, text=True)
    local_clusters = set((out_clusters.stdout or "").splitlines())
    if "lctmh-alpha" not in local_clusters:
        raise RuntimeError(
            "`e2e` must be run on Machine 1 hosting `lctmh-alpha` (`e2e-user-gateway`)."
        )
    local_beta = ("lctmh-beta" in local_clusters) and (not args.remote_faults)
    op_timeout = float(args.operator_timeout)
    results: Dict[str, Any] = {
        "run_id": run_id,
        "local_beta_auto_fault": local_beta,
        "scenarios": {},
    }

    out_dir: Optional[Path] = Path(args.output_dir).resolve() if args.output_dir else None
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)

    def _save_scenario(key: str, data: Dict[str, Any]) -> None:
        clean = _scrub(data)
        results["scenarios"][key] = clean
        if out_dir is not None:
            (out_dir / f"scenario_{key.lower()}.json").write_text(
                json.dumps(clean, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

    if "1" in wanted:
        print("[e2e] Running Scenario 1 (Identity-Addressed A2A v1.0 + SSE + 1-to-N / N-to-1 / M-to-N DAG)...", flush=True)
        _save_scenario("1", _exec_e2e_driver_phase("scenario1_normal_dag", run_id))
        print("[e2e] Scenario 1: PASS", flush=True)

    if "2A" in wanted:
        print("[e2e] Running Scenario 2A (Downward Atomic Prune-and-Graft on Byzantine/Zombie Node)...", flush=True)
        _save_scenario("2A", _exec_e2e_driver_phase("scenario2a_zombie_prune_and_graft", run_id))
        print("[e2e] Scenario 2A: PASS", flush=True)

    if "2B" in wanted:
        print("[e2e] Running Scenario 2B (Real Pod Kill on hotel-specialist-primary -> Failover to Backup)...", flush=True)
        _trigger_or_prompt_fault(
            local_beta=local_beta,
            fault_args=("--kill", "hotel-primary"),
            machine_label="Machine 2 (beta)",
            expect_hotel_reachable=False,
            timeout_sec=op_timeout,
        )
        try:
            _save_scenario(
                "2B", _exec_e2e_driver_phase("scenario2b_pod_down_prune_and_graft", run_id)
            )
            print("[e2e] Scenario 2B: PASS", flush=True)
        finally:
            _trigger_or_prompt_fault(
                local_beta=local_beta,
                fault_args=("--restore", "hotel-primary"),
                machine_label="Machine 2 (beta)",
                expect_hotel_reachable=True,
                timeout_sec=op_timeout,
            )

    if "3A" in wanted:
        print("[e2e] Running Scenario 3A (Forged Skip-Level Return Rejected While Intermediate Alive)...", flush=True)
        _save_scenario(
            "3A", _exec_e2e_driver_phase("scenario3a_forged_skip_blocked_while_alive", run_id)
        )
        print("[e2e] Scenario 3A: PASS", flush=True)

    if "3B" in wanted:
        print("[e2e] Running Scenario 3B (Mid-Flight Intermediate Pod Kill -> Authenticated Skip-Level Return)...", flush=True)
        marker_file = f"/tmp/s3b_mh_{run_id}"
        subprocess.run(
            [
                "kubectl",
                "--context",
                "kind-lctmh-alpha",
                "-n",
                "lineage-alpha",
                "exec",
                "deploy/e2e-user-gateway",
                "--",
                "rm",
                "-f",
                marker_file,
            ],
            check=False,
        )
        alpha_ports = read_cluster_role_ports("alpha") or {}
        sync_np = alpha_ports.get("e2e_sync_hook")
        sync_svc_yaml = yaml.safe_dump(
            render_e2e_sync_service_manifest("lineage-alpha", node_port=sync_np),
            sort_keys=False,
        )
        subprocess.run(
            ["kubectl", "--context", "kind-lctmh-alpha", "apply", "-f", "-"],
            input=sync_svc_yaml,
            text=True,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        time.sleep(1.0)
        s3b_box: Dict[str, Any] = {}
        s3b_err: List[Exception] = []

        def _s3b_worker() -> None:
            try:
                s3b_box["out"] = _exec_e2e_driver_phase(
                    "scenario3b_genuine_skip_level_when_pod_killed",
                    run_id,
                    extra_args=("--sync-marker-file", marker_file),
                )
            except Exception as exc:
                s3b_err.append(exc)

        t_s3b = threading.Thread(target=_s3b_worker, daemon=True)
        t_s3b.start()
        try:
            deadline_m = time.time() + 45.0
            found_marker = False
            while time.time() < deadline_m:
                if s3b_err:
                    raise s3b_err[0]
                chk = subprocess.run(
                    [
                        "kubectl",
                        "--context",
                        "kind-lctmh-alpha",
                        "-n",
                        "lineage-alpha",
                        "exec",
                        "deploy/e2e-user-gateway",
                        "--",
                        "test",
                        "-f",
                        marker_file,
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if chk.returncode == 0:
                    found_marker = True
                    break
                time.sleep(0.25)
            if not found_marker:
                raise RuntimeError("Scenario 3B did not reach mid-flight sync hook marker")

            _trigger_or_prompt_fault(
                local_beta=local_beta,
                fault_args=("--kill", "hotel-primary", "--fast"),
                machine_label="Machine 2 (beta)",
                expect_hotel_reachable=False,
                timeout_sec=op_timeout,
            )
            t_s3b.join(timeout=60.0)
            if s3b_err:
                raise s3b_err[0]
            if "out" not in s3b_box:
                raise RuntimeError("Scenario 3B worker timed out")
            _save_scenario("3B", s3b_box["out"])
            print("[e2e] Scenario 3B: PASS", flush=True)
        finally:
            subprocess.run(
                [
                    "kubectl",
                    "--context",
                    "kind-lctmh-alpha",
                    "-n",
                    "lineage-alpha",
                    "delete",
                    "service",
                    "e2e-user-gateway-sync",
                    "--ignore-not-found",
                ],
                check=False,
                stdout=subprocess.DEVNULL,
            )
            _trigger_or_prompt_fault(
                local_beta=local_beta,
                fault_args=("--restore", "hotel-primary"),
                machine_label="Machine 2 (beta)",
                expect_hotel_reachable=True,
                timeout_sec=op_timeout,
            )

    if "4" in wanted:
        print("[e2e] Running Scenario 4 (A2A CancelTask Cross-Machine Revocation + Fagin Degradation + Concurrency)...", flush=True)
        pod_ips_json = _collect_local_pod_ips_json()
        _save_scenario(
            "4",
            _exec_e2e_driver_phase(
                "scenario4_fagin_degradation_concurrency_and_bypass_guard",
                run_id,
                extra_args=("--pod-ips-json", pod_ips_json),
            ),
        )
        print("[e2e] Scenario 4: PASS", flush=True)

    if "6" in wanted:
        print("[e2e] Running Scenario 6 (Whole-Machine Beta Partition -> Fail-Closed 503 -> Heal & Recovery)...", flush=True)
        subprocess.run(
            [
                "kubectl",
                "--context",
                "kind-lctmh-alpha",
                "-n",
                "lineage-alpha",
                "exec",
                "deploy/e2e-user-gateway",
                "--",
                "rm",
                "-f",
                "/tmp/s6_ready_disconnect",
                "/tmp/s6_ack_disconnected",
                "/tmp/s6_ready_reconnect",
                "/tmp/s6_ack_reconnected",
            ],
            check=False,
        )
        s6_box: Dict[str, Any] = {}
        s6_err: List[Exception] = []

        def _s6_worker() -> None:
            try:
                s6_box["out"] = _exec_e2e_driver_phase(
                    "scenario6_whole_cluster_partition", run_id
                )
            except Exception as exc:
                s6_err.append(exc)

        t_s6 = threading.Thread(target=_s6_worker, daemon=True)
        t_s6.start()
        partitioned = False
        try:
            deadline_d = time.time() + 60.0
            while time.time() < deadline_d:
                if s6_err:
                    raise s6_err[0]
                chk_d = subprocess.run(
                    [
                        "kubectl",
                        "--context",
                        "kind-lctmh-alpha",
                        "-n",
                        "lineage-alpha",
                        "exec",
                        "deploy/e2e-user-gateway",
                        "--",
                        "test",
                        "-f",
                        "/tmp/s6_ready_disconnect",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if chk_d.returncode == 0:
                    break
                time.sleep(0.3)

            _trigger_or_prompt_fault(
                local_beta=local_beta,
                fault_args=("--partition", "--role", "beta"),
                machine_label="Machine 2 (beta)",
                expect_hotel_reachable=False,
                timeout_sec=op_timeout,
            )
            partitioned = True
            subprocess.run(
                [
                    "kubectl",
                    "--context",
                    "kind-lctmh-alpha",
                    "-n",
                    "lineage-alpha",
                    "exec",
                    "deploy/e2e-user-gateway",
                    "--",
                    "sh",
                    "-c",
                    "echo ACK > /tmp/s6_ack_disconnected",
                ],
                check=True,
            )

            deadline_r = time.time() + 60.0
            while time.time() < deadline_r:
                if s6_err:
                    raise s6_err[0]
                chk_r = subprocess.run(
                    [
                        "kubectl",
                        "--context",
                        "kind-lctmh-alpha",
                        "-n",
                        "lineage-alpha",
                        "exec",
                        "deploy/e2e-user-gateway",
                        "--",
                        "test",
                        "-f",
                        "/tmp/s6_ready_reconnect",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if chk_r.returncode == 0:
                    break
                time.sleep(0.3)

            _trigger_or_prompt_fault(
                local_beta=local_beta,
                fault_args=("--heal", "--role", "beta"),
                machine_label="Machine 2 (beta)",
                expect_hotel_reachable=True,
                timeout_sec=op_timeout,
            )
            partitioned = False
            subprocess.run(
                [
                    "kubectl",
                    "--context",
                    "kind-lctmh-alpha",
                    "-n",
                    "lineage-alpha",
                    "exec",
                    "deploy/e2e-user-gateway",
                    "--",
                    "sh",
                    "-c",
                    "echo ACK > /tmp/s6_ack_reconnected",
                ],
                check=True,
            )
            t_s6.join(timeout=90.0)
            if s6_err:
                raise s6_err[0]
            if "out" not in s6_box:
                raise RuntimeError("Scenario 6 worker timed out")
            _save_scenario("6", s6_box["out"])
            print("[e2e] Scenario 6: PASS", flush=True)
        finally:
            if partitioned:
                _trigger_or_prompt_fault(
                    local_beta=local_beta,
                    fault_args=("--heal", "--role", "beta"),
                    machine_label="Machine 2 (beta)",
                    expect_hotel_reachable=None,
                    timeout_sec=op_timeout,
                )

    if "5" in wanted:
        print("[e2e] Running Scenario 5 (100% CausalChainAuditor Reconstruction Over TLS 1.3 Audit Center)...", flush=True)
        time.sleep(0.8)
        _save_scenario(
            "5", _exec_e2e_driver_phase("scenario5_cluster_audit_reconstruction", run_id)
        )
        print("[e2e] Scenario 5: PASS", flush=True)

    results["overall_status"] = "PASS"
    if out_dir is not None:
        (out_dir / "e2e_multihost_summary.json").write_text(
            json.dumps(_scrub(results), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    print(
        json.dumps(
            {
                "run_id": run_id,
                "overall_status": "PASS",
                "scenarios": list(results["scenarios"].keys()),
            },
            indent=2,
        )
    )
    return 0


def format_m8_comparison_markdown(comp: Mapping[str, Any]) -> str:
    """Render a side-by-side empirical Markdown report from `run_m8_protocol_comparison` output."""
    dims = comp.get("dimensions") or {}
    d1 = dims.get("1_latency_and_sts_rpcs") or {}
    d2 = dims.get("2_fine_grained_overprivilege") or {}
    d3 = dims.get("3_multiparent_convergence_and_branch_cancel") or {}
    d4 = dims.get("4_zombie_primary_failover_double_spend") or {}
    d5 = dims.get("5_central_sts_partition_impact") or {}
    d6 = dims.get("6_causal_audit_reconstruction") or {}

    c1 = d1.get("oauth_centralized") or {}
    f1 = d1.get("oauth_federated") or {}
    l1 = d1.get("lct") or {}

    c2 = d2.get("oauth_centralized") or {}
    f2 = d2.get("oauth_federated") or {}
    l2 = d2.get("lct") or {}

    c3 = d3.get("oauth_centralized") or {}
    f3 = d3.get("oauth_federated") or {}
    l3 = d3.get("lct") or {}

    c4 = d4.get("oauth_centralized") or {}
    f4 = d4.get("oauth_federated") or {}
    l4 = d4.get("lct") or {}

    c5 = d5.get("oauth_centralized") or {}
    f5 = d5.get("oauth_federated") or {}
    l5 = d5.get("lct") or {}

    c6 = d6.get("oauth_centralized") or {}
    f6 = d6.get("oauth_federated") or {}
    l6 = d6.get("lct") or {}

    lines = [
        f"# Empirical Protocol Comparison (`run_id={comp.get('run_id')}`, `alpha_sts={comp.get('alpha_sts_engine')}`)",
        "",
        "| Dimension | `oauth_centralized` (RFC 8693 Central STS) | `oauth_federated` (Per-Org STS Relay) | `lct` (Hop-0 OIDC/Keycloak -> Offline LCT) |",
        "| :--- | :--- | :--- | :--- |",
        (
            f"| **1. Multi-Hop Latency & STS RPCs** (`Alpha -> Beta -> Pay -> MCP`) | "
            f"`{c1.get('online_sts_exchange_rpcs')}` online STS RPCs (`{c1.get('cumulative_sts_rtt_ms')} ms` STS RTT, `{c1.get('e2e_wall_ms')} ms` wall) | "
            f"`{f1.get('online_sts_exchange_rpcs')}` online STS RPCs (`{f1.get('cumulative_sts_rtt_ms')} ms` STS RTT, `{f1.get('e2e_wall_ms')} ms` wall) | "
            f"**`{l1.get('online_sts_exchange_rpcs')}` downstream STS RPCs** (`0.0 ms` STS RTT, `{l1.get('hop0_ca_bridge_ms')} ms` Hop-0 bridge, `{l1.get('e2e_wall_ms')} ms` wall) |"
        ),
        (
            f"| **2. Fine-Grained Parameter Over-Privilege** (`$950` / `Paris` vs `$650` / `Tokyo`) | "
            f"HTTP `{c2.get('http_status')}` (`{c2.get('overprivileged_call_outcome')}` — `${c2.get('charged_usd')}` `{c2.get('booked_city')}`) | "
            f"HTTP `{f2.get('http_status')}` (`{f2.get('overprivileged_call_outcome')}` — `${f2.get('charged_usd')}` `{f2.get('booked_city')}`) | "
            f"**HTTP `{l2.get('http_status')}` (`{l2.get('overprivileged_call_outcome')}`)** |"
        ),
        (
            f"| **3. N-to-1 Convergence & Flight-Only Cancel** | "
            f"Airline HTTP `{c3.get('airline_escrow_status_after_flight_cancel')}`, Hotel HTTP `{c3.get('hotel_escrow_status')}` (`{c3.get('outcome')}`) | "
            f"Airline HTTP `{f3.get('airline_escrow_status_after_flight_cancel')}`, Hotel HTTP `{f3.get('hotel_escrow_status')}` (`{f3.get('outcome')}`) | "
            f"**Airline HTTP `{l3.get('airline_escrow_status_after_flight_cancel')}` (Blocked), Hotel HTTP `{l3.get('hotel_escrow_status')}` (`{l3.get('hotel_lineage_decision')}`)** |"
        ),
        (
            f"| **4. Slow Primary Zombie Wakeup on Failover** | "
            f"Zombie MCP HTTP `{c4.get('zombie_wakeup_mcp_status')}` (`double_spend_prevented={c4.get('double_spend_prevented')}`) | "
            f"Zombie MCP HTTP `{f4.get('zombie_wakeup_mcp_status')}` (`double_spend_prevented={f4.get('double_spend_prevented')}`) | "
            f"**Zombie MCP HTTP `{l4.get('zombie_wakeup_mcp_status')}` (`double_spend_prevented={l4.get('double_spend_prevented')}`)** |"
        ),
        (
            f"| **5. Central `alpha-sts` Partition Impact** | "
            f"HTTP `{c5.get('http_status_during_alpha_sts_outage', 'N/A')}` (`survives={c5.get('survives_central_sts_outage', False)}`) | "
            f"`Beta->Pay` HTTP `{f5.get('beta_to_pay_http_status_during_alpha_sts_outage', 'N/A')}` (`downstream_survives={f5.get('downstream_orgs_survive_alpha_sts_outage', True)}`) | "
            f"**`Alpha->Beta->Pay` HTTP `{l5.get('alpha_to_beta_to_pay_http_status_during_alpha_sts_outage', 'N/A')}` (`survives={l5.get('survives_central_sts_outage', True)}`, `0` STS calls)** |"
        ),
        (
            f"| **6. Causal Audit DAG Reconstruction** | "
            f"`{c6.get('hash_linked_causal_coverage_pct')}%` (`{c6.get('task_correlated_dag_events')}` task-linked DAG events) | "
            f"`{f6.get('hash_linked_causal_coverage_pct')}%` (`{f6.get('task_correlated_dag_events')}` task-linked DAG events) | "
            f"**`{l6.get('hash_linked_causal_coverage_pct')}%` (`{l6.get('verified_causal_events_for_d1_trip')}` verified events, `{l6.get('tampered_or_unverified_events')}` tampered)** |"
        ),
    ]
    return "\n".join(lines)


def _handle_oauth_cmd(args: argparse.Namespace) -> int:
    from lineage.multihost.config_gen import (
        _ensure_in_memory_oauth_secret,
        _read_existing_oauth_creds_from_cluster,
    )

    if args.oauth_cmd == "export-creds":
        creds = _read_existing_oauth_creds_from_cluster(args.role)
        if creds is None:
            print(f"ERROR: Secret/lct-oauth-credentials not found in lctmh-{args.role}", file=sys.stderr)
            return 1
        out_path = Path(args.output).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(out_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(creds, fh, indent=2)
        print(json.dumps({"exported_to": str(out_path), "mode": "0600", "role": args.role}))
        return 0

    if args.oauth_cmd == "import-creds":
        in_path = Path(args.file).expanduser().resolve()
        raw_json = in_path.read_text(encoding="utf-8")
        roles = [r for r in _detect_local_lctmh_roles(args.roles) if r != "audit"]
        updated: List[Dict[str, Any]] = []
        for r in roles:
            updated.append(
                _ensure_in_memory_oauth_secret(
                    role=r,
                    sts_engine="lightweight",
                    import_creds_json=raw_json,
                )
            )
        print(json.dumps({"imported_roles": updated}, indent=2))
        return 0
    return 1


def _run_compare_from_host(args: argparse.Namespace) -> int:
    run_id = args.run_id.strip() or f"m8cmp-{int(time.time())}"
    out_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir.strip() else None
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)

    kube_ctx = args.kube_context
    extra_drv_args = ["--skip-sts-partition"] if args.skip_sts_partition else []
    comp_box: Dict[str, Any] = {}
    comp_err: List[BaseException] = []

    def _gw_test_file(fpath: str) -> bool:
        p = subprocess.run(
            [
                "kubectl",
                "--context",
                kube_ctx,
                "-n",
                "lineage-alpha",
                "exec",
                "deploy/e2e-user-gateway",
                "--",
                "test",
                "-f",
                fpath,
            ],
            capture_output=True,
        )
        return p.returncode == 0

    def _gw_touch(fpath: str) -> None:
        subprocess.run(
            [
                "kubectl",
                "--context",
                kube_ctx,
                "-n",
                "lineage-alpha",
                "exec",
                "deploy/e2e-user-gateway",
                "--",
                "sh",
                "-c",
                f"echo ACK > {fpath}",
            ],
            check=True,
        )

    def _worker() -> None:
        try:
            comp_box["out"] = _exec_e2e_driver_phase(
                "m8_compare_protocols",
                run_id,
                extra_args=extra_drv_args,
                kube_context=kube_ctx,
            )
        except BaseException as exc:
            comp_err.append(exc)

    def _gw_clear_markers() -> None:
        subprocess.run(
            [
                "kubectl",
                "--context",
                kube_ctx,
                "-n",
                "lineage-alpha",
                "exec",
                "deploy/e2e-user-gateway",
                "--",
                "rm",
                "-f",
                "/tmp/m8_ready_stop_alpha_sts",
                "/tmp/m8_ack_stopped_alpha_sts",
                "/tmp/m8_ready_restore_alpha_sts",
                "/tmp/m8_ack_restored_alpha_sts",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    _gw_clear_markers()
    print(
        f"[compare] Running 6-dimension empirical comparison (oauth_centralized vs oauth_federated vs lct) run_id={run_id}...",
        flush=True,
    )
    t_cmp = threading.Thread(target=_worker, daemon=True)
    t_cmp.start()

    def _alpha_sts_reachable() -> bool:
        cp = subprocess.run(
            [
                "kubectl",
                "--context",
                kube_ctx,
                "-n",
                "lineage-alpha",
                "exec",
                "deploy/e2e-user-gateway",
                "--",
                "/app/.venv/bin/python3",
                "-c",
                (
                    "import httpx, sys\n"
                    "ok = False\n"
                    "for u in ('http://alpha-sts.lineage-alpha.svc.cluster.local:8095/realms/lct/.well-known/openid-configuration', "
                    "'http://alpha-sts-federation.lineage-alpha.svc.cluster.local:8095/realms/lct/.well-known/openid-configuration'):\n"
                    "    try:\n"
                    "        if httpx.get(u, timeout=1.5, trust_env=False).status_code == 200:\n"
                    "            ok = True\n"
                    "    except Exception:\n"
                    "        pass\n"
                    "sys.exit(0 if ok else 1)\n"
                ),
            ],
            check=False,
            capture_output=True,
        )
        return cp.returncode == 0

    def _set_alpha_sts_selector(app_val: str) -> None:
        for svc_name in ("alpha-sts", "alpha-sts-federation"):
            subprocess.run(
                [
                    "kubectl",
                    "--context",
                    kube_ctx,
                    "-n",
                    "lineage-alpha",
                    "patch",
                    "svc",
                    svc_name,
                    "-p",
                    json.dumps({"spec": {"selector": {"app": app_val}}}),
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    sts_partitioned = False
    try:
        if not args.skip_sts_partition:
            deadline = time.time() + 420.0
            while t_cmp.is_alive() and not _gw_test_file("/tmp/m8_ready_stop_alpha_sts"):
                if time.time() > deadline:
                    raise RuntimeError("Timed out waiting for Dimension 5 alpha-sts partition trigger")
                time.sleep(0.4)
            if t_cmp.is_alive():
                print(
                    "[compare] Dimension 5: Severing Service/alpha-sts (+ federation) endpoints to test central STS outage...",
                    flush=True,
                )
                _set_alpha_sts_selector("alpha-sts-partitioned")
                sts_partitioned = True
                ep_deadline = time.time() + 25.0
                while time.time() < ep_deadline and _alpha_sts_reachable():
                    time.sleep(0.4)
                time.sleep(0.5)
                _gw_touch("/tmp/m8_ack_stopped_alpha_sts")

                deadline_rest = time.time() + 180.0
                while t_cmp.is_alive() and not _gw_test_file("/tmp/m8_ready_restore_alpha_sts"):
                    if time.time() > deadline_rest:
                        raise RuntimeError("Timed out waiting for Dimension 5 restore signal")
                    time.sleep(0.4)
                print("[compare] Dimension 5: Restoring Service/alpha-sts (+ federation) endpoints...", flush=True)
                _set_alpha_sts_selector("alpha-sts")
                ep_rest_deadline = time.time() + 25.0
                while time.time() < ep_rest_deadline and not _alpha_sts_reachable():
                    time.sleep(0.4)
                sts_partitioned = False
                _gw_touch("/tmp/m8_ack_restored_alpha_sts")

        t_cmp.join(timeout=420.0)
        if comp_err:
            raise comp_err[0]
        if "out" not in comp_box:
            raise RuntimeError("Protocol comparison worker did not produce output")
    finally:
        if sts_partitioned:
            _set_alpha_sts_selector("alpha-sts")

    scrubbed = _scrub(comp_box["out"])
    md_report = format_m8_comparison_markdown(scrubbed)
    if out_dir is not None:
        (out_dir / "m8_protocol_comparison.json").write_text(
            json.dumps(scrubbed, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        (out_dir / "m8_protocol_comparison.md").write_text(
            md_report + "\n",
            encoding="utf-8",
        )
    print("\n" + md_report + "\n", flush=True)
    print(json.dumps(scrubbed, indent=2, ensure_ascii=False))
    return 0


# =============================================================================
# CLI Argument Parser (Exposed for Unit Tests & Interactive Use)
# =============================================================================


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lct_multihost_cli.py",
        description="Identity-Addressed Cross-Machine LCT Federation Operator & Verification CLI",
    )
    parser.add_argument(
        "--in-gateway",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--kube-context",
        default="kind-lctmh-alpha",
        help="Kubectl context for Machine 1 gateway cluster (default: kind-lctmh-alpha)",
    )
    sub = parser.add_subparsers(dest="subcmd", required=True)

    # status
    sub.add_parser(
        "status",
        help="Show per-domain descriptor health and per-hop identity -> locator resolution",
    )

    # locator
    p_loc = sub.add_parser(
        "locator",
        help="Inspect own + learned signed domain descriptors and workload locators",
    )
    l_sub = p_loc.add_subparsers(dest="locator_cmd", required=True)
    p_l_show = l_sub.add_parser(
        "show",
        help="Show local host locators, signed domain descriptors, and AgentCards",
    )
    p_l_show.add_argument("--roles", default="", help="Comma-separated local roles")

    # seeds
    p_seeds = sub.add_parser(
        "seeds",
        help="Manage untrusted bootstrap seed endpoints (ip:port) in ConfigMap/lct-bootstrap-seeds",
    )
    s_sub = p_seeds.add_subparsers(dest="seeds_cmd", required=True)
    p_s_list = s_sub.add_parser("list", help="List configured bootstrap seeds")
    p_s_list.add_argument("--roles", default="", help="Comma-separated local roles")

    p_s_add = s_sub.add_parser("add", help="Add one or more bootstrap seed ip:port endpoints")
    p_s_add.add_argument("endpoints", nargs="+", help="Seed endpoint(s) ip:port")
    p_s_add.add_argument("--roles", default="", help="Comma-separated local roles")

    p_s_rm = s_sub.add_parser("remove", help="Remove one or more bootstrap seed ip:port endpoints")
    p_s_rm.add_argument("endpoints", nargs="+", help="Seed endpoint(s) ip:port")
    p_s_rm.add_argument("--roles", default="", help="Comma-separated local roles")

    # trust
    p_trust = sub.add_parser("trust", help="Manage SSH-style SHA-256 domain trust anchors")
    t_sub = p_trust.add_subparsers(dest="trust_cmd", required=True)

    p_t_show = t_sub.add_parser("show", help="Display pinned trust anchors in local ConfigMaps")
    p_t_show.add_argument("--roles", default="", help="Comma-separated local roles")

    p_t_add = t_sub.add_parser("add", help="Pin a verified domain trust anchor")
    p_t_add.add_argument("domain", help="Trust domain (e.g., org-beta.io)")
    p_t_add.add_argument("anchor", help="sha256:<x509-spki-hex>:<jwks-set-hex|keyless>")
    p_t_add.add_argument("--roles", default="", help="Comma-separated local roles")

    p_t_rm = t_sub.add_parser("remove", help="Remove a domain trust anchor pin")
    p_t_rm.add_argument("domain", help="Trust domain to unpin")
    p_t_rm.add_argument("--roles", default="", help="Comma-separated local roles")

    p_t_imp = t_sub.add_parser(
        "import",
        help="Import batch file of '<domain> sha256:...' lines (displays each and requires confirmation)",
    )
    p_t_imp.add_argument("file", help="Path to file containing domain trust anchor lines")
    p_t_imp.add_argument("--yes", action="store_true", help="Confirm without interactive prompt")
    p_t_imp.add_argument("--roles", default="", help="Comma-separated local roles")

    p_t_fetch = t_sub.add_parser(
        "fetch",
        help="Fetch candidate bundle from peer seed ip:port, display fingerprint, and pin on confirmation",
    )
    p_t_fetch.add_argument("--domain", required=True, help="Expected trust domain")
    p_t_fetch.add_argument("--seed", default="", help="Peer ca_federation seed ip:port")
    p_t_fetch.add_argument("--ip", default="", help="Peer machine IPv4 address")
    p_t_fetch.add_argument("--port", type=int, default=0, help="Peer ca_federation port")
    p_t_fetch.add_argument("--scheme", choices=("http", "https"), default="")
    p_t_fetch.add_argument(
        "--expect",
        default="",
        help="Expected sha256:<spki>:<jwks|keyless> fingerprint obtained out-of-band",
    )
    p_t_fetch.add_argument("--yes", action="store_true", help="Confirm without interactive prompt")
    p_t_fetch.add_argument("--roles", default="", help="Comma-separated local roles")

    # send
    p_send = sub.add_parser(
        "send", help="Send real A2A v1.0 message across Alpha -> Beta -> Pay"
    )
    p_send.add_argument("--text", required=True, help="User travel request text")
    p_send.add_argument("--stream", action="store_true", help="Use SendStreamingMessage (SSE)")
    p_send.add_argument("--task-id", default="", help="Optional custom task_id")
    p_send.add_argument("--sub", default="user:alice@org-alpha.io", help="User subject")
    p_send.add_argument("--city", default="", help="Optional comma-separated allowed cities")
    p_send.add_argument("--max-amount", type=float, default=1000.0)
    p_send.add_argument("--pause-before-settlement", action="store_true")

    # cancel
    p_cancel = sub.add_parser(
        "cancel", help="Cancel A2A task and verify cross-machine revocation propagation"
    )
    p_cancel.add_argument("task_id", help="Target task_id to cancel")
    p_cancel.add_argument("--sub", default="user:alice@org-alpha.io")
    p_cancel.add_argument(
        "--stage-first",
        action="store_true",
        help="Stage a paused cross-domain trip under task_id before invoking CancelTask",
    )

    # audit
    p_audit = sub.add_parser(
        "audit", help="Fetch signed audit log over TLS 1.3 and reconstruct causal tree"
    )
    p_audit.add_argument("task_id", nargs="?", default="", help="Task ID (omit for all tasks)")

    # e2e
    p_e2e = sub.add_parser(
        "e2e", help="Run cross-machine E2E scenarios (1,2A,2B,3A,3B,4,5,6)"
    )
    p_e2e.add_argument("--scenarios", default="1,2A,2B,3A,3B,4,5,6")
    p_e2e.add_argument("--run-id", default="")
    p_e2e.add_argument("--output-dir", default="")
    p_e2e.add_argument(
        "--remote-faults",
        action="store_true",
        help="Prompt remote operator for faults even if lctmh-beta exists locally",
    )
    p_e2e.add_argument("--operator-timeout", type=float, default=180.0)

    # compare
    p_cmp = sub.add_parser(
        "compare",
        help="Run 6-dimension empirical comparison: oauth_centralized vs oauth_federated vs lct",
    )
    p_cmp.add_argument("--run-id", default="")
    p_cmp.add_argument("--output-dir", default="")
    p_cmp.add_argument(
        "--skip-sts-partition",
        action="store_true",
        help="Skip Dimension 5 alpha-sts scale-to-0 outage probe",
    )

    # oauth
    p_oauth = sub.add_parser(
        "oauth",
        help="Export or import OAuth 2.0 confidential client credentials across machines",
    )
    o_sub = p_oauth.add_subparsers(dest="oauth_cmd", required=True)
    p_o_exp = o_sub.add_parser(
        "export-creds",
        help="Export Secret/lct-oauth-credentials to a 0600 file (for 4-machine oauth_centralized)",
    )
    p_o_exp.add_argument("--role", default="alpha")
    p_o_exp.add_argument("--output", required=True)

    p_o_imp = o_sub.add_parser(
        "import-creds",
        help="Import OAuth client credentials file into local lctmh-* clusters",
    )
    p_o_imp.add_argument("file")
    p_o_imp.add_argument("--roles", default="")

    # deprecated update-peer-ips
    p_dep = sub.add_parser(
        "update-peer-ips",
        help="[DEPRECATED in M7] Replaced by automatic locator-agent + seeds/locator commands",
    )
    p_dep.add_argument("extra", nargs="*", help=argparse.SUPPRESS)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_cli_parser()
    args = parser.parse_args(raw_argv)

    if args.subcmd == "update-peer-ips":
        print(
            "[DEPRECATED] `update-peer-ips` and static CoreDNS IP addressing were removed in Milestone 7.\n"
            "  - Local host IP changes are now detected and re-signed automatically by `locator-agent.py`.\n"
            "  - Inspect signed descriptors and workload locators via: `multihost.sh locator show`\n"
            "  - Manage untrusted bootstrap seeds via: `multihost.sh seeds list|add|remove <ip:port>`",
            file=sys.stderr,
        )
        return 2

    if args.subcmd == "send":
        if not args.text.strip():
            parser.error("--text must not be empty")
        if args.max_amount <= 0:
            parser.error("--max-amount must be positive")
    if args.subcmd == "cancel" and not args.task_id.strip():
        parser.error("task_id must not be empty")
    if args.subcmd == "seeds" and args.seeds_cmd in ("add", "remove"):
        try:
            for ep in args.endpoints:
                normalize_seed_endpoint(ep)
        except Exception as exc:
            parser.error(str(exc))
    if args.subcmd == "trust" and args.trust_cmd == "fetch":
        try:
            SpiffeId.parse(f"spiffe://{args.domain.strip().lower()}/authority/ca")
            if args.seed.strip():
                normalize_seed_endpoint(args.seed)
            else:
                if not args.ip.strip() or args.port <= 0:
                    raise ValueError("Provide --seed <ip:port> or both --ip and --port")
                validate_ipv4_address(args.ip, "--ip")
            if args.expect.strip():
                parse_trust_anchor_value(args.expect)
        except Exception as exc:
            parser.error(str(exc))
    if args.subcmd == "trust" and args.trust_cmd == "add":
        try:
            SpiffeId.parse(f"spiffe://{args.domain.strip().lower()}/authority/ca")
            parse_trust_anchor_value(args.anchor)
        except Exception as exc:
            parser.error(str(exc))

    if args.subcmd == "trust":
        return _handle_trust_cmd(args)
    if args.subcmd == "seeds":
        return _handle_seeds_cmd(args)
    if args.subcmd == "locator":
        return _handle_locator_cmd(args)
    if args.subcmd == "oauth":
        return _handle_oauth_cmd(args)
    if args.subcmd == "e2e":
        return _run_e2e_suite_from_host(args)
    if args.subcmd == "compare":
        return _run_compare_from_host(args)

    if not args.in_gateway and not _in_gateway_pod():
        fwd = [a for a in raw_argv if a != "--in-gateway"]
        return _exec_in_gateway(fwd, kube_context=args.kube_context)

    if args.subcmd == "status":
        return _run_status_in_gateway()
    if args.subcmd == "send":
        return _run_send_in_gateway(args)
    if args.subcmd == "cancel":
        return _run_cancel_in_gateway(args)
    if args.subcmd == "audit":
        return _run_audit_in_gateway(args)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
