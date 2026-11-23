#!/usr/bin/env python3
"""Interactive & Scriptable Cross-Machine LCT Operator CLI (`lct_multihost_cli.py`).

Sub-commands:
- `status`: Per-domain CA/Directory/Revocation/Audit health, CoreDNS-resolved machine IPs,
  and federated A2A v1.0 `AgentCard` inventory with live mTLS 1.3 handshake telemetry.
- `trust`: Manage SSH-style SHA-256 domain trust anchors (`show`, `add`, `fetch`, `remove`)
  stored in Kubernetes `ConfigMap` `lct-trust-anchors` with zero-restart pod hot-reload.
- `send --text "..." [--stream]`: Execute real A2A v1.0 `SendMessage` or `SendStreamingMessage`
  across `org-alpha.io -> org-beta.io -> org-payment.io`, printing per-hop SPIFFE ID,
  peer certificate issuer domain, resolved peer IP, negotiated TLS version/cipher, and decision.
- `cancel <task_id>`: Invoke A2A v1.0 `CancelTask` and verify cross-machine cascading
  revocation propagation on both `beta-revocation` and `payment-revocation` over mTLS 1.3.
- `audit <task_id>`: Fetch signed `AuditEntry` records over TLS 1.3 from `audit-collector`
  and run `CausalChainAuditor` full causal tree reconstruction.
- `e2e`: Run Multi-Host Scenarios `1, 2A, 2B, 3A, 3B, 4, 5, 6` (executing faults directly
  when all roles are local, or pausing with exact operator commands when remote).
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, IO, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

import httpx
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from lineage.a2a import A2AClient, Message, TaskState
from lineage.audit import CausalChainAuditor
from lineage.common.crypto import redact_sensitive, sha256_hex
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
    render_e2e_sync_service_manifest,
    validate_ipv4_address,
)

DEFAULT_DOMAIN_BUNDLE_PORTS: Dict[str, Tuple[str, int]] = {
    "org-alpha.io": ("http", 30094),
    "org-beta.io": ("http", 31094),
    "org-payment.io": ("http", 32094),
    "org-audit.io": ("https", 30893),
}


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
        if base.startswith("eyJhbG") and base.count(".") == 2:
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


# =============================================================================
# `trust` Subcommand (Runs directly on Host via `kubectl` + `httpx`)
# =============================================================================


def _read_configmap_anchors(kube_context: str, namespace: str) -> Dict[str, str]:
    res = subprocess.run(
        [
            "kubectl",
            "--context",
            kube_context,
            "-n",
            namespace,
            "get",
            "configmap",
            "lct-trust-anchors",
            "-o",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        return {}
    obj = json.loads(res.stdout)
    return dict(obj.get("data") or {})


def _write_configmap_anchors(
    kube_context: str, namespace: str, data: Dict[str, str]
) -> None:
    cm_doc = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "lct-trust-anchors", "namespace": namespace},
        "data": data,
    }
    subprocess.run(
        ["kubectl", "--context", kube_context, "apply", "-f", "-"],
        input=json.dumps(cm_doc),
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    # Trigger immediate Kubelet volume sync (<1s) via benign Pod annotation update
    # WITHOUT restarting any container (`restartCount` stays 0)!
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
            f"lct.io/anchor-sync-ts={time.time_ns()}",
            "--overwrite",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _handle_trust_cmd(args: argparse.Namespace) -> int:
    t_sub = args.trust_cmd
    if t_sub == "show":
        roles = _detect_local_lctmh_roles(args.roles)
        out: Dict[str, Any] = {}
        for r in roles:
            spec = ROLE_SPECS[r]
            out[spec.cluster_name] = _read_configmap_anchors(
                spec.kube_context, spec.namespace
            )
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

    if t_sub == "fetch":
        td = args.domain.strip().lower()
        SpiffeId.parse(f"spiffe://{td}/authority/ca")
        ip_clean = validate_ipv4_address(args.ip, "--ip")
        default_scheme, default_port = DEFAULT_DOMAIN_BUNDLE_PORTS.get(td, ("http", 30094))
        scheme = args.scheme or default_scheme
        port = int(args.port) if args.port else default_port
        url = f"{scheme}://{ip_clean}:{port}/v1/federation/bundle"
        verify_arg: Any = False if scheme == "https" else True
        with httpx.Client(verify=verify_arg, timeout=5.0, trust_env=False) as cli:
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
                    "Prefer `trust add <domain> sha256:...` or `trust fetch --expect sha256:...`.",
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
# Gateway-Executed Subcommands (`status`, `send`, `cancel`, `audit`)
# =============================================================================


def _run_status_in_gateway() -> int:
    from lineage.k8s.e2e_driver import (
        ALPHA_CA_URL,
        ALPHA_DIR_URL,
        ALPHA_REV_URL,
        AUDIT_URL,
        BETA_CA_URL,
        BETA_REV_URL,
        PAYMENT_CA_URL,
        PAYMENT_REV_URL,
        TRAVEL_MCP_SVC_URL,
        PAYMENT_MCP_SVC_URL,
        GatewaySession,
    )

    gw = GatewaySession(require_all_peers=False, max_wait_sec=10.0)
    try:
        gw.syncer.sync_all(require_all=False, max_wait_sec=3.0)
        ready_ok, ready_diag = gw.syncer.is_ready()
        control_checks: Dict[str, Any] = {}
        for name, u in (
            ("alpha-ca", f"{ALPHA_CA_URL}/healthz"),
            ("alpha-directory", f"{ALPHA_DIR_URL}/healthz"),
            ("alpha-revocation", f"{ALPHA_REV_URL}/healthz"),
            ("beta-ca-fed", f"{BETA_CA_URL}/healthz"),
            ("payment-ca-fed", f"{PAYMENT_CA_URL}/healthz"),
        ):
            sp = urlsplit(u)
            res_ip = ""
            try:
                infos = socket.getaddrinfo(sp.hostname or "", sp.port or 80, socket.AF_INET)
                res_ip = str(infos[0][4][0]) if infos else ""
                r = httpx.get(u, timeout=3.0)
                control_checks[name] = {
                    "url": u,
                    "resolved_ip": res_ip,
                    "http_status": r.status_code,
                }
            except Exception as exc:
                control_checks[name] = {"url": u, "resolved_ip": res_ip, "error": str(exc)}

        for m_name, m_url in (
            ("beta-revocation-fed", f"{BETA_REV_URL}/healthz"),
            ("payment-revocation-fed", f"{PAYMENT_REV_URL}/healthz"),
        ):
            sp = urlsplit(m_url)
            res_ip = ""
            try:
                infos = socket.getaddrinfo(sp.hostname or "", sp.port or 443, socket.AF_INET)
                res_ip = str(infos[0][4][0]) if infos else ""
                r = gw.get_mtls(m_url, timeout=3.0)
                control_checks[m_name] = {
                    "url": m_url,
                    "resolved_ip": res_ip,
                    "http_status": r.status_code,
                }
            except Exception as exc:
                control_checks[m_name] = {
                    "url": m_url,
                    "resolved_ip": res_ip,
                    "error": str(exc),
                }

        sp_aud = urlsplit(AUDIT_URL)
        aud_ip = ""
        try:
            infos = socket.getaddrinfo(sp_aud.hostname or "", sp_aud.port or 443, socket.AF_INET)
            aud_ip = str(infos[0][4][0]) if infos else ""
            r_aud = gw.audit_client.healthz()
            control_checks["audit-collector"] = {
                "url": f"{AUDIT_URL}/healthz",
                "resolved_ip": aud_ip,
                "http_status": r_aud.status_code,
                "entries_count": r_aud.json().get("count"),
            }
        except Exception as exc:
            control_checks["audit-collector"] = {
                "url": f"{AUDIT_URL}/healthz",
                "resolved_ip": aud_ip,
                "error": str(exc),
            }

        cards = gw.dir_client.discover(only_healthy=True)
        card_summaries: List[Dict[str, Any]] = []
        for c in cards:
            c_info: Dict[str, Any] = {
                "spiffe_id": c.spiffe_id,
                "trust_domain": c.trust_domain,
                "name": c.name,
                "skills": list(c.skills),
                "priority": c.priority,
                "version": c.version,
                "endpoint": c.endpoint,
            }
            try:
                verify_ctx = gw.mtls_bundle.verify_for_target(
                    target_url=c.endpoint,
                    expected_spiffe_id=c.spiffe_id,
                )
                tls_meta = _probe_tls_handshake_details(c.endpoint, verify_ctx, timeout=3.0)
                r_h = gw.get_mtls(f"{c.endpoint.rstrip('/')}/healthz", timeout=3.0)
                c_info["resolved_machine_ip"] = tls_meta["resolved_ip"]
                c_info["tls_version"] = tls_meta["tls_version"]
                c_info["tls_cipher"] = tls_meta["tls_cipher"]
                c_info["healthz_status"] = r_h.status_code
            except Exception as exc:
                c_info["probe_error"] = str(exc)
            card_summaries.append(c_info)

        mcp_tools: List[Dict[str, Any]] = []
        for mcp_lbl, mcp_u, mcp_td in (
            ("travel-ops-mcp", TRAVEL_MCP_SVC_URL.rsplit("/mcp", 1)[0], "org-payment.io"),
            ("payment-vault-mcp", PAYMENT_MCP_SVC_URL.rsplit("/mcp", 1)[0], "org-payment.io"),
        ):
            try:
                v_ctx = gw.mtls_bundle.verify_for_target(
                    target_url=mcp_u, expected_trust_domain=mcp_td
                )
                t_meta = _probe_tls_handshake_details(mcp_u, v_ctx, timeout=3.0)
                mcp_tools.append(t_meta)
            except Exception as exc:
                mcp_tools.append({"endpoint": mcp_u, "error": str(exc)})

        report = {
            "gateway_spiffe_id": gw.identity.spiffe_id,
            "svid_generation": gw.identity.renewal_generation,
            "federation_ready": ready_ok,
            "federation_sync": ready_diag,
            "control_plane": control_checks,
            "discovered_agent_cards": card_summaries,
            "mcp_tool_endpoints": mcp_tools,
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
        ORCH_URL,
        GatewaySession,
        _extract_a2a_task_data,
        _full_travel_root_permissions,
    )

    gw = GatewaySession()
    try:
        task_id = args.task_id or f"task-mh-{uuid.uuid4().hex[:10]}"
        cities = _infer_cities_from_text(args.text, args.city)
        perms = _full_travel_root_permissions(cities, max_amount=float(args.max_amount))
        tok, _ = gw.mint_root_for_user(task_id, args.sub, perms)

        orch_verify_ctx = gw.mtls_bundle.verify_for_target(
            target_url=ORCH_URL, expected_trust_domain="org-alpha.io"
        )
        entry_tls = _probe_tls_handshake_details(ORCH_URL, orch_verify_ctx, timeout=5.0)

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

        # Allow asynchronous audit flusher a brief beat, then fetch verified per-hop audit trail
        time.sleep(0.5)
        entries = gw.audit_client.fetch_entries(task_id=task_id)
        hop_traces: List[Dict[str, Any]] = [
            {
                "hop_index": 0,
                "event_type": "GATEWAY_ENTRY_MTLS",
                "caller_spiffe_id": gw.identity.spiffe_id,
                "target_spiffe_id": entry_tls["peer_spiffe_id"],
                "peer_cert_issuer_domain": entry_tls["peer_issuer_domain"],
                "resolved_peer_ip": entry_tls["resolved_ip"],
                "tls_version": entry_tls["tls_version"],
                "tls_cipher": entry_tls["tls_cipher"],
                "decision": "ALLOW",
            }
        ]
        # Map `(lineage_path, node)` outbound resolved IP onto inbound authz/tool events
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
                hop_traces.append(
                    {
                        "hop_index": e.hop_index,
                        "event_type": e.event_type.value,
                        "lineage_path": e.lineage_path,
                        "node_spiffe_id": e.node_spiffe_id,
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
            "hop_by_hop_mtls_and_lct_trace": hop_traces,
        }
        print(json.dumps(_scrub(output), indent=2, ensure_ascii=False))
        return exit_rc
    finally:
        gw.syncer.stop_background_refresh()
        gw.mtls_bundle.cleanup()


def _run_cancel_in_gateway(args: argparse.Namespace) -> int:
    from lineage.k8s.e2e_driver import (
        ALPHA_REV_URL,
        BETA_REV_URL,
        ORCH_URL,
        PAYMENT_REV_URL,
        GatewaySession,
        _full_travel_root_permissions,
    )

    gw = GatewaySession()
    try:
        task_id = args.task_id
        perms = _full_travel_root_permissions(["Tokyo"], max_amount=800.0)
        tok, _ = gw.mint_root_for_user(task_id, args.sub, perms)

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
        for peer_name, peer_url in (
            ("alpha-revocation", ALPHA_REV_URL),
            ("beta-revocation", BETA_REV_URL),
            ("payment-revocation", PAYMENT_REV_URL),
        ):
            matched = False
            detail: Dict[str, Any] = {"url": peer_url}
            for _ in range(20):
                try:
                    if peer_url.startswith("https://"):
                        r_ev = gw.get_mtls(
                            f"{peer_url}/v1/federation/events?since_version=0", timeout=3.0
                        )
                        r_h = gw.get_mtls(f"{peer_url}/healthz", timeout=3.0)
                        if r_h.status_code == 200:
                            detail["trie_version"] = r_h.json().get("version")
                            if int(r_h.json().get("version", 0)) >= 1:
                                matched = True
                                break
                    else:
                        r_loc = httpx.get(f"{peer_url}/v1/events", timeout=3.0)
                        evs = r_loc.json().get("events", [])
                        if any(e.get("target") == expected_prefix for e in evs):
                            matched = True
                            detail["matched_prefix"] = expected_prefix
                            break
                except Exception as exc:
                    detail["last_error"] = str(exc)
                time.sleep(0.25)
            detail["propagated"] = matched
            propagation[peer_name] = detail

        r_replay = gw.post_lct_mtls(
            ORCH_URL,
            tok,
            {"op": "inspect_inbox", "inspect_task_id": task_id},
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
            return 0 if (report.stream_integrity_ok and trec.reconstructed_complete and not trec.anomalies) else 1

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


def _probe_gateway_endpoint_reachable(
    endpoint_env_var: str,
    kube_context: str = "kind-lctmh-alpha",
    require_directory_card: bool = False,
) -> bool:
    code = (
        "import os, sys\n"
        "from lineage.k8s.e2e_driver import GatewaySession\n"
        f"u = os.environ[{endpoint_env_var!r}].rsplit('/mcp', 1)[0] + '/healthz'\n"
        "gw = GatewaySession(require_all_peers=False, max_wait_sec=3.0, peer_timeout=1.2)\n"
        "try:\n"
        "    gw.syncer.sync_all(require_all=False, max_wait_sec=2.0)\n"
        "    r = gw.get_mtls(u, timeout=1.5)\n"
        "    if r.status_code != 200:\n"
        "        sys.exit(1)\n"
        f"    if {bool(require_directory_card)!r}:\n"
        "        cards = gw.dir_client.discover(skill='travel.hotel', only_healthy=True)\n"
        "        if not any('primary' in c.spiffe_id for c in cards):\n"
        "            sys.exit(1)\n"
        "    sys.exit(0)\n"
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
    pretty_cmd = f"bash lineage/scripts/multihost fault {' '.join(fault_args)}"
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
            is_up = _probe_gateway_endpoint_reachable(
                "HOTEL_PRIMARY_URL",
                require_directory_card=bool(expect_hotel_reachable),
            )
            if is_up == expect_hotel_reachable:
                return
            time.sleep(1.0)
        raise TimeoutError(
            f"Timed out ({timeout_sec}s) waiting for HOTEL_PRIMARY_URL reachable={expect_hotel_reachable} after `{pretty_cmd}`"
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
    out_Clusters = subprocess.run(["kind", "get", "clusters"], capture_output=True, text=True)
    local_clusters = set((out_Clusters.stdout or "").splitlines())
    if "lctmh-alpha" not in local_clusters:
        raise RuntimeError(
            "`e2e` must be run on Machine 1 hosting `lctmh-alpha` (`e2e-user-gateway`)."
        )
    local_beta = ("lctmh-beta" in local_clusters) and (not args.remote_faults)
    op_timeout = float(args.operator_timeout)
    results: Dict[str, Any] = {"run_id": run_id, "local_beta_auto_fault": local_beta, "scenarios": {}}

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
        print("[e2e] Running Scenario 1 (Cross-Machine A2A v1.0 + SSE + 1-to-N / N-to-1 / M-to-N DAG)...", flush=True)
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
        # Transiently expose NodePort `30990` ONLY for the duration of Scenario 3B (`[MEDIUM-M6-01]`)
        sync_svc_yaml = yaml.safe_dump(render_e2e_sync_service_manifest("lineage-alpha"), sort_keys=False)
        subprocess.run(
            ["kubectl", "--context", "kind-lctmh-alpha", "apply", "-f", "-"],
            input=sync_svc_yaml,
            text=True,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        # Allow kube-proxy NodePort iptables rules a brief beat to program :30990
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
            # Wait for leaf arrival sync marker inside `e2e-user-gateway`
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
            # Wait for `/tmp/s6_ready_disconnect`
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

            # Wait for `/tmp/s6_ready_reconnect`
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
    print(json.dumps({"run_id": run_id, "overall_status": "PASS", "scenarios": list(results["scenarios"].keys())}, indent=2))
    return 0


# =============================================================================
# CLI Argument Parser (Exposed for Unit Tests & Interactive Use)
# =============================================================================


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lct_multihost_cli.py",
        description="Cross-Machine LCT Federation Operator & Verification CLI",
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
    sub.add_parser("status", help="Show per-domain health, resolved machine IPs, and AgentCards")

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

    p_t_fetch = t_sub.add_parser(
        "fetch", help="Fetch candidate bundle from peer IP, display fingerprint, and pin on confirmation"
    )
    p_t_fetch.add_argument("--domain", required=True, help="Expected trust domain")
    p_t_fetch.add_argument("--ip", required=True, help="Peer machine IPv4 address")
    p_t_fetch.add_argument("--port", type=int, default=0, help="Override bundle port")
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

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_cli_parser()
    args = parser.parse_args(raw_argv)

    # Additional semantic validation on CLI arguments
    if args.subcmd == "send":
        if not args.text.strip():
            parser.error("--text must not be empty")
        if args.max_amount <= 0:
            parser.error("--max-amount must be positive")
    if args.subcmd == "cancel" and not args.task_id.strip():
        parser.error("task_id must not be empty")
    if args.subcmd == "trust" and args.trust_cmd == "fetch":
        try:
            SpiffeId.parse(f"spiffe://{args.domain.strip().lower()}/authority/ca")
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

    if args.subcmd == "e2e":
        return _run_e2e_suite_from_host(args)

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
