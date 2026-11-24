"""Host-Side Self-Locating Agent (`locator-agent`) for Multi-Host LCT Clusters.

Responsibilities:
1. Automatically detects the host machine's primary routable RFC1918 LAN IPv4 address
   across macOS (`route -n get default` / `ipconfig getifaddr`), Linux (`ip -4 route`),
   and Windows+WSL2 (`powershell.exe` / `ipconfig.exe` parsing of the Windows host LAN
   adapter — never the unreachable WSL2 `172.x` NAT interface).
   Note: Never auto-detects or advertises VPN/CGNAT/`100.64.0.0/10` interfaces;
   supports explicit `--advertise-ip` override for multi-NIC machines (e.g. VMware).
2. Writes per-cluster `ConfigMap/lct-node-locator` (`locator.json`) containing the
   current advertised IPv4(s) and local NodePort table. When DHCP or `--set-role-ip`
   changes an IP, updates `ConfigMap/lct-node-locator` in-place so Pods re-sign their
   `SignedDomainDescriptor`s and `AgentCard`s with `version + 1` and zero Pod restarts.
3. Persists verified domain descriptors into `ConfigMap/lct-learned-descriptors` so
   Pod/cluster restarts converge immediately without needing bootstrap seeds again.
4. Optionally runs opt-in DNS-SD `_lct._tcp.local.` (`--discover mdns`), feeding any
   discovered `ip:port` hints into `ConfigMap/lct-bootstrap-seeds` as untrusted seeds.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import httpx
import yaml

from lineage.common.locators import (
    DEFAULT_ALLOWED_LOCATOR_CIDRS,
    MAX_BOOTSTRAP_SEEDS,
    LocatorError,
    normalize_seed_endpoint,
    validate_locator_host,
)
from lineage.multihost.mdns_discovery import MDNSSeedBroadcaster

ROLE_ORDER: Tuple[str, ...] = ("alpha", "beta", "pay", "audit")
ROLE_TO_NAMESPACE: Dict[str, str] = {
    "alpha": "lineage-alpha",
    "beta": "lineage-beta",
    "pay": "lineage-pay",
    "audit": "lineage-audit",
}
ROLE_TO_DOMAIN: Dict[str, str] = {
    "alpha": "org-alpha.io",
    "beta": "org-beta.io",
    "pay": "org-payment.io",
    "audit": "org-audit.io",
}

_VIRTUAL_WIN_ADAPTER_KEYWORDS: Tuple[str, ...] = (
    "vethernet",
    "wsl",
    "hyper-v",
    "vmware",
    "vmnet",
    "virtualbox",
    "vboxnet",
    "docker",
    "loopback",
    "npcap",
    "bluetooth",
    "zerotier",
    "wireguard",
    "wintun",
    "tap-windows",
    "tap-",
    "tun",
    "quickq",
    "clash",
    "sing-box",
)

_VIRTUAL_LINUX_IFACE_PREFIXES: Tuple[str, ...] = (
    "lo",
    "docker",
    "br-",
    "veth",
    "cni",
    "flannel",
    "cali",
    "virbr",
    "vboxnet",
    "vmnet",
    "utun",
    "tun",
    "tap",
    "wg",
    "zt",
)


def default_state_dir() -> Path:
    env_dir = os.environ.get("LCT_LOCATOR_STATE_DIR", "").strip()
    if env_dir:
        return Path(env_dir)
    return Path(tempfile.gettempdir()) / "lct-locator-agent"


def is_wsl2_environment(proc_version_text: Optional[str] = None) -> bool:
    """Return True when running inside a Windows Subsystem for Linux (WSL2) kernel."""
    if proc_version_text is not None:
        low = proc_version_text.lower()
        return ("microsoft" in low) or ("wsl" in low)
    if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
        return True
    for candidate in ("/proc/sys/kernel/osrelease", "/proc/version"):
        try:
            txt = Path(candidate).read_text(encoding="utf-8", errors="ignore").lower()
            if "microsoft" in txt or "wsl" in txt:
                return True
        except OSError:
            continue
    return False


def _is_virtual_windows_adapter_name(name: str) -> bool:
    low = name.strip().lower()
    return any(kw in low for kw in _VIRTUAL_WIN_ADAPTER_KEYWORDS)


def parse_windows_powershell_lan_ips(
    output_text: str,
    allowed_cidrs: Optional[Iterable[str] | str] = None,
) -> List[str]:
    """Parse JSON or `InterfaceAlias|IPAddress` lines emitted by `powershell.exe` route query."""
    text = (output_text or "").strip()
    if not text:
        return []
    results: List[str] = []
    try:
        parsed = json.loads(text)
        rows = [parsed] if isinstance(parsed, Mapping) else (parsed if isinstance(parsed, list) else [])
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            alias = str(row.get("InterfaceAlias") or row.get("Alias") or "")
            desc = str(row.get("InterfaceDescription") or "")
            ip_val = str(row.get("IPAddress") or "").strip()
            if _is_virtual_windows_adapter_name(alias) or _is_virtual_windows_adapter_name(desc):
                continue
            try:
                clean_ip = validate_locator_host(ip_val, allowed_cidrs=allowed_cidrs)
                if clean_ip not in results:
                    results.append(clean_ip)
            except LocatorError:
                continue
        if results:
            return results
    except Exception:
        pass

    for raw_ln in text.splitlines():
        ln = raw_ln.strip()
        if not ln:
            continue
        if "|" in ln:
            alias, ip_val = ln.split("|", 1)
            if _is_virtual_windows_adapter_name(alias):
                continue
        else:
            ip_val = ln
        try:
            clean_ip = validate_locator_host(ip_val.strip(), allowed_cidrs=allowed_cidrs)
            if clean_ip not in results:
                results.append(clean_ip)
        except LocatorError:
            continue
    return results


def _decode_windows_cli_bytes(raw: bytes | str) -> str:
    """Decode Windows CLI output bytes strictly as UTF-8 first, then GBK/CP936, then UTF-8 replace."""
    if isinstance(raw, str):
        return raw
    if not raw:
        return ""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        return raw.decode("gbk")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace")


def parse_windows_ipconfig_lan_ips(
    ipconfig_text: str,
    allowed_cidrs: Optional[Iterable[str] | str] = None,
) -> List[str]:
    """Parse `ipconfig.exe [/all]` (English or localized) selecting physical adapters with a Default Gateway."""
    if not ipconfig_text:
        return []
    sections: List[Tuple[str, List[str]]] = []
    cur_header = ""
    cur_lines: List[str] = []
    for raw_ln in ipconfig_text.splitlines():
        ln = raw_ln.rstrip("\r")
        if ln and not ln.startswith((" ", "\t")) and ln.endswith(":"):
            if cur_header or cur_lines:
                sections.append((cur_header, cur_lines))
            cur_header = ln[:-1].strip()
            cur_lines = []
        else:
            cur_lines.append(ln)
    if cur_header or cur_lines:
        sections.append((cur_header, cur_lines))

    gateway_ips: List[str] = []
    fallback_ips: List[str] = []
    ipv4_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

    for header, lines in sections:
        if _is_virtual_windows_adapter_name(header):
            continue
        is_virtual_desc = False
        for line in lines:
            low_desc = line.strip().lower()
            if low_desc.startswith("description") or "描述" in low_desc:
                desc_val = line.split(":", 1)[1].strip() if ":" in line else line
                if _is_virtual_windows_adapter_name(desc_val):
                    is_virtual_desc = True
                    break
        if is_virtual_desc:
            continue

        found_v4: List[str] = []
        has_gateway = False
        for idx, line in enumerate(lines):
            low = line.lower()
            if "ipv4" in low or "ip address" in low or "ip 地址" in low:
                for m in ipv4_re.findall(line):
                    try:
                        clean = validate_locator_host(m, allowed_cidrs=allowed_cidrs)
                        if clean not in found_v4:
                            found_v4.append(clean)
                    except LocatorError:
                        continue
            if "default gateway" in low or "默认网关" in low:
                tail = line.split(":", 1)[1].strip() if ":" in line else ""
                if tail and any(ch.isdigit() for ch in tail):
                    has_gateway = True
                elif idx + 1 < len(lines) and ":" not in lines[idx + 1]:
                    nxt = lines[idx + 1].strip()
                    if nxt and any(ch.isdigit() for ch in nxt):
                        has_gateway = True
        if has_gateway:
            for ip in found_v4:
                if ip not in gateway_ips:
                    gateway_ips.append(ip)
        else:
            for ip in found_v4:
                if ip not in fallback_ips:
                    fallback_ips.append(ip)

    if gateway_ips:
        return gateway_ips
    fallback_ips.sort(key=lambda ip: (1 if ip.endswith(".1") else 0))
    return fallback_ips


def _detect_wsl2_windows_host_ips(
    allowed_cidrs: Optional[Iterable[str] | str] = None,
) -> List[Tuple[str, int, str]]:
    ps_script = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
        "Sort-Object RouteMetric,InterfaceMetric | "
        "ForEach-Object { "
        "  $idx = $_.InterfaceIndex; "
        "  $ad = Get-NetAdapter -InterfaceIndex $idx -ErrorAction SilentlyContinue; "
        "  Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "  ForEach-Object { [PSCustomObject]@{ InterfaceAlias=$_.InterfaceAlias; InterfaceDescription=$ad.InterfaceDescription; IPAddress=$_.IPAddress } } "
        "} | ConvertTo-Json -Compress"
    )
    for ps_bin in ("powershell.exe", "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"):
        try:
            proc = subprocess.run(
                [ps_bin, "-NoProfile", "-NonInteractive", "-Command", ps_script],
                capture_output=True,
                text=False,
                timeout=6.0,
            )
            ps_out = _decode_windows_cli_bytes(proc.stdout)
            if proc.returncode == 0 and ps_out.strip():
                ips = parse_windows_powershell_lan_ips(ps_out, allowed_cidrs=allowed_cidrs)
                if ips:
                    return [(ip, 10 + i * 10, "wsl2-powershell-host-lan") for i, ip in enumerate(ips)]
        except Exception:
            continue

    for ipc_bin in ("ipconfig.exe", "/mnt/c/Windows/System32/ipconfig.exe"):
        for ipc_args in ([ipc_bin, "/all"], [ipc_bin]):
            try:
                proc = subprocess.run(
                    ipc_args,
                    capture_output=True,
                    text=False,
                    timeout=5.0,
                )
                raw_out = _decode_windows_cli_bytes(proc.stdout)
                if not raw_out.strip():
                    continue
                ips = parse_windows_ipconfig_lan_ips(raw_out, allowed_cidrs=allowed_cidrs)
                if ips:
                    return [(ip, 10 + i * 10, "wsl2-ipconfig-host-lan") for i, ip in enumerate(ips)]
            except Exception:
                continue
    return []


def _detect_macos_lan_ips(
    allowed_cidrs: Optional[Iterable[str] | str] = None,
) -> List[Tuple[str, int, str]]:
    candidates: List[Tuple[str, int, str]] = []
    default_iface = ""
    try:
        rt = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True,
            text=True,
            timeout=3.0,
        )
        for ln in rt.stdout.splitlines():
            s = ln.strip()
            if s.startswith("interface:"):
                default_iface = s.split(":", 1)[1].strip()
                break
    except Exception:
        default_iface = ""

    # Never auto-advertise utun*/VPN tunnels even if a proxy temporarily hijacked default route
    probe_ifaces: List[str] = []
    if default_iface and not default_iface.startswith(("utun", "tun", "tap", "lo", "bridge", "vmnet")):
        probe_ifaces.append(default_iface)
    for fallback_if in ("en0", "en1", "en2", "en3"):
        if fallback_if not in probe_ifaces:
            probe_ifaces.append(fallback_if)

    for iface in probe_ifaces:
        try:
            r = subprocess.run(
                ["ipconfig", "getifaddr", iface],
                capture_output=True,
                text=True,
                timeout=2.5,
            )
            ip_raw = r.stdout.strip()
            if r.returncode == 0 and ip_raw:
                clean = validate_locator_host(ip_raw, allowed_cidrs=allowed_cidrs)
                if all(existing_ip != clean for existing_ip, _, _ in candidates):
                    prio = 10 if not candidates else (10 + len(candidates) * 10)
                    candidates.append((clean, prio, f"macos:{iface}"))
                # Primary default-route physical interface is authoritative
                if iface == default_iface:
                    break
        except Exception:
            continue
    return candidates


def _detect_linux_lan_ips(
    allowed_cidrs: Optional[Iterable[str] | str] = None,
) -> List[Tuple[str, int, str]]:
    candidates: List[Tuple[str, int, str]] = []
    try:
        rt = subprocess.run(
            ["ip", "-4", "-o", "route", "get", "10.255.255.254"],
            capture_output=True,
            text=True,
            timeout=3.0,
        )
        m_dev = re.search(r"\bdev\s+(\S+)", rt.stdout)
        m_src = re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)", rt.stdout)
        dev_name = m_dev.group(1) if m_dev else ""
        if (
            m_src
            and dev_name
            and not dev_name.startswith(_VIRTUAL_LINUX_IFACE_PREFIXES)
        ):
            clean = validate_locator_host(m_src.group(1), allowed_cidrs=allowed_cidrs)
            candidates.append((clean, 10, f"linux-route:{dev_name}"))
            return candidates
    except Exception:
        pass

    try:
        ad = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "up"],
            capture_output=True,
            text=True,
            timeout=3.0,
        )
        for ln in ad.stdout.splitlines():
            parts = ln.split()
            if len(parts) < 4:
                continue
            dev_name = parts[1]
            if dev_name.startswith(_VIRTUAL_LINUX_IFACE_PREFIXES):
                continue
            m_ip = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", ln)
            if not m_ip:
                continue
            try:
                clean = validate_locator_host(m_ip.group(1), allowed_cidrs=allowed_cidrs)
                if all(existing_ip != clean for existing_ip, _, _ in candidates):
                    candidates.append((clean, 10 + len(candidates) * 10, f"linux:{dev_name}"))
                    break
            except LocatorError:
                continue
    except Exception:
        pass
    return candidates


def detect_host_lan_locators(
    advertise_ips_override: Optional[Sequence[str] | str] = None,
    allowed_cidrs: Optional[Iterable[str] | str] = None,
) -> List[Dict[str, Any]]:
    """Return prioritized `[{'host': '<IPv4>', 'priority': 10, 'source': '...'}]` for this host."""
    eff_cidrs = allowed_cidrs if allowed_cidrs is not None else DEFAULT_ALLOWED_LOCATOR_CIDRS

    if advertise_ips_override:
        raw_list = (
            [s.strip() for s in advertise_ips_override.split(",") if s.strip()]
            if isinstance(advertise_ips_override, str)
            else [str(s).strip() for s in advertise_ips_override if str(s).strip()]
        )
        override_out: List[Dict[str, Any]] = []
        for idx, raw_ip in enumerate(raw_list):
            clean = validate_locator_host(raw_ip, allowed_cidrs=eff_cidrs)
            if all(item["host"] != clean for item in override_out):
                override_out.append(
                    {"host": clean, "priority": 10 + idx * 10, "source": "operator-override"}
                )
        if not override_out:
            raise LocatorError("Empty --advertise-ip override after validation")
        return override_out

    detected: List[Tuple[str, int, str]] = []
    if is_wsl2_environment():
        detected = _detect_wsl2_windows_host_ips(allowed_cidrs=eff_cidrs)
        if not detected:
            raise LocatorError(
                "WSL2 detected, but could not auto-detect Windows host LAN IPv4 via powershell.exe/ipconfig.exe. "
                "Pass '--advertise-ip <Windows-LAN-IPv4>' explicitly."
            )
    elif sys.platform == "darwin":
        detected = _detect_macos_lan_ips(allowed_cidrs=eff_cidrs)
    else:
        detected = _detect_linux_lan_ips(allowed_cidrs=eff_cidrs)

    if not detected:
        # Pure stdlib UDP routing-table probe (transmits zero packets)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("10.255.255.254", 80))
                cand_ip = s.getsockname()[0]
            clean = validate_locator_host(cand_ip, allowed_cidrs=eff_cidrs)
            detected.append((clean, 10, "udp-route-probe"))
        except Exception as exc:
            raise LocatorError(
                f"Could not auto-detect a valid RFC1918 LAN IPv4 on this host ({exc}). "
                f"Pass '--advertise-ip <LAN-IPv4>' explicitly."
            ) from exc

    return [
        {"host": ip, "priority": prio, "source": src}
        for ip, prio, src in detected
    ]


def _kubectl_json(context: str, args: Sequence[str]) -> Optional[Dict[str, Any]]:
    proc = subprocess.run(
        ["kubectl", "--context", context, *args, "-o", "json"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        return json.loads(proc.stdout)
    except Exception:
        return None


def _apply_configmap(
    context: str,
    namespace: str,
    name: str,
    data: Mapping[str, str],
    trigger_volume_sync: bool = False,
) -> None:
    cm = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": namespace},
        "data": {str(k): str(v) for k, v in data.items()},
    }
    subprocess.run(
        ["kubectl", "--context", context, "apply", "-f", "-"],
        input=yaml.safe_dump(cm, sort_keys=False),
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    if trigger_volume_sync:
        subprocess.run(
            [
                "kubectl",
                "--context",
                context,
                "-n",
                namespace,
                "annotate",
                "pods",
                "--all",
                f"lct.io/{name}-sync={time.time_ns()}",
                "--overwrite",
            ],
            capture_output=True,
            text=True,
            check=False,
        )


def discover_local_active_roles(filter_roles: Optional[Sequence[str]] = None) -> List[str]:
    proc = subprocess.run(
        ["kind", "get", "clusters"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return []
    clusters = {ln.strip() for ln in proc.stdout.splitlines() if ln.strip()}
    wanted = set(filter_roles) if filter_roles else set(ROLE_ORDER)
    return [r for r in ROLE_ORDER if r in wanted and f"lctmh-{r}" in clusters]


def read_role_ports_from_cluster(role: str) -> Dict[str, int]:
    ctx = f"kind-lctmh-{role}"
    ns = ROLE_TO_NAMESPACE[role]
    ns_obj = _kubectl_json(ctx, ["get", "namespace", ns])
    if not ns_obj:
        return {}
    ann = (ns_obj.get("metadata") or {}).get("annotations") or {}
    raw_ports = ann.get("lct.io/role-ports-json", "")
    if not raw_ports:
        return {}
    try:
        parsed = json.loads(raw_ports)
        if isinstance(parsed, Mapping):
            return {str(k): int(v) for k, v in parsed.items()}
    except Exception:
        pass
    return {}


def load_role_overrides(state_dir: Path) -> Dict[str, List[str]]:
    f = state_dir / "role_overrides.json"
    if not f.is_file():
        return {}
    try:
        raw = json.loads(f.read_text(encoding="utf-8"))
        if isinstance(raw, Mapping):
            return {
                str(k): [str(x) for x in v]
                for k, v in raw.items()
                if isinstance(v, list) and v
            }
    except Exception:
        pass
    return {}


def save_role_overrides(state_dir: Path, overrides: Mapping[str, List[str]]) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    f = state_dir / "role_overrides.json"
    f.write_text(json.dumps(dict(overrides), indent=2) + "\n", encoding="utf-8")


def sync_clusters_once(
    roles: Optional[Sequence[str]] = None,
    global_advertise_ip: Optional[str] = None,
    allowed_cidrs: Optional[Iterable[str] | str] = None,
    state_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Reconcile `lct-node-locator` and `lct-learned-descriptors` across active local clusters."""
    sdir = state_dir or default_state_dir()
    sdir.mkdir(parents=True, exist_ok=True)
    role_overrides = load_role_overrides(sdir)
    active_roles = discover_local_active_roles(roles)
    report: Dict[str, Any] = {"roles": {}}

    for role in active_roles:
        ctx = f"kind-lctmh-{role}"
        ns = ROLE_TO_NAMESPACE[role]
        if _kubectl_json(ctx, ["get", "namespace", ns]) is None:
            continue
        ports = read_role_ports_from_cluster(role)
        ovr_ips = role_overrides.get(role)
        eff_override: Optional[Sequence[str] | str] = (
            ovr_ips if ovr_ips else global_advertise_ip
        )
        locs = detect_host_lan_locators(
            advertise_ips_override=eff_override,
            allowed_cidrs=allowed_cidrs,
        )

        # Read existing ConfigMap to avoid noisy no-op updates
        existing_cm = _kubectl_json(ctx, ["-n", ns, "get", "configmap", "lct-node-locator"])
        prev_json_str = ((existing_cm or {}).get("data") or {}).get("locator.json", "")
        prev_epoch = 0
        same_state = False
        if prev_json_str:
            try:
                prev_obj = json.loads(prev_json_str)
                prev_epoch = int(prev_obj.get("epoch", 0))
                if (
                    prev_obj.get("locators") == locs
                    and prev_obj.get("ports") == ports
                ):
                    same_state = True
            except Exception:
                same_state = False

        updated_locator = False
        next_epoch = prev_epoch if same_state else (prev_epoch + 1)
        if not same_state:
            payload = {
                "role": role,
                "trust_domain": ROLE_TO_DOMAIN[role],
                "epoch": next_epoch,
                "updated_at": round(time.time(), 3),
                "locators": locs,
                "ports": ports,
            }
            _apply_configmap(
                ctx,
                ns,
                "lct-node-locator",
                {"locator.json": json.dumps(payload, indent=2)},
                trigger_volume_sync=True,
            )
            updated_locator = True

        # Persist learned verified descriptors into ConfigMap/lct-learned-descriptors
        persisted_count = 0
        ca_port = ports.get("ca_federation")
        if ca_port:
            try:
                resp = httpx.get(
                    f"http://127.0.0.1:{ca_port}/v1/federation/descriptors",
                    timeout=2.0,
                    trust_env=False,
                )
                if resp.status_code == 200:
                    desc_body = resp.json()
                    descs = desc_body.get("descriptors") or []
                    if isinstance(descs, list) and descs:
                        persisted_count = len(descs)
                        canonical_str = json.dumps(
                            {"descriptors": descs}, sort_keys=True, separators=(",", ":")
                        )
                        existing_desc_cm = _kubectl_json(
                            ctx, ["-n", ns, "get", "configmap", "lct-learned-descriptors"]
                        )
                        prev_desc_str = ((existing_desc_cm or {}).get("data") or {}).get(
                            "descriptors.json", ""
                        )
                        if canonical_str != prev_desc_str:
                            _apply_configmap(
                                ctx,
                                ns,
                                "lct-learned-descriptors",
                                {"descriptors.json": canonical_str},
                            )
            except Exception:
                pass

        report["roles"][role] = {
            "epoch": next_epoch,
            "updated_locator": updated_locator,
            "locators": locs,
            "ports": ports,
            "persisted_descriptors": persisted_count,
        }

    return report


def append_seed_to_local_clusters(
    seed: str, roles: Optional[Sequence[str]] = None
) -> List[str]:
    norm_seed = normalize_seed_endpoint(seed)
    updated_roles: List[str] = []
    for role in discover_local_active_roles(roles):
        ctx = f"kind-lctmh-{role}"
        ns = ROLE_TO_NAMESPACE[role]
        cm = _kubectl_json(ctx, ["-n", ns, "get", "configmap", "lct-bootstrap-seeds"])
        data_map = (cm or {}).get("data") or {}
        cur_list: List[str] = []
        if isinstance(data_map, Mapping):
            for raw_val in data_map.values():
                for raw_item in str(raw_val or "").replace(",", "\n").splitlines():
                    val = raw_item.strip()
                    if not val or val.startswith("#"):
                        continue
                    try:
                        ns_existing = normalize_seed_endpoint(val)
                        if ns_existing not in cur_list and len(cur_list) < MAX_BOOTSTRAP_SEEDS:
                            cur_list.append(ns_existing)
                    except LocatorError:
                        continue
        needs_key_migration = isinstance(data_map, Mapping) and ("seeds.txt" in data_map)
        added_new = False
        if norm_seed not in cur_list and len(cur_list) < MAX_BOOTSTRAP_SEEDS:
            cur_list.append(norm_seed)
            added_new = True
        if added_new or needs_key_migration:
            _apply_configmap(
                ctx,
                ns,
                "lct-bootstrap-seeds",
                {"seeds": "\n".join(cur_list) + "\n"},
                trigger_volume_sync=True,
            )
            updated_roles.append(role)
    return updated_roles


def stop_running_daemon(state_dir: Optional[Path] = None) -> bool:
    sdir = state_dir or default_state_dir()
    pid_file = sdir / "locator-agent.pid"
    stopped = False
    if pid_file.is_file():
        try:
            pid = int(pid_file.read_text(encoding="utf-8").strip())
            os.kill(pid, signal.SIGTERM)
            for _ in range(25):
                try:
                    os.kill(pid, 0)
                    time.sleep(0.1)
                except ProcessLookupError:
                    break
            stopped = True
        except Exception:
            pass
        try:
            pid_file.unlink(missing_ok=True)
        except OSError:
            pass
    try:
        (sdir / "role_overrides.json").unlink(missing_ok=True)
    except OSError:
        pass
    return stopped


def start_background_daemon(
    roles_csv: str = "",
    advertise_ip: str = "",
    discover_mode: str = "",
    interval_sec: float = 2.0,
    allowed_cidrs: str = "",
    state_dir: Optional[Path] = None,
) -> int:
    sdir = state_dir or default_state_dir()
    sdir.mkdir(parents=True, exist_ok=True)

    # Persist per-role advertise_ip override (or clear stale override when deploying without --advertise-ip)
    target_roles = [
        r.strip().lower()
        for r in roles_csv.split(",")
        if r.strip() and r.strip().lower() != "all"
    ]
    if roles_csv.strip().lower() == "all":
        target_roles = list(ROLE_ORDER)
    if target_roles:
        ovrs = load_role_overrides(sdir)
        if advertise_ip.strip():
            validated = [
                item["host"]
                for item in detect_host_lan_locators(
                    advertise_ips_override=advertise_ip,
                    allowed_cidrs=allowed_cidrs or None,
                )
            ]
            for r in target_roles:
                ovrs[r] = validated
        else:
            for r in target_roles:
                ovrs.pop(r, None)
        save_role_overrides(sdir, ovrs)

    pid_file = sdir / "locator-agent.pid"
    if pid_file.is_file():
        try:
            old_pid = int(pid_file.read_text(encoding="utf-8").strip())
            os.kill(old_pid, 0)
            if not discover_mode:
                sync_clusters_once(
                    roles=None,
                    allowed_cidrs=allowed_cidrs or None,
                    state_dir=sdir,
                )
                return old_pid
            # Restart daemon if --discover mode was explicitly requested
            os.kill(old_pid, signal.SIGTERM)
            time.sleep(0.2)
        except Exception:
            pass
        pid_file.unlink(missing_ok=True)

    cmd = [
        sys.executable,
        "-m",
        "lineage.multihost.locator_agent",
        "--foreground-loop",
        "--interval",
        str(interval_sec),
        "--state-dir",
        str(sdir),
    ]
    if not target_roles and advertise_ip:
        cmd.extend(["--advertise-ip", advertise_ip])
    if discover_mode:
        cmd.extend(["--discover", discover_mode])
    if allowed_cidrs:
        cmd.extend(["--allowed-cidrs", allowed_cidrs])

    log_path = sdir / "locator-agent.log"
    with open(log_path, "a", encoding="utf-8") as log_fh:
        proc = subprocess.Popen(
            cmd,
            stdout=log_fh,
            stderr=log_fh,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    pid_file.write_text(f"{proc.pid}\n", encoding="utf-8")
    return proc.pid


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="LCT Host-Side Self-Locating Agent")
    p.add_argument("--roles", default="", help="Optional comma-separated roles filter")
    p.add_argument(
        "--advertise-ip",
        default="",
        help="Explicit host LAN IPv4 override (comma-separated for multi-NIC fallback)",
    )
    p.add_argument(
        "--allowed-cidrs",
        default="",
        help="Optional comma-separated locator CIDR allowlist (defaults strictly to RFC1918)",
    )
    p.add_argument(
        "--discover",
        choices=("", "none", "mdns"),
        default="",
        help="Optional zero-config same-LAN seed discovery ('mdns' for _lct._tcp.local.)",
    )
    p.add_argument("--interval", type=float, default=2.0, help="Watch interval seconds")
    p.add_argument("--state-dir", default="", help="State directory for PID & role overrides")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="Reconcile once and print JSON")
    mode.add_argument("--daemon", action="store_true", help="Start background daemon and exit")
    mode.add_argument("--foreground-loop", action="store_true", help=argparse.SUPPRESS)
    mode.add_argument("--stop", action="store_true", help="Stop background daemon cleanly")
    mode.add_argument("--detect-only", action="store_true", help="Print detected host LAN IPv4(s)")
    mode.add_argument(
        "--set-role-ip",
        action="store_true",
        help="Live-switch a specific role's advertised IPv4(s) without restarting Pods",
    )
    mode.add_argument(
        "--clear-role-ip",
        action="store_true",
        help="Clear per-role IPv4 override and revert role to auto-detected host LAN IP",
    )
    p.add_argument("--role", default="", help="Target role for --set-role-ip / --clear-role-ip")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    sdir = Path(args.state_dir) if args.state_dir else default_state_dir()
    cidrs = args.allowed_cidrs.strip() or None
    roles_filter = [
        r.strip().lower() for r in args.roles.split(",") if r.strip() and r.strip() != "all"
    ] or None

    if args.stop:
        was_running = stop_running_daemon(sdir)
        print(json.dumps({"stopped": was_running, "state_dir": str(sdir)}))
        return 0

    if args.detect_only:
        locs = detect_host_lan_locators(
            advertise_ips_override=args.advertise_ip or None,
            allowed_cidrs=cidrs,
        )
        print(json.dumps({"locators": locs}, indent=2))
        return 0

    if args.set_role_ip:
        r = args.role.strip().lower()
        if r not in ROLE_TO_NAMESPACE or not args.advertise_ip.strip():
            print("ERROR: --set-role-ip requires --role <alpha|beta|pay|audit> and --advertise-ip <IPv4>", file=sys.stderr)
            return 2
        validated = [
            item["host"]
            for item in detect_host_lan_locators(
                advertise_ips_override=args.advertise_ip,
                allowed_cidrs=cidrs,
            )
        ]
        ovrs = load_role_overrides(sdir)
        ovrs[r] = validated
        save_role_overrides(sdir, ovrs)
        rep = sync_clusters_once(
            roles=[r],
            allowed_cidrs=cidrs,
            state_dir=sdir,
        )
        print(json.dumps(rep, indent=2))
        return 0

    if args.clear_role_ip:
        r = args.role.strip().lower()
        if r not in ROLE_TO_NAMESPACE:
            print("ERROR: --clear-role-ip requires --role <alpha|beta|pay|audit>", file=sys.stderr)
            return 2
        ovrs = load_role_overrides(sdir)
        ovrs.pop(r, None)
        save_role_overrides(sdir, ovrs)
        rep = sync_clusters_once(
            roles=[r],
            global_advertise_ip=args.advertise_ip or None,
            allowed_cidrs=cidrs,
            state_dir=sdir,
        )
        print(json.dumps(rep, indent=2))
        return 0

    if args.daemon:
        pid = start_background_daemon(
            roles_csv=args.roles,
            advertise_ip=args.advertise_ip,
            discover_mode=args.discover,
            interval_sec=args.interval,
            allowed_cidrs=args.allowed_cidrs,
            state_dir=sdir,
        )
        # Run synchronous pass so ConfigMaps exist immediately before deploy continues
        sync_clusters_once(
            roles=None,
            allowed_cidrs=cidrs,
            state_dir=sdir,
        )
        print(json.dumps({"daemon_pid": pid, "state_dir": str(sdir)}))
        return 0

    if args.foreground_loop:
        stop_flag = False

        def _sig_handler(_signum: int, _frame: Any) -> None:
            nonlocal stop_flag
            stop_flag = True

        signal.signal(signal.SIGTERM, _sig_handler)
        signal.signal(signal.SIGINT, _sig_handler)

        mdns: Optional[MDNSSeedBroadcaster] = None
        if args.discover == "mdns":
            def _local_mdns_provider() -> List[Tuple[str, str, int]]:
                items: List[Tuple[str, str, int]] = []
                ovrs = load_role_overrides(sdir)
                for r in discover_local_active_roles(roles_filter):
                    ports = read_role_ports_from_cluster(r)
                    ca_p = ports.get("ca_federation")
                    if not ca_p:
                        continue
                    try:
                        locs = detect_host_lan_locators(
                            advertise_ips_override=ovrs.get(r) or args.advertise_ip or None,
                            allowed_cidrs=cidrs,
                        )
                        if locs:
                            items.append((ROLE_TO_DOMAIN[r], str(locs[0]["host"]), int(ca_p)))
                    except Exception:
                        continue
                return items

            def _on_mdns_seed(td: str, seed_ep: str) -> None:
                local_tds = {ROLE_TO_DOMAIN[r] for r in discover_local_active_roles(roles_filter)}
                if td in local_tds:
                    return
                append_seed_to_local_clusters(seed_ep, roles=roles_filter)

            mdns = MDNSSeedBroadcaster(
                local_announcements_provider=_local_mdns_provider,
                on_seed_discovered=_on_mdns_seed,
                allowed_cidrs=cidrs,
            )
            mdns.start()

        try:
            while not stop_flag:
                try:
                    sync_clusters_once(
                        roles=roles_filter,
                        global_advertise_ip=args.advertise_ip or None,
                        allowed_cidrs=cidrs,
                        state_dir=sdir,
                    )
                except Exception as exc:
                    print(f"[locator-agent:warn] {exc}", file=sys.stderr, flush=True)
                time.sleep(max(0.5, float(args.interval)))
        finally:
            if mdns is not None:
                mdns.stop()
        return 0

    # Default / --once
    rep = sync_clusters_once(
        roles=roles_filter,
        global_advertise_ip=args.advertise_ip or None,
        allowed_cidrs=cidrs,
        state_dir=sdir,
    )
    print(json.dumps(rep, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
