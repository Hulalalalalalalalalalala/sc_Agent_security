"""Low-Level Validated Workload/Service Locators, Bootstrap Seeds & Node Locator Watcher.

Placed in `lineage.common` (zero dependency on `audit`/`resilience`/`registry`) so both
`AgentCard` (`lineage.registry`) and `SignedDomainDescriptor` (`lineage.federation`) share
a single canonical locator implementation without circular package imports.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import re
import threading
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from lineage.identity.spiffe import IdentityError, SpiffeId

DEFAULT_ALLOWED_LOCATOR_CIDRS: Tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
)
MAX_BOOTSTRAP_SEEDS: int = 32

ALLOWED_TRANSPORTS: Tuple[str, ...] = ("mtls-tcp", "tls-tcp", "http-ro")
_STRICT_IPV4_RE = re.compile(r"^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$")


class LocatorError(Exception):
    """Raised when a workload or domain locator fails structural or CIDR validation."""


LocatorValidationError = LocatorError


def allowed_cidrs_from_env() -> Optional[Tuple[str, ...]]:
    """Return explicit `LCT_ALLOWED_LOCATOR_CIDRS` tuple if set, else `None` (RFC1918 default)."""
    env_val = os.environ.get("LCT_ALLOWED_LOCATOR_CIDRS", "").strip()
    if not env_val:
        return None
    items = tuple(s.strip() for s in env_val.split(",") if s.strip())
    if not items:
        return None
    parse_allowed_locator_cidrs(items)
    return items


def parse_allowed_locator_cidrs(
    spec: Optional[Iterable[str] | str] = None,
) -> Tuple[ipaddress.IPv4Network, ...]:
    """Parse CIDR allowlist (defaults strictly to RFC1918 or `LCT_ALLOWED_LOCATOR_CIDRS` env)."""
    if spec is None:
        env_val = os.environ.get("LCT_ALLOWED_LOCATOR_CIDRS", "").strip()
        raw_items: Sequence[str] = (
            [s.strip() for s in env_val.split(",") if s.strip()]
            if env_val
            else DEFAULT_ALLOWED_LOCATOR_CIDRS
        )
    elif isinstance(spec, str):
        raw_items = [s.strip() for s in spec.split(",") if s.strip()]
    else:
        raw_items = [str(s).strip() for s in spec if str(s).strip()]

    if not raw_items:
        raise LocatorError("Locator CIDR allowlist cannot be empty")

    networks: List[ipaddress.IPv4Network] = []
    for item in raw_items:
        try:
            net = ipaddress.IPv4Network(item, strict=False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as exc:
            raise LocatorError(f"Invalid locator allowlist CIDR {item!r}: {exc}") from exc
        if net not in networks:
            networks.append(net)
    return tuple(networks)


def validate_locator_host(
    host: str,
    allowed_cidrs: Optional[Iterable[str] | str] = None,
    *,
    allow_loopback: bool = False,
) -> str:
    """Validate an advertised IPv4 locator host against reserved ranges and allowed CIDRs."""
    if not isinstance(host, str):
        raise LocatorError(f"Locator host must be an IPv4 string, got {host!r}")
    s = host.strip()
    if not _STRICT_IPV4_RE.match(s):
        raise LocatorError(
            f"Invalid locator host {host!r}: must be strict dotted-quad IPv4 without leading zeros or hostname"
        )
    try:
        addr = ipaddress.IPv4Address(s)
    except ipaddress.AddressValueError as exc:
        raise LocatorError(f"Invalid IPv4 locator host {host!r}: {exc}") from exc

    nets = parse_allowed_locator_cidrs(allowed_cidrs)

    if addr.is_unspecified or str(addr) == "255.255.255.255":
        raise LocatorError(f"Unspecified or broadcast locator host {s!r} is forbidden")
    if addr.is_multicast:
        raise LocatorError(f"Multicast locator host {s!r} is forbidden")
    if addr.is_link_local:
        raise LocatorError(f"Link-local locator host {s!r} (169.254.0.0/16) is forbidden")
    if addr.is_loopback and not allow_loopback:
        raise LocatorError(f"Loopback locator host {s!r} (127.0.0.0/8) is forbidden")

    matched_nets = [net for net in nets if addr in net]
    if not matched_nets:
        cidr_str = ", ".join(str(n) for n in nets)
        raise LocatorError(
            f"Locator host {s!r} is outside allowed CIDRs [{cidr_str}]"
        )
    return str(addr)


@dataclass(frozen=True)
class ServiceLocator:
    """Cryptographically signed network locator for an LCT workload or domain service."""

    transport: str
    host: str
    port: int
    priority: int = 10
    spiffe_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.transport not in ALLOWED_TRANSPORTS:
            raise LocatorError(
                f"Unsupported locator transport {self.transport!r}; expected one of {ALLOWED_TRANSPORTS}"
            )
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not (1 <= self.port <= 65535):
            raise LocatorError(f"Invalid locator port {self.port!r}: expected int in [1, 65535]")
        if isinstance(self.priority, bool) or not isinstance(self.priority, int) or not (0 <= self.priority <= 10000):
            raise LocatorError(f"Invalid locator priority {self.priority!r}: expected int in [0, 10000]")
        if self.spiffe_id is not None:
            try:
                parsed = SpiffeId.parse(self.spiffe_id)
            except IdentityError as exc:
                raise LocatorError(f"Invalid locator spiffe_id {self.spiffe_id!r}: {exc}") from exc
            object.__setattr__(self, "spiffe_id", parsed.uri)

    @property
    def scheme(self) -> str:
        return "http" if self.transport == "http-ro" else "https"

    @property
    def origin_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def sort_key(self) -> Tuple[int, str, int, str]:
        return (self.priority, self.host, self.port, self.transport)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "transport": self.transport,
            "host": self.host,
            "port": self.port,
            "priority": self.priority,
        }
        if self.spiffe_id is not None:
            out["spiffe_id"] = self.spiffe_id
        return out

    @classmethod
    def create(
        cls,
        transport: str,
        host: str,
        port: int,
        priority: int = 10,
        spiffe_id: Optional[str] = None,
        allowed_cidrs: Optional[Iterable[str] | str] = None,
    ) -> "ServiceLocator":
        clean_host = validate_locator_host(host, allowed_cidrs=allowed_cidrs)
        return cls(
            transport=str(transport).strip(),
            host=clean_host,
            port=int(port) if not isinstance(port, bool) else -1,
            priority=int(priority) if not isinstance(priority, bool) else -1,
            spiffe_id=str(spiffe_id).strip() if spiffe_id else None,
        )

    @classmethod
    def from_dict(
        cls,
        raw: Mapping[str, Any],
        allowed_cidrs: Optional[Iterable[str] | str] = None,
    ) -> "ServiceLocator":
        if not isinstance(raw, Mapping):
            raise LocatorError("ServiceLocator must be a JSON object")
        raw_port = raw.get("port")
        raw_prio = raw.get("priority", 10)
        if isinstance(raw_port, bool) or not isinstance(raw_port, int):
            raise LocatorError(f"Invalid ServiceLocator port: {raw_port!r}")
        if isinstance(raw_prio, bool) or not isinstance(raw_prio, int):
            raise LocatorError(f"Invalid ServiceLocator priority: {raw_prio!r}")
        clean_host = validate_locator_host(str(raw.get("host", "")), allowed_cidrs=allowed_cidrs)
        spiffe_raw = raw.get("spiffe_id")
        return cls(
            transport=str(raw.get("transport", "")).strip(),
            host=clean_host,
            port=raw_port,
            priority=raw_prio,
            spiffe_id=str(spiffe_raw).strip() if spiffe_raw else None,
        )


def sort_and_dedup_locators(locators: Iterable[ServiceLocator]) -> Tuple[ServiceLocator, ...]:
    """Deduplicate by `(transport, host, port)` keeping lowest priority number, then sort."""
    best: Dict[Tuple[str, str, int], ServiceLocator] = {}
    for loc in locators:
        key = (loc.transport, loc.host, loc.port)
        existing = best.get(key)
        if existing is None or loc.priority < existing.priority:
            best[key] = loc
    return tuple(sorted(best.values(), key=lambda x: x.sort_key()))


def normalize_seed_endpoint(raw: str) -> str:
    """Normalize an untrusted seed string (`ip:port` or `http(s)://ip:port`)."""
    if not isinstance(raw, str) or not raw.strip():
        raise LocatorError("Empty seed endpoint")
    s = raw.strip().rstrip("/")
    if "://" in s:
        sp = urlsplit(s)
        if sp.scheme not in ("http", "https") or not sp.hostname or not sp.port:
            raise LocatorError(f"Invalid seed URL {raw!r}: expected [http(s)://]<IPv4>:<port>")
        if sp.username or sp.password or (sp.path and sp.path != "/") or sp.query or sp.fragment:
            raise LocatorError(f"Seed endpoint {raw!r} must not include path, query, or userinfo")
        if not _STRICT_IPV4_RE.match(sp.hostname):
            raise LocatorError(f"Seed host {sp.hostname!r} must be a strict IPv4 address")
        ipaddress.IPv4Address(sp.hostname)
        if not (1 <= int(sp.port) <= 65535):
            raise LocatorError(f"Seed port out of range: {sp.port}")
        return f"{sp.scheme.lower()}://{sp.hostname}:{sp.port}"

    if ":" not in s:
        raise LocatorError(f"Invalid seed {raw!r}: expected '<IPv4>:<port>'")
    host_part, port_part = s.rsplit(":", 1)
    if not _STRICT_IPV4_RE.match(host_part):
        raise LocatorError(f"Seed host {host_part!r} must be a strict IPv4 address")
    ipaddress.IPv4Address(host_part)
    try:
        port_num = int(port_part)
    except ValueError as exc:
        raise LocatorError(f"Invalid seed port in {raw!r}") from exc
    if not (1 <= port_num <= 65535):
        raise LocatorError(f"Seed port out of range: {port_num}")
    return f"{host_part}:{port_num}"


def seed_candidate_descriptor_urls(seed: str) -> List[str]:
    """Return candidate `/v1/federation/descriptors` URLs for a normalized seed."""
    norm = normalize_seed_endpoint(seed)
    if norm.startswith(("http://", "https://")):
        return [f"{norm}/v1/federation/descriptors"]
    return [f"http://{norm}/v1/federation/descriptors"]


class SeedEndpointStore:
    """Thread-safe untrusted bootstrap seed store backed by env + hot-reloaded ConfigMap dir."""

    def __init__(
        self,
        initial_seeds: Iterable[str] = (),
        static_seeds: Iterable[str] = (),
        watch_dir: Optional[str | Path] = None,
        seeds_dir: Optional[str | Path] = None,
        env_seeds_spec: Optional[str] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._static_seeds: List[str] = []
        eff_env = (
            env_seeds_spec
            if env_seeds_spec is not None
            else os.environ.get("LCT_BOOTSTRAP_SEEDS", "")
        )
        env_items = [
            s.strip()
            for s in eff_env.replace("\n", ",").split(",")
            if s.strip() and not s.strip().startswith("#")
        ]
        for s in (*env_items, *initial_seeds, *static_seeds):
            if str(s).strip():
                ns = normalize_seed_endpoint(str(s))
                if ns not in self._static_seeds and len(self._static_seeds) < MAX_BOOTSTRAP_SEEDS:
                    self._static_seeds.append(ns)
        eff_dir = seeds_dir if seeds_dir is not None else watch_dir
        self._watch_dir: Optional[Path] = Path(eff_dir) if eff_dir else None
        self._dir_seeds: List[str] = []
        self._dynamic_seeds: List[str] = []
        self._last_dir_snapshot: Optional[str] = None
        self.refresh_from_dir()

    def refresh_from_dir(self) -> bool:
        if self._watch_dir is None or not self._watch_dir.is_dir():
            return False
        chunks: List[str] = []
        parsed: List[str] = []
        for entry in sorted(self._watch_dir.iterdir(), key=lambda p: p.name):
            if entry.name.startswith(".") or not entry.is_file():
                continue
            try:
                txt = entry.read_text(encoding="utf-8")
            except OSError:
                continue
            chunks.append(f"{entry.name}:{txt}")
            for ln in txt.replace(",", "\n").splitlines():
                val = ln.strip()
                if not val or val.startswith("#"):
                    continue
                try:
                    ns = normalize_seed_endpoint(val)
                    if ns not in parsed and len(parsed) < MAX_BOOTSTRAP_SEEDS:
                        parsed.append(ns)
                except LocatorError:
                    continue
        snap = "\n".join(chunks)
        with self._lock:
            if snap == self._last_dir_snapshot:
                return False
            self._last_dir_snapshot = snap
            self._dir_seeds = parsed
            return True

    def add_dynamic_seed(self, seed: str) -> str:
        ns = normalize_seed_endpoint(seed)
        with self._lock:
            if ns in self._dynamic_seeds:
                self._dynamic_seeds.remove(ns)
            elif len(self._dynamic_seeds) >= MAX_BOOTSTRAP_SEEDS:
                self._dynamic_seeds.pop(0)
            self._dynamic_seeds.append(ns)
        return ns

    def remove_seed(self, seed: str) -> bool:
        ns = normalize_seed_endpoint(seed)
        removed = False
        with self._lock:
            if ns in self._static_seeds:
                self._static_seeds.remove(ns)
                removed = True
            if ns in self._dynamic_seeds:
                self._dynamic_seeds.remove(ns)
                removed = True
        return removed

    def list_seeds(self) -> List[str]:
        self.refresh_from_dir()
        with self._lock:
            merged: List[str] = []
            for s in (*self._static_seeds, *self._dir_seeds, *self._dynamic_seeds):
                if s not in merged:
                    merged.append(s)
                    if len(merged) >= MAX_BOOTSTRAP_SEEDS:
                        break
            return merged


@dataclass(frozen=True)
class NodeLocatorSnapshot:
    """Host-published IPv4 interface(s) + local NodePort table mounted from `lct-node-locator`."""

    epoch: int
    hosts: Tuple[Tuple[str, int], ...]
    ports: Dict[str, int]

    def build_service_locators(
        self,
        service_slot: str,
        transport: str,
        spiffe_id: Optional[str] = None,
        fallback_port: Optional[int] = None,
        allowed_cidrs: Optional[Iterable[str] | str] = None,
    ) -> Tuple[ServiceLocator, ...]:
        port = self.ports.get(service_slot, fallback_port)
        if port is None or port <= 0 or not self.hosts:
            return ()
        items = [
            ServiceLocator.create(
                transport=transport,
                host=h,
                port=int(port),
                priority=int(prio),
                spiffe_id=spiffe_id,
                allowed_cidrs=allowed_cidrs,
            )
            for h, prio in self.hosts
        ]
        return sort_and_dedup_locators(items)


class NodeLocatorWatcher:
    """Watches `/etc/lct-node-locator/locator.json` and triggers zero-restart re-signing on IP change."""

    def __init__(
        self,
        locator_file: Optional[str | Path] = None,
        poll_interval_sec: float = 1.0,
        allowed_cidrs: Optional[Iterable[str] | str] = None,
        fallback_ips_csv: str = "",
        fallback_ports_json: str = "",
        on_change: Optional[Callable[[NodeLocatorSnapshot], None]] = None,
    ) -> None:
        self._file = Path(locator_file) if locator_file else None
        self.poll_interval_sec = max(0.05, float(poll_interval_sec))
        self.allowed_cidrs = allowed_cidrs
        self._fallback_ips_csv = fallback_ips_csv.strip()
        self._fallback_ports_json = fallback_ports_json.strip()
        self._lock = threading.RLock()
        self._last_raw: Optional[str] = None
        self._snapshot: Optional[NodeLocatorSnapshot] = None
        self._callbacks: List[Callable[[NodeLocatorSnapshot], None]] = []
        if on_change is not None:
            self._callbacks.append(on_change)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.refresh_if_changed(notify=False)

    def _parse_snapshot(self, data: Mapping[str, Any]) -> Optional[NodeLocatorSnapshot]:
        raw_locs = data.get("locators") or []
        hosts: List[Tuple[str, int]] = []
        if isinstance(raw_locs, list):
            for idx, entry in enumerate(raw_locs):
                if isinstance(entry, str):
                    h = validate_locator_host(entry, allowed_cidrs=self.allowed_cidrs)
                    prio = 10 + idx * 10
                elif isinstance(entry, Mapping):
                    h = validate_locator_host(
                        str(entry.get("host", "")), allowed_cidrs=self.allowed_cidrs
                    )
                    prio = int(entry.get("priority", 10 + idx * 10))
                else:
                    continue
                if all(existing_h != h for existing_h, _ in hosts):
                    hosts.append((h, prio))
        if not hosts:
            return None
        hosts.sort(key=lambda item: (item[1], item[0]))
        raw_ports = data.get("ports") or {}
        ports: Dict[str, int] = {}
        if isinstance(raw_ports, Mapping):
            for k, v in raw_ports.items():
                if not isinstance(v, bool) and isinstance(v, (int, str)):
                    try:
                        ports[str(k)] = int(v)
                    except ValueError:
                        continue
        epoch = int(data.get("epoch", 1)) if not isinstance(data.get("epoch"), bool) else 1
        return NodeLocatorSnapshot(epoch=epoch, hosts=tuple(hosts), ports=ports)

    def _build_fallback_snapshot(self) -> Optional[NodeLocatorSnapshot]:
        if not self._fallback_ips_csv:
            return None
        hosts: List[Tuple[str, int]] = []
        for idx, part in enumerate(self._fallback_ips_csv.split(",")):
            s = part.strip()
            if not s:
                continue
            try:
                h = validate_locator_host(s, allowed_cidrs=self.allowed_cidrs)
                hosts.append((h, 10 + idx * 10))
            except LocatorError:
                continue
        if not hosts:
            return None
        ports: Dict[str, int] = {}
        if self._fallback_ports_json:
            try:
                parsed = json.loads(self._fallback_ports_json)
                if isinstance(parsed, Mapping):
                    ports = {str(k): int(v) for k, v in parsed.items()}
            except Exception:
                pass
        return NodeLocatorSnapshot(epoch=0, hosts=tuple(hosts), ports=ports)

    def current_snapshot(self) -> Optional[NodeLocatorSnapshot]:
        with self._lock:
            return self._snapshot

    def refresh_if_changed(self, notify: bool = True) -> bool:
        raw_content: Optional[str] = None
        if self._file is not None and self._file.is_file():
            try:
                raw_content = self._file.read_text(encoding="utf-8").strip()
            except OSError:
                raw_content = None

        new_snap: Optional[NodeLocatorSnapshot] = None
        if raw_content:
            with self._lock:
                if raw_content == self._last_raw and self._snapshot is not None:
                    return False
            try:
                parsed_json = json.loads(raw_content)
                if isinstance(parsed_json, Mapping):
                    new_snap = self._parse_snapshot(parsed_json)
            except Exception:
                return False
        else:
            new_snap = self._build_fallback_snapshot()

        if new_snap is None:
            return False

        with self._lock:
            if self._snapshot == new_snap:
                self._last_raw = raw_content
                return False
            self._last_raw = raw_content
            self._snapshot = new_snap
            cbs = list(self._callbacks)

        if notify:
            for cb in cbs:
                try:
                    cb(new_snap)
                except Exception:
                    pass
        return True

    def add_callback(self, cb: Callable[[NodeLocatorSnapshot], None]) -> None:
        with self._lock:
            self._callbacks.append(cb)

    def wait_for_locators(
        self, max_wait_sec: float = 12.0
    ) -> Optional[NodeLocatorSnapshot]:
        import time as _time

        deadline = _time.time() + max(0.0, float(max_wait_sec))
        while True:
            self.refresh_if_changed(notify=False)
            snap = self.current_snapshot()
            if snap is not None and snap.hosts:
                return snap
            if _time.time() >= deadline:
                return snap
            _time.sleep(min(0.25, self.poll_interval_sec))

    def start(self, poll_interval_sec: Optional[float] = None) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        eff_interval = (
            max(0.05, float(poll_interval_sec))
            if poll_interval_sec is not None
            else self.poll_interval_sec
        )
        self._stop.clear()

        def _loop() -> None:
            while not self._stop.is_set():
                try:
                    self.refresh_if_changed(notify=True)
                except Exception:
                    pass
                self._stop.wait(eff_interval)

        self._thread = threading.Thread(
            target=_loop, name="lct-node-locator-watcher", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
