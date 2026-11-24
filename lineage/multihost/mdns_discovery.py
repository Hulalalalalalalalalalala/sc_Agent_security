"""Optional Zero-Dependency DNS-SD / mDNS Discovery (`_lct._tcp.local.`) for Same-LAN Seeds.

Security & Operational Design:
- Disabled by default (`--discover mdns` opt-in) because enterprise/campus Wi-Fi APs
  frequently filter link-local multicast (`224.0.0.251:5353`).
- Every mDNS packet is treated as 100% UNTRUSTED: discovered `ip:port` pairs are fed
  solely into `SeedEndpointStore` as candidate `/v1/federation/descriptors` transport
  hints. Returned descriptors still undergo full SHA-256 `TrustAnchorPinStore` matching
  and Domain Root CA signature verification before any key or locator is accepted.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from lineage.common.locators import LocatorError, validate_locator_host

MDNS_MULTICAST_GROUP = "224.0.0.251"
MDNS_PORT = 5353
LCT_MDNS_SERVICE = "_lct._tcp.local."
_QTYPE_TXT = 16
_QCLASS_IN = 1


def _encode_dns_name(name: str) -> bytes:
    parts = [p for p in name.strip(".").split(".") if p]
    out = bytearray()
    for label in parts:
        enc = label.encode("ascii")
        out.append(len(enc))
        out.extend(enc)
    out.append(0)
    return bytes(out)


def _decode_dns_name(buf: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    jumped = False
    orig_next = offset
    seen_ptrs: Set[int] = set()
    cur = offset
    while cur < len(buf):
        length = buf[cur]
        if length == 0:
            cur += 1
            if not jumped:
                orig_next = cur
            break
        if (length & 0xC0) == 0xC0:
            if cur + 1 >= len(buf):
                raise ValueError("Truncated DNS compression pointer")
            ptr = ((length & 0x3F) << 8) | buf[cur + 1]
            if ptr in seen_ptrs or ptr >= len(buf):
                raise ValueError("Invalid or cyclic DNS compression pointer")
            seen_ptrs.add(ptr)
            if not jumped:
                orig_next = cur + 2
                jumped = True
            cur = ptr
            continue
        cur += 1
        if cur + length > len(buf):
            raise ValueError("Truncated DNS label")
        labels.append(buf[cur : cur + length].decode("ascii", errors="replace"))
        cur += length
        if not jumped:
            orig_next = cur
    return ".".join(labels) + ".", orig_next


def build_mdns_query_packet() -> bytes:
    """Build standard DNS-SD query for `_lct._tcp.local.` TXT records."""
    header = struct.pack("!HHHHHH", 0, 0x0000, 1, 0, 0, 0)
    qname = _encode_dns_name(LCT_MDNS_SERVICE)
    question = qname + struct.pack("!HH", _QTYPE_TXT, _QCLASS_IN)
    return header + question


def build_mdns_announcement_packet(
    advertised_endpoints: Iterable[Tuple[str, str, int]],
    ttl_sec: int = 60,
) -> bytes:
    """Build DNS-SD TXT response advertising `(trust_domain, host_ip, ca_port)` entries."""
    items = list(advertised_endpoints)
    if not items:
        return b""
    txt_chunks = bytearray()
    for td, ip_str, port in items:
        entry_bytes = f"lct={td}@{ip_str}:{int(port)}".encode("ascii")
        if len(entry_bytes) <= 255:
            txt_chunks.append(len(entry_bytes))
            txt_chunks.extend(entry_bytes)
    if not txt_chunks:
        return b""
    header = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
    rname = _encode_dns_name(LCT_MDNS_SERVICE)
    rdata = bytes(txt_chunks)
    rr = rname + struct.pack("!HHIH", _QTYPE_TXT, _QCLASS_IN, int(ttl_sec), len(rdata)) + rdata
    return header + rr


def parse_mdns_seed_announcements(
    packet: bytes,
    allowed_cidrs: Optional[Iterable[str] | str] = None,
) -> List[Tuple[str, str]]:
    """Parse untrusted `(trust_domain, 'ip:port')` hints from an `_lct._tcp.local.` packet."""
    if len(packet) < 12:
        return []
    try:
        _, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    except struct.error:
        return []
    if (flags & 0x8000) == 0:
        # Query packet, not a response
        return []
    offset = 12
    try:
        for _ in range(qdcount):
            _, offset = _decode_dns_name(packet, offset)
            offset += 4
        total_rr = ancount + nscount + arcount
        discovered: List[Tuple[str, str]] = []
        for _ in range(total_rr):
            rname, offset = _decode_dns_name(packet, offset)
            if offset + 10 > len(packet):
                break
            rtype, _, _, rdlen = struct.unpack("!HHIH", packet[offset : offset + 10])
            offset += 10
            if offset + rdlen > len(packet):
                break
            rdata = packet[offset : offset + rdlen]
            offset += rdlen
            if rname.lower() != LCT_MDNS_SERVICE or rtype != _QTYPE_TXT:
                continue
            pos = 0
            while pos < len(rdata):
                tlen = rdata[pos]
                pos += 1
                if pos + tlen > len(rdata):
                    break
                txt = rdata[pos : pos + tlen].decode("ascii", errors="ignore")
                pos += tlen
                if not txt.startswith("lct=") or "@" not in txt or ":" not in txt:
                    continue
                body = txt[4:]
                td, host_port = body.split("@", 1)
                ip_part, port_part = host_port.rsplit(":", 1)
                clean_ip = validate_locator_host(ip_part, allowed_cidrs=allowed_cidrs)
                port_int = int(port_part)
                if 1 <= port_int <= 65535 and td:
                    pair = (td.strip().lower(), f"{clean_ip}:{port_int}")
                    if pair not in discovered:
                        discovered.append(pair)
        return discovered
    except (ValueError, LocatorError):
        return []


class MDNSSeedBroadcaster:
    """Optional background DNS-SD `_lct._tcp.local.` announcer & listener."""

    def __init__(
        self,
        local_announcements_provider: Callable[[], List[Tuple[str, str, int]]],
        on_seed_discovered: Callable[[str, str], None],
        allowed_cidrs: Optional[Iterable[str] | str] = None,
        bind_port: int = MDNS_PORT,
    ) -> None:
        self._provider = local_announcements_provider
        self._on_discovered = on_seed_discovered
        self._allowed_cidrs = allowed_cidrs
        self._bind_port = int(bind_port)
        self._stop = threading.Event()
        self._rx_thread: Optional[threading.Thread] = None
        self._tx_thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None

    def start(self, interval_sec: float = 5.0) -> bool:
        """Start best-effort UDP mDNS listener/announcer; returns False if socket unavailable."""
        if self._rx_thread is not None and self._rx_thread.is_alive():
            return True
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except OSError:
                    pass
            sock.bind(("", self._bind_port))
            mreq = struct.pack("4s4s", socket.inet_aton(MDNS_MULTICAST_GROUP), socket.inet_aton("0.0.0.0"))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(1.0)
        except OSError:
            return False

        self._sock = sock
        self._stop.clear()

        def _rx_loop() -> None:
            assert self._sock is not None
            while not self._stop.is_set():
                try:
                    pkt, _ = self._sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if len(pkt) >= 12:
                    _, flags, _, _, _, _ = struct.unpack("!HHHHHH", pkt[:12])
                    if (flags & 0x8000) == 0:
                        # Respond to incoming query
                        ann = build_mdns_announcement_packet(self._provider())
                        if ann:
                            try:
                                self._sock.sendto(ann, (MDNS_MULTICAST_GROUP, self._bind_port))
                            except OSError:
                                pass
                        continue
                for td, seed in parse_mdns_seed_announcements(
                    pkt, allowed_cidrs=self._allowed_cidrs
                ):
                    try:
                        self._on_discovered(td, seed)
                    except Exception:
                        pass

        def _tx_loop() -> None:
            assert self._sock is not None
            q_pkt = build_mdns_query_packet()
            while not self._stop.is_set():
                try:
                    self._sock.sendto(q_pkt, (MDNS_MULTICAST_GROUP, self._bind_port))
                    ann = build_mdns_announcement_packet(self._provider())
                    if ann:
                        self._sock.sendto(ann, (MDNS_MULTICAST_GROUP, self._bind_port))
                except OSError:
                    pass
                self._stop.wait(interval_sec)

        self._rx_thread = threading.Thread(target=_rx_loop, name="lct-mdns-rx", daemon=True)
        self._tx_thread = threading.Thread(target=_tx_loop, name="lct-mdns-tx", daemon=True)
        self._rx_thread.start()
        self._tx_thread.start()
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._rx_thread is not None:
            self._rx_thread.join(timeout=1.5)
            self._rx_thread = None
        if self._tx_thread is not None:
            self._tx_thread.join(timeout=1.5)
            self._tx_thread = None
