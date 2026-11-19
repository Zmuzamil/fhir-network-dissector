"""Public entry point: :class:`FhirDissector` (plan §5.3).

Pipeline: TCP segment -> reassembly -> HTTP/1.1 -> FHIR detection/classification -> event.

The core is independent of scapy. Three ways to feed it:

* :meth:`FhirDissector.process_tcp` - already-decoded TCP segments (any framework);
* :meth:`FhirDissector.process_frame` - raw link-layer frames (fast path, used by the CLI);
* :meth:`FhirDissector.process_packet` - scapy packets (IPv4 and IPv6).
"""
from __future__ import annotations

import socket
import struct
from collections import Counter
from typing import Any, Optional

from fhir_dissector.body import summarize
from fhir_dissector.classifier import classify
from fhir_dissector.detector import detect
from fhir_dissector.events import build_event
from fhir_dissector.http_parser import DEFAULT_MAX_BODY
from fhir_dissector.reassembly import DEFAULT_MAX_CONNECTIONS, Endpoint, Exchange, TcpReassembler

# pcap link-layer types handled by decode_frame()
LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LOOP = 0, 1, 101, 108
LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2 = 113, 276
_RAW_IP = {LINKTYPE_RAW, 12, 14, 228, 229}  # bare IPv4/IPv6 (values differ per OS)
SUPPORTED_LINKTYPES = {LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_LOOP, LINKTYPE_LINUX_SLL,
                       LINKTYPE_LINUX_SLL2} | _RAW_IP
_TCP_FLAGS = ((0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"), (0x10, "A"), (0x20, "U"))

Segment = tuple[str, int, str, int, str, int, bytes, int, bool]


def _ip_offset(linktype: int, frame: bytes) -> Optional[int]:
    """Byte offset of the IP header inside a link-layer frame, or None if not IP."""
    if linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
        return 4  # 4-byte address family; the IP version nibble tells v4/v6
    if linktype in _RAW_IP:
        return 0
    if linktype == LINKTYPE_ETHERNET:
        off, etype = 14, struct.unpack_from("!H", frame, 12)[0]
        while etype in (0x8100, 0x88A8):  # VLAN tags
            etype = struct.unpack_from("!H", frame, off + 2)[0]
            off += 4
        return off if etype in (0x0800, 0x86DD) else None
    if linktype == LINKTYPE_LINUX_SLL:
        return 16 if struct.unpack_from("!H", frame, 14)[0] in (0x0800, 0x86DD) else None
    if linktype == LINKTYPE_LINUX_SLL2:
        return 20 if struct.unpack_from("!H", frame, 0)[0] in (0x0800, 0x86DD) else None
    return None


def decode_frame(linktype: int, frame: bytes) -> Optional[Segment]:
    """Decode a raw frame into ``(src, sport, dst, dport, flags, seq, payload, ack, truncated)``.

    Pure ``struct`` parsing (much faster than building scapy objects). Returns None for
    anything that is not an unfragmented IPv4/IPv6 TCP segment.
    """
    try:
        off = _ip_offset(linktype, frame)
        if off is None or len(frame) <= off:
            return None
        version = frame[off] >> 4
        if version == 4:
            ihl = (frame[off] & 0x0F) * 4
            total, frag = struct.unpack_from("!H2xH", frame, off + 2)
            if frame[off + 9] != 6 or frag & 0x3FFF:  # not TCP, or a fragment
                return None
            src = socket.inet_ntop(socket.AF_INET, frame[off + 12:off + 16])
            dst = socket.inet_ntop(socket.AF_INET, frame[off + 16:off + 20])
            tcp, end = off + ihl, off + total
        elif version == 6:
            plen = struct.unpack_from("!H", frame, off + 4)[0]
            nxt, tcp = frame[off + 6], off + 40
            while nxt in (0, 43, 60):  # hop-by-hop, routing, destination options
                nxt, tcp = frame[tcp], tcp + (frame[tcp + 1] + 1) * 8
            if nxt != 6:  # not TCP (or a fragment header)
                return None
            src = socket.inet_ntop(socket.AF_INET6, frame[off + 8:off + 24])
            dst = socket.inet_ntop(socket.AF_INET6, frame[off + 24:off + 40])
            end = off + 40 + plen
        else:
            return None
        sport, dport, seq, ack, doff, fl = struct.unpack_from("!HHIIBB", frame, tcp)
        flags = "".join(ch for bit, ch in _TCP_FLAGS if fl & bit)
        truncated = end > len(frame)
        return (src, sport, dst, dport, flags, seq, frame[tcp + (doff >> 4) * 4:end], ack, truncated)
    except (struct.error, IndexError, ValueError, OSError):
        return None


class FhirDissector:
    """Detect and classify HL7 FHIR exchanges in TCP traffic.

    Args:
        redact: remove patient data from events (search values, tokens, diagnostics).
        min_confidence: detection threshold (0..1).
        emit_non_fhir: also return events for non-FHIR HTTP exchanges (``is_fhir: false``).
        max_body: per-message stored body cap in bytes.
        idle_timeout: close connections idle for this many seconds (``None`` = never).
        max_connections: upper bound on tracked TCP connections (memory limit).
    """

    def __init__(self, redact: bool = True, min_confidence: float = 0.5,
                 emit_non_fhir: bool = False, max_body: int = DEFAULT_MAX_BODY,
                 idle_timeout: Optional[float] = 120.0,
                 max_connections: int = DEFAULT_MAX_CONNECTIONS) -> None:
        self.redact = redact
        self.min_confidence = min_confidence
        self.emit_non_fhir = emit_non_fhir
        self.reassembler = TcpReassembler(max_body=max_body, idle_timeout=idle_timeout,
                                          max_connections=max_connections)
        self.server_versions: dict[Endpoint, str] = {}
        self.stats: Counter[str] = Counter()
        self.by_interaction: Counter[str] = Counter()

    # ------------------------------------------------------------- inputs
    def process_tcp(self, ts: float, src: str, sport: int, dst: str, dport: int,
                    flags: str, seq: int, payload: bytes, ack: Optional[int] = None) -> list[dict]:
        """Feed one TCP segment; return the events it completed.

        ``flags`` uses scapy-style letters (``S``, ``A``, ``F``, ``R``, ``P``).
        ``ack`` (optional) enables immediate recovery from bytes the capture missed.
        """
        self.stats["tcp_packets"] += 1
        try:
            exchanges = self.reassembler.process(ts, src, sport, dst, dport, flags, seq,
                                                 payload or b"", ack)
        except Exception:  # fail soft: never crash on weird traffic
            self.stats["internal_errors"] += 1
            return []
        return self._events(exchanges)

    def process_frame(self, ts: float, linktype: int, frame: bytes) -> list[dict]:
        """Feed one raw link-layer frame (pcap ``linktype`` + bytes). Fast path."""
        self.stats["packets"] += 1
        seg = decode_frame(linktype, frame)
        if seg is None:
            return []
        src, sport, dst, dport, flags, seq, payload, ack, truncated = seg
        if truncated:
            self.stats["truncated_packets"] += 1
        return self.process_tcp(ts, src, sport, dst, dport, flags, seq, payload, ack)

    def process_packet(self, pkt: Any) -> list[dict]:
        """Feed one scapy packet (IPv4/IPv6 + TCP). Other packets are ignored."""
        self.stats["packets"] += 1
        try:
            from scapy.layers.inet import IP, TCP
            from scapy.layers.inet6 import IPv6

            if TCP not in pkt:
                return []
            if IP in pkt:
                ip = pkt[IP]
                declared = ip.len - ip.ihl * 4 if ip.len else None
            elif IPv6 in pkt:
                ip = pkt[IPv6]
                declared = ip.plen or None
            else:
                return []
            tcp = pkt[TCP]
            payload = bytes(tcp.payload)
            if declared is not None and len(bytes(ip.payload)) < declared:
                # Frame cut by the capture (snaplen): the missing bytes form a hole
                # that reassembly detects via ACKs and handles as a gap.
                self.stats["truncated_packets"] += 1
            ts = float(pkt.time)
            return self.process_tcp(ts, ip.src, int(tcp.sport), ip.dst, int(tcp.dport),
                                    str(tcp.flags), int(tcp.seq), payload, int(tcp.ack))
        except Exception:
            self.stats["internal_errors"] += 1
            return []

    def flush(self) -> list[dict]:
        """Close all open connections (end of PCAP / shutdown) and return remaining events."""
        return self._events(self.reassembler.flush())

    def expire_idle(self, now: float) -> list[dict]:
        """Close connections idle since before ``now - idle_timeout`` (live mode)."""
        return self._events(self.reassembler.expire(now))

    # ----------------------------------------------------------- analysis
    def analyze(self, ex: Exchange) -> dict[str, Any]:
        """Turn one exchange into an event dict (always, FHIR or not)."""
        req, resp = ex.request, ex.response
        req_ct = req.headers.get("content-type", "") if req else ""
        resp_ct = resp.headers.get("content-type", "") if resp else ""
        req_sum = summarize(req.body, req_ct, self.redact) if req else {}
        resp_sum = summarize(resp.body, resp_ct, self.redact) if resp else {}
        bundle_type = (req_sum.get("bundle") or {}).get("type")
        form = req.body if req and "x-www-form-urlencoded" in req_ct.lower() else None
        cls = classify(req.method or "", req.target or "/", bundle_type, form) if req else \
            classify("", "/")
        det = detect(req, resp, req_sum, resp_sum, self.min_confidence)
        if det.is_fhir and det.version:
            self.server_versions[ex.server] = det.version
        known_version = self.server_versions.get(ex.server) if det.is_fhir else None
        return build_event(ex, cls, det, req_sum, resp_sum, self.redact, known_version)

    def _events(self, exchanges: list[Exchange]) -> list[dict]:
        out: list[dict] = []
        for ex in exchanges:
            try:
                event = self.analyze(ex)
            except Exception:
                self.stats["internal_errors"] += 1
                continue
            self.stats["http_exchanges"] += 1
            if event["fhir"]["is_fhir"]:
                self.stats["fhir_events"] += 1
                self.by_interaction[event["fhir"]["interaction"]] += 1
            elif not self.emit_non_fhir:
                continue
            self.stats["events"] += 1
            out.append(event)
        return out

    @property
    def connections(self) -> int:
        """Number of TCP connections seen so far."""
        return self.reassembler.connections_seen
