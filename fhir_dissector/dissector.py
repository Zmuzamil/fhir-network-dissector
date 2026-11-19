"""Public entry point: :class:`FhirDissector` (plan §5.3).

Pipeline: TCP segment -> reassembly -> HTTP/1.1 -> FHIR detection/classification -> event.

The core is independent of scapy. Use :meth:`FhirDissector.process_tcp` to plug the
module into another framework; :meth:`FhirDissector.process_packet` is a convenience
wrapper for scapy packets (IPv4 and IPv6).
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Optional

from fhir_dissector.body import summarize
from fhir_dissector.classifier import classify
from fhir_dissector.detector import detect
from fhir_dissector.events import build_event
from fhir_dissector.http_parser import DEFAULT_MAX_BODY
from fhir_dissector.reassembly import Endpoint, Exchange, TcpReassembler


class FhirDissector:
    """Detect and classify HL7 FHIR exchanges in TCP traffic.

    Args:
        redact: remove patient data from events (search values, tokens, diagnostics).
        min_confidence: detection threshold (0..1).
        emit_non_fhir: also return events for non-FHIR HTTP exchanges (``is_fhir: false``).
        max_body: per-message stored body cap in bytes.
        idle_timeout: close connections idle for this many seconds (``None`` = never).
    """

    def __init__(self, redact: bool = True, min_confidence: float = 0.5,
                 emit_non_fhir: bool = False, max_body: int = DEFAULT_MAX_BODY,
                 idle_timeout: Optional[float] = 120.0) -> None:
        self.redact = redact
        self.min_confidence = min_confidence
        self.emit_non_fhir = emit_non_fhir
        self.reassembler = TcpReassembler(max_body=max_body, idle_timeout=idle_timeout)
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
