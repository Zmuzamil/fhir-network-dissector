"""Tests for the fast raw-frame path (decode_frame, classic PCAP reader, PCAPNG fallback)."""
from __future__ import annotations

from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import CookedLinux, Dot1Q, Ether, Loopback
from scapy.packet import Raw
from scapy.utils import wrpcapng

from fhir_dissector import FhirDissector
from fhir_dissector.cli import dissect_pcap, iter_pcap, iter_pcap_frames, main as cli_main
from fhir_dissector.dissector import decode_frame
from tests.pcap_builder import build_conversation, http_request, http_response, write_pcap

SEG = TCP(sport=50000, dport=8080, flags="PA", seq=123456, ack=654321) / Raw(b"GET /fhir/metadata HTTP/1.1\r\n\r\n")


@pytest.mark.parametrize("linktype, frame", [
    (1, Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / SEG),
    (1, Ether() / Dot1Q(vlan=7) / IP(src="10.0.0.1", dst="10.0.0.2") / SEG),
    (0, Loopback(type=24) / IPv6(src="::1", dst="::1") / SEG),
    (113, CookedLinux(proto=0x0800) / IP(src="10.0.0.1", dst="10.0.0.2") / SEG),
    (101, IP(src="10.0.0.1", dst="10.0.0.2") / SEG),
    (1, Ether() / IPv6(src="fd00::1", dst="fd00::2", nh=0) / Raw(b"\x06\x00" + b"\x00" * 6) / SEG),
], ids=["ethernet-ipv4", "vlan", "loopback-ipv6", "linux-sll", "raw-ip", "ipv6-ext-header"])
def test_decode_frame_matches_scapy(linktype: int, frame) -> None:
    raw = bytes(frame)
    src, sport, dst, dport, flags, seq, payload, ack, truncated = decode_frame(linktype, raw)
    ip = frame[IP] if IP in frame else frame[IPv6]
    assert (src, dst) == (ip.src, ip.dst)
    assert (sport, dport, seq, ack) == (50000, 8080, 123456, 654321)
    assert set(flags) == {"P", "A"} and payload == b"GET /fhir/metadata HTTP/1.1\r\n\r\n" and not truncated


@pytest.mark.parametrize("frame", [
    Ether() / IP() / UDP() / Raw(b"x"),                    # not TCP
    Ether() / IP(flags="MF") / SEG,                        # IPv4 fragment
    Ether(type=0x0806) / Raw(b"\x00" * 28),                # ARP
    Ether() / IP(),                                        # IP without TCP header
], ids=["udp", "fragment", "arp", "short"])
def test_decode_frame_ignores_non_tcp(frame) -> None:
    assert decode_frame(1, bytes(frame)) is None


def test_decode_frame_flags_truncation_and_garbage() -> None:
    raw = bytes(Ether() / IP() / SEG)
    assert decode_frame(1, raw[:-10])[-1] is True       # cut by snaplen
    for junk in (b"", b"\x00", b"\xff" * 13, b"\x45" * 60):
        decode_frame(1, junk)                           # never raises
        decode_frame(0, junk)


CONV = [(http_request("GET", "/fhir/Patient/1", {"Accept": "application/fhir+json"}),
         http_response(200, {"Content-Type": "application/fhir+json"}, b'{"resourceType":"Patient","id":"1"}'))]


def _events_scapy_path(pkts) -> list[dict]:
    d = FhirDissector()
    out = [e for p in pkts for e in d.process_packet(p)]
    return out + d.flush()


def test_fast_pcap_path_equals_scapy_path(tmp_path: Path) -> None:
    pkts = build_conversation(CONV * 3, shuffle=True, duplicate=True, seed=5)
    path = write_pcap(tmp_path / "x.pcap", pkts)
    assert iter_pcap_frames(path) is not None
    fast = dissect_pcap(path, FhirDissector())
    assert fast == _events_scapy_path(iter_pcap(path)) and len(fast) == 3  # same file, both decoders


def test_pcapng_falls_back_to_scapy(tmp_path: Path) -> None:
    pkts = build_conversation(CONV)
    path = tmp_path / "x.pcapng"
    wrpcapng(str(path), pkts)
    assert iter_pcap_frames(path) is None
    events = dissect_pcap(path, FhirDissector())
    assert [e["fhir"]["interaction"] for e in events] == ["read"]


def test_cli_new_options(tmp_path: Path) -> None:
    path = write_pcap(tmp_path / "x.pcap", build_conversation(CONV))
    out = tmp_path / "e.jsonl"
    assert cli_main(["pcap", str(path), "-o", str(out), "--max-body", "1000", "--idle-timeout", "0",
                     "--max-connections", "5"]) == 0
    assert len(out.read_text().splitlines()) == 1
