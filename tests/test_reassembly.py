"""Tests for TCP reassembly, using synthetic conversations from pcap_builder."""
from __future__ import annotations

import gzip

import pytest

from fhir_dissector.reassembly import Exchange, TcpReassembler
from tests.pcap_builder import build_conversation, http_request, http_response, tcp_tuples

PATIENT = b'{"resourceType":"Patient","id":"1","name":[{"family":"Rossi"}]}' * 3
BUNDLE = b'{"resourceType":"Bundle","type":"searchset","total":0}'

EXCHANGES = [
    (http_request("GET", "/fhir/metadata"),
     http_response(200, {"Content-Type": "application/fhir+json"}, b'{"resourceType":"CapabilityStatement"}')),
    (http_request("POST", "/fhir/Patient", {"Content-Type": "application/fhir+json"}, PATIENT),
     http_response(201, {"Content-Type": "application/fhir+json", "Content-Encoding": "gzip"},
                   gzip.compress(PATIENT), chunked=True)),
    (http_request("GET", "/fhir/Patient?family=Rossi"),
     http_response(200, {"Content-Type": "application/fhir+json"}, BUNDLE, chunked=True, chunk_size=3)),
]


def run(packets, **kw) -> list[Exchange]:
    r = TcpReassembler(**kw)
    out: list[Exchange] = []
    for t in tcp_tuples(packets):
        out += r.process(*t)
    return out + r.flush()


def check(out: list[Exchange]) -> None:
    assert [(x.request.method, x.request.target, x.response.status) for x in out] == [
        ("GET", "/fhir/metadata", 200),
        ("POST", "/fhir/Patient", 201),
        ("GET", "/fhir/Patient?family=Rossi", 200),
    ]
    assert out[1].request.body == PATIENT and out[1].response.body == PATIENT
    assert out[2].response.body == BUNDLE
    for x in out:
        assert x.client[1] == 50000 and x.server[1] == 8080
        assert x.errors == [] and x.request.errors == [] and x.response.errors == []


def test_in_order() -> None:
    check(run(build_conversation(EXCHANGES)))


@pytest.mark.parametrize("seed", range(10))
def test_shuffled_segments(seed: int) -> None:
    check(run(build_conversation(EXCHANGES, shuffle=True, seed=seed)))


@pytest.mark.parametrize("seed", range(10))
def test_retransmissions_and_overlaps(seed: int) -> None:
    check(run(build_conversation(EXCHANGES, duplicate=True, seed=seed)))


@pytest.mark.parametrize("seed", range(5))
def test_shuffled_and_duplicated(seed: int) -> None:
    check(run(build_conversation(EXCHANGES, shuffle=True, duplicate=True, seed=seed, segment_size=13)))


def test_missing_handshake() -> None:
    check(run(build_conversation(EXCHANGES, handshake=False)))


def test_ipv6() -> None:
    out = run(build_conversation(EXCHANGES, ipv6=True))
    check(out)
    assert out[0].client[0] == "fd00::1"


def test_sequence_number_wraparound() -> None:
    check(run(build_conversation(EXCHANGES, client_isn=0xFFFFFF00, server_isn=0xFFFFFFF0, segment_size=17)))


def test_no_fin_flushed_at_end() -> None:
    check(run(build_conversation(EXCHANGES, fin=False)))


def test_request_without_response_emitted_on_close() -> None:
    out = run(build_conversation([(http_request("GET", "/fhir/Patient/9"), b"")]))
    assert len(out) == 1 and out[0].request.target == "/fhir/Patient/9" and out[0].response is None


def test_head_request_pairs_with_bodyless_response() -> None:
    conv = [(http_request("HEAD", "/fhir/Patient/1"), b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n"),
            (http_request("GET", "/fhir/Patient/1"), http_response(200, body=b"{}"))]
    out = run(build_conversation(conv))
    assert [(x.request.method, x.response.status, x.response.body) for x in out] == [
        ("HEAD", 200, b""), ("GET", 200, b"{}")]


def test_two_connections_kept_apart() -> None:
    a = build_conversation(EXCHANGES[:1], client=("10.0.0.1", 50000))
    b = build_conversation(EXCHANGES[2:], client=("10.0.0.1", 50001), start_ts=1_700_000_000.0005)
    merged = sorted(a + b, key=lambda p: float(p.time))
    out = run(merged)
    assert sorted((x.client[1], x.request.target) for x in out) == [
        (50000, "/fhir/metadata"), (50001, "/fhir/Patient?family=Rossi")]


def _drop_segment_in_second_request(pkts: list) -> list:
    """Remove one client data segment from the middle of the POST body (capture loss)."""
    victim = next(i for i, p in enumerate(pkts)
                  if p["TCP"].sport == 50000 and b"Patient" in bytes(p["TCP"].payload)
                  and not bytes(p["TCP"].payload).startswith(b"POST"))
    return pkts[:victim] + pkts[victim + 1:]


def test_gap_skipped_using_ack_and_pairing_recovers() -> None:
    pkts = _drop_segment_in_second_request(build_conversation(EXCHANGES, segment_size=20))
    out = run(pkts)
    # Exchange 1 intact; the broken POST is kept as a partial (truncated) request and is
    # still paired with its own 201 response; exchange 3 is paired correctly too.
    assert len(out) == 3
    assert out[0].request.target == "/fhir/metadata" and out[0].response.status == 200
    assert out[1].request.method == "POST" and out[1].request.target == "/fhir/Patient"
    assert out[1].request.truncated and "gap" in out[1].request.errors
    assert out[1].response.status == 201
    assert "response-without-request" not in out[1].errors
    assert out[-1].request.target == "/fhir/Patient?family=Rossi"
    assert out[-1].response.body == BUNDLE


def test_gap_without_ack_info_resolved_at_flush() -> None:
    pkts = _drop_segment_in_second_request(build_conversation(EXCHANGES, segment_size=20))
    r = TcpReassembler()
    out: list[Exchange] = []
    for t in tcp_tuples(pkts):
        out += r.process(*t[:8])  # no ack argument
    out += r.flush()
    assert any("gap" in x.request.errors for x in out if x.request)
    assert any(x.request is not None and x.request.target == "/fhir/Patient?family=Rossi" for x in out)


def test_rst_closes_connection() -> None:
    from scapy.layers.inet import TCP

    pkts = build_conversation(EXCHANGES[:1], fin=False)
    last = pkts[-1]
    rst = last.copy()
    rst[TCP].flags = "R"
    rst[TCP].remove_payload()
    rst.time = float(last.time) + 0.01
    r = TcpReassembler()
    out = []
    for t in tcp_tuples(pkts + [rst]):
        out += r.process(*t)
    assert len(out) == 1 and r.conns == {}


def test_gap_inside_response_keeps_pairing() -> None:
    """A hole inside a response body must not shift later responses to wrong requests."""
    big = b"<html>" + b"x" * 400 + b"</html>"
    conv = [(http_request("GET", "/"), http_response(200, {"Content-Type": "text/html"}, big, chunked=True,
                                                    chunk_size=100)),
            (http_request("GET", "/favicon.ico"), http_response(404, {"Content-Type": "application/json"}, b"{}"))]
    pkts = build_conversation(conv, segment_size=60)
    victim = next(i for i, p in enumerate(pkts)
                  if p["TCP"].sport == 8080 and bytes(p["TCP"].payload).startswith(b"x"))
    out = run(pkts[:victim] + pkts[victim + 1:])
    assert [(x.request.target, x.response.status) for x in out] == [("/", 200), ("/favicon.ico", 404)]
    assert out[0].response.truncated and "gap" in out[0].response.errors
    assert out[1].response.body == b"{}" and not out[1].response.truncated


def test_max_connections_evicts_least_recent() -> None:
    r = TcpReassembler(max_connections=3)
    for port in range(50000, 50005):  # 5 clients each send half a request, never finish
        r.process(1.0, "10.0.0.1", port, "10.0.0.2", 8080, "S", 100, b"")
        r.process(1.0, "10.0.0.1", port, "10.0.0.2", 8080, "PA", 101, b"GET /fhir/Patient/1 HTTP/1.1\r\n\r\n")
    assert len(r.conns) == 3 and r.evicted == 2
    assert {c.client[1] for c in r.conns.values()} == {50002, 50003, 50004}


def test_evicted_connection_reports_its_requests() -> None:
    r = TcpReassembler(max_connections=1)
    r.process(1.0, "10.0.0.1", 50000, "10.0.0.2", 8080, "PA", 1, b"GET /fhir/metadata HTTP/1.1\r\n\r\n")
    out = r.process(2.0, "10.0.0.3", 50001, "10.0.0.2", 8080, "PA", 1, b"GET /fhir/Patient HTTP/1.1\r\n\r\n")
    assert len(out) == 1 and out[0].request.target == "/fhir/metadata" and "evicted" in out[0].errors


def test_request_queue_is_bounded() -> None:
    from fhir_dissector.reassembly import MAX_QUEUED_REQUESTS

    r = TcpReassembler()
    data = http_request("GET", "/fhir/Patient/1") * (MAX_QUEUED_REQUESTS + 5)
    out = r.process(1.0, "10.0.0.1", 50000, "10.0.0.2", 8080, "PA", 1, data)
    assert len(out) == 5 and all("request-queue-overflow" in x.errors for x in out)
    conn = next(iter(r.conns.values()))
    assert len(conn.requests) == MAX_QUEUED_REQUESTS
