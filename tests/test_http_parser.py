"""Unit tests for the incremental HTTP/1.1 parser."""
from __future__ import annotations

import gzip
import zlib

import pytest

from fhir_dissector.http_parser import HttpParser
from tests.pcap_builder import http_request, http_response

BODY = b'{"resourceType":"Patient","id":"1"}'


def feed_all(p: HttpParser, data: bytes) -> list:
    return p.feed(data, 1.0)


def test_request_without_body() -> None:
    p = HttpParser("request")
    (m,) = feed_all(p, http_request("GET", "/fhir/Patient/1", {"Accept": "application/fhir+json"}))
    assert (m.method, m.target, m.version) == ("GET", "/fhir/Patient/1", "HTTP/1.1")
    assert m.headers["accept"] == "application/fhir+json"
    assert m.body == b"" and m.errors == []


def test_request_with_content_length() -> None:
    p = HttpParser("request")
    (m,) = feed_all(p, http_request("POST", "/fhir/Patient", {"Content-Type": "application/fhir+json"}, BODY))
    assert m.body == BODY and m.body_size == len(BODY)


def test_response_content_length_and_empty_reason() -> None:
    p = HttpParser("response")
    raw = b"HTTP/1.1 200 \r\nContent-Length: %d\r\n\r\n" % len(BODY) + BODY
    (m,) = feed_all(p, raw)
    assert m.status == 200 and m.reason == "" and m.body == BODY


def test_duplicate_headers_joined() -> None:
    p = HttpParser("response")
    raw = b"HTTP/1.1 200 OK\r\nVary: Accept\r\nVary: Origin\r\nContent-Length: 0\r\n\r\n"
    (m,) = feed_all(p, raw)
    assert m.headers["vary"] == "Accept, Origin"


def test_chunked_split_at_every_byte_boundary() -> None:
    raw = http_response(200, {"Content-Type": "application/fhir+json"}, BODY, chunked=True, chunk_size=5)
    for i in range(len(raw) + 1):
        p = HttpParser("response")
        msgs = p.feed(raw[:i], 1.0) + p.feed(raw[i:], 2.0)
        assert len(msgs) == 1, f"split at {i}"
        assert msgs[0].body == BODY, f"split at {i}"
        assert msgs[0].errors == []


def test_chunked_byte_by_byte_with_extension_and_trailer() -> None:
    raw = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
           b"5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: yes\r\n\r\n")
    p = HttpParser("response")
    msgs = []
    for b in raw:
        msgs += p.feed(bytes([b]), 1.0)
    assert len(msgs) == 1 and msgs[0].body == b"hello world"


def test_gzip_body_decoded() -> None:
    comp = gzip.compress(BODY)
    raw = http_response(200, {"Content-Encoding": "gzip"}, comp, chunked=True)
    (m,) = HttpParser("response").feed(raw, 1.0)
    assert m.body == BODY and m.body_size == len(comp) and m.errors == []


@pytest.mark.parametrize("wbits", [zlib.MAX_WBITS, -zlib.MAX_WBITS])
def test_deflate_zlib_and_raw(wbits: int) -> None:
    c = zlib.compressobj(wbits=wbits)
    comp = c.compress(BODY) + c.flush()
    raw = http_response(200, {"Content-Encoding": "deflate"}, comp)
    (m,) = HttpParser("response").feed(raw, 1.0)
    assert m.body == BODY


def test_bad_gzip_keeps_raw_body_and_records_error() -> None:
    raw = http_response(200, {"Content-Encoding": "gzip"}, b"not gzip at all")
    (m,) = HttpParser("response").feed(raw, 1.0)
    assert m.body == b"not gzip at all" and "decompress-failed" in m.errors


def test_head_response_has_no_body() -> None:
    methods = ["HEAD", "GET"]  # one per response, like the connection's request queue
    p = HttpParser("response", request_method=lambda: methods.pop(0))
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n" + http_response(200, body=b"x")
    msgs = p.feed(raw, 1.0)
    assert len(msgs) == 2 and msgs[0].body == b"" and msgs[1].body == b"x"


@pytest.mark.parametrize("status", [204, 304])
def test_204_304_have_no_body(status: int) -> None:
    raw = f"HTTP/1.1 {status} X\r\n\r\n".encode() + http_response(200, body=b"next")
    msgs = HttpParser("response").feed(raw, 1.0)
    assert [m.status for m in msgs] == [status, 200] and msgs[1].body == b"next"


def test_1xx_not_emitted() -> None:
    raw = b"HTTP/1.1 100 Continue\r\n\r\n" + http_response(201, body=BODY)
    msgs = HttpParser("response").feed(raw, 1.0)
    assert [m.status for m in msgs] == [201] and msgs[0].body == BODY


def test_101_stops_parsing() -> None:
    p = HttpParser("response")
    msgs = p.feed(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\x05hello", 1.0)
    assert [m.status for m in msgs] == [101]
    assert p.feed(http_response(200, body=b"x"), 2.0) == []


def test_until_close_body() -> None:
    p = HttpParser("response")
    assert p.feed(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\npart1-", 1.0) == []
    assert p.feed(b"part2", 2.0) == []
    (m,) = p.close(3.0)
    assert m.body == b"part1-part2" and m.errors == [] and m.end_ts == 3.0


def test_two_pipelined_requests_in_one_buffer() -> None:
    raw = http_request("GET", "/a") + http_request("POST", "/b", body=b"xyz")
    msgs = HttpParser("request").feed(raw, 1.0)
    assert [(m.method, m.target, m.body) for m in msgs] == [("GET", "/a", b""), ("POST", "/b", b"xyz")]


def test_chunked_request() -> None:
    raw = (b"POST /fhir HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
           b"3\r\nabc\r\n0\r\n\r\n")
    (m,) = HttpParser("request").feed(raw, 1.0)
    assert m.body == b"abc"


def test_oversized_headers_then_resync() -> None:
    p = HttpParser("request", max_header=1024)
    huge = b"GET /x HTTP/1.1\r\nX-Big: " + b"a" * 5000 + b"\r\n\r\n"
    msgs = p.feed(huge + http_request("GET", "/ok"), 1.0)
    assert [m.target for m in msgs] == ["/ok"]
    assert "header-overflow" in msgs[0].errors


def test_garbage_input_does_not_crash_and_resyncs() -> None:
    p = HttpParser("request")
    msgs = p.feed(b"\x00\xff\x13garbage garbage\r\nmore junk\r\n\r\n" + http_request("GET", "/fhir/metadata"), 1.0)
    assert [m.target for m in msgs] == ["/fhir/metadata"]
    assert "bad-start-line" in msgs[0].errors
    assert p.close(2.0) == []


def test_random_garbage_never_raises() -> None:
    import random

    rng = random.Random(7)
    for kind in ("request", "response"):
        for _ in range(200):
            p = HttpParser(kind)
            for _ in range(5):
                p.feed(bytes(rng.randrange(256) for _ in range(rng.randrange(1, 200))), 1.0)
            p.close(2.0)


def test_body_limit_sets_truncated() -> None:
    p = HttpParser("response", max_body=10)
    (m,) = p.feed(http_response(200, body=b"x" * 100), 1.0)
    assert m.truncated and len(m.body) == 10 and m.body_size == 100


def test_incomplete_message_at_close_is_flagged() -> None:
    p = HttpParser("response")
    p.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nonly-some", 1.0)
    (m,) = p.close(2.0)
    assert m.truncated and "incomplete-message-at-close" in m.errors


def test_timestamps_first_and_last_byte() -> None:
    p = HttpParser("response")
    raw = http_response(200, body=b"abcdef")
    assert p.feed(raw[:10], 5.0) == []
    (m,) = p.feed(raw[10:], 6.0)
    assert (m.ts, m.end_ts) == (5.0, 6.0)


def test_reset_resyncs_mid_body() -> None:
    p = HttpParser("response")
    p.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nabc", 1.0)
    p.reset()
    msgs = p.feed(b"tail of lost body..." + http_response(404, body=b"nf"), 2.0)
    assert [m.status for m in msgs] == [404]
