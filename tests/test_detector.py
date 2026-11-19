"""Unit tests for FHIR detection scoring, event building, and the public API."""
from __future__ import annotations

import json

import pytest

from fhir_dissector import FhirDissector
from fhir_dissector.body import summarize
from fhir_dissector.detector import WEIGHTS, detect, fhir_version_from_content_type
from fhir_dissector.http_parser import HttpMessage
from tests.pcap_builder import build_conversation, http_request, http_response, tcp_tuples


def req(target: str, headers: dict[str, str] | None = None, body: bytes = b"", method: str = "GET") -> HttpMessage:
    return HttpMessage(kind="request", method=method, target=target,
                       headers={k.lower(): v for k, v in (headers or {}).items()}, body=body)


def resp(status: int = 200, headers: dict[str, str] | None = None, body: bytes = b"") -> HttpMessage:
    return HttpMessage(kind="response", status=status,
                       headers={k.lower(): v for k, v in (headers or {}).items()}, body=body)


def run_detect(q: HttpMessage, r: HttpMessage | None):
    qs = summarize(q.body, q.headers.get("content-type", ""))
    rs = summarize(r.body, r.headers.get("content-type", "")) if r else {}
    return detect(q, r, qs, rs)


def test_fhir_json_read_all_signals() -> None:
    d = run_detect(req("/fhir/Patient/1", {"Accept": "application/fhir+json"}),
                   resp(200, {"Content-Type": "application/fhir+json"}, b'{"resourceType":"Patient"}'))
    assert d.is_fhir and d.confidence == 1.0
    assert d.signals == ["content-type", "accept", "resourceType-body", "path-resource", "path-fhir"]


@pytest.mark.parametrize("signal, q, r, score", [
    ("content-type", req("/x"), resp(200, {"Content-Type": "application/fhir+xml"}), 0.6),
    ("accept", req("/x", {"Accept": "application/fhir+json"}), resp(), 0.4),
    ("resourceType-body", req("/x"), resp(200, {"Content-Type": "application/json"}, b'{"resourceType":"X"}'), 0.5),
    ("xml-namespace", req("/x"), resp(200, {"Content-Type": "application/xml"}, b'<X xmlns="http://hl7.org/fhir"/>'), 0.5),
    ("format-param", req("/x?_format=json"), resp(), 0.3),
    ("path-resource", req("/x/Patient/1"), resp(), 0.3),
    ("path-metadata", req("/x/metadata"), resp(), 0.3),
    ("path-fhir", req("/fhir/x"), resp(), 0.2),
])
def test_each_signal_weight(signal, q, r, score) -> None:
    d = run_detect(q, r)
    assert d.signals == [signal] and d.confidence == score == WEIGHTS[signal]


@pytest.mark.parametrize("q, r", [
    (req("/"), resp(200, {"Content-Type": "text/html"}, b"<html><body>Home</body></html>")),
    (req("/favicon.ico"), resp(404, {"Content-Type": "application/json"}, b'{"status":404,"error":"Not Found"}')),
    (req("/api/users/1"), resp(200, {"Content-Type": "application/json"}, b'{"id":1,"name":"x"}')),
    (req("/fhir"), resp(200, {"Content-Type": "text/html"}, b"<html/>")),  # 0.2 < 0.5
])
def test_non_fhir_below_threshold(q, r) -> None:
    assert not run_detect(q, r).is_fhir


def test_score_capped_at_one_and_threshold() -> None:
    d = detect(req("/fhir/metadata?_format=json", {"Accept": "application/fhir+json"}),
               resp(200, {"Content-Type": "application/fhir+json"}),
               {}, {"format": "json", "resource_type": "CapabilityStatement"}, min_confidence=0.99)
    assert d.confidence == 1.0 and d.is_fhir


def test_request_only_and_version_sources() -> None:
    d = detect(req("/fhir/Patient/1", {"Accept": "application/fhir+json; fhirVersion=4.0"}), None, {}, {})
    assert d.is_fhir and d.confidence == pytest.approx(0.9)
    assert fhir_version_from_content_type("application/fhir+json; fhirVersion=4.0") == "4.0"
    assert detect(req("/fhir/metadata"), resp(), {}, {"fhir_version": "4.0.1"}).version == "4.0.1"


# ---------------------------------------------------------- public API / events
CONV = [
    (http_request("GET", "/fhir/metadata", {"Accept": "application/fhir+json"}),
     http_response(200, {"Content-Type": "application/fhir+json"},
                   b'{"resourceType":"CapabilityStatement","fhirVersion":"4.0.1"}')),
    (http_request("GET", "/fhir/Patient?family=Rossi&_count=5",
                  {"Accept": "application/fhir+json", "Authorization": "Bearer SECRET-TOKEN-123"}),
     http_response(200, {"Content-Type": "application/fhir+json"},
                   json.dumps({"resourceType": "Bundle", "type": "searchset", "total": 1, "entry": [
                       {"resource": {"resourceType": "Patient", "id": "1", "name": [{"family": "Rossi"}],
                                     "birthDate": "1980-04-12"}}]}).encode())),
    (http_request("GET", "/fhir/Patient/zzz"),
     http_response(404, {"Content-Type": "application/fhir+json"},
                   b'{"resourceType":"OperationOutcome","issue":[{"severity":"error","code":"not-found",'
                   b'"diagnostics":"Resource Patient/zzz (Rossi) is not known"}]}')),
    (http_request("GET", "/index.html"), http_response(200, {"Content-Type": "text/html"}, b"<html></html>")),
]


def dissect(**kw) -> list[dict]:
    d = FhirDissector(**kw)
    out: list[dict] = []
    for t in tcp_tuples(build_conversation(CONV)):
        out += d.process_tcp(*t)
    return out + d.flush()


def test_events_default_redacted() -> None:
    ev = dissect()
    assert [e["fhir"]["interaction"] for e in ev] == ["capabilities", "search-type", "read"]
    text = json.dumps(ev)
    for secret in ("Rossi", "1980", "SECRET-TOKEN", "diagnostics", "family=", "_count=5"):
        assert secret not in text
    s = ev[1]
    assert s["fhir"]["search_params"] == ["family", "_count"]
    assert s["request"]["path"] == "/fhir/Patient"
    assert s["request"]["auth"] == {"bearer_present": True, "scheme": "Bearer"}
    assert s["response"]["bundle"]["entry_types"] == {"Patient": 1}
    assert s["fhir"]["version"] == "4.0.1"  # learned from /metadata on this server
    assert ev[2]["response"]["outcome_issues"] == [{"severity": "error", "code": "not-found"}]
    assert ev[0]["flow"] == {"client": "10.0.0.1:50000", "server": "10.0.0.2:8080"}


def test_events_no_redact_and_all() -> None:
    ev = dissect(redact=False, emit_non_fhir=True)
    assert len(ev) == 4 and ev[3]["fhir"]["is_fhir"] is False
    assert ev[1]["fhir"]["search_params"] == ["family=Rossi", "_count=5"]
    assert ev[1]["request"]["path"] == "/fhir/Patient?family=Rossi&_count=5"
    assert "diagnostics" in ev[2]["response"]["outcome_issues"][0]
    assert "SECRET-TOKEN" not in json.dumps(ev)  # tokens are never stored


def test_min_confidence_threshold() -> None:
    assert dissect(min_confidence=1.01) == []


def test_process_packet_ipv6_scapy() -> None:
    d = FhirDissector()
    out: list[dict] = []
    for p in build_conversation(CONV[:1], ipv6=True):
        out += d.process_packet(p)
    out += d.flush()
    assert len(out) == 1 and out[0]["flow"]["server"] == "[fd00::2]:8080"


def test_process_packet_ignores_non_tcp() -> None:
    from scapy.layers.inet import IP, UDP
    from scapy.packet import Raw

    d = FhirDissector()
    assert d.process_packet(IP() / UDP() / Raw(b"GET / HTTP/1.1\r\n\r\n")) == []
    assert d.process_packet(Raw(b"\x00\x01garbage")) == []
