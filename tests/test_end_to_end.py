"""End-to-end tests: PCAP file -> CLI -> JSONL events, and the evaluator (plan §7).

* Synthetic: a PCAP with FHIR + non-FHIR exchanges on one keep-alive connection is
  written to a temp dir and processed through the real CLI code path.
* Real: if ``captures/lab.pcap`` + ``captures/expected.json`` exist (from the lab run),
  the evaluator must report a 100% match; otherwise the test is skipped.
"""
from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from fhir_dissector import FhirDissector
from fhir_dissector.cli import main as cli_main
from lab import evaluate
from tests.pcap_builder import build_conversation, http_request, http_response, tcp_tuples, write_pcap

ROOT = Path(__file__).resolve().parent.parent

FJ = {"Content-Type": "application/fhir+json;charset=UTF-8"}
ACC = {"Accept": "application/fhir+json"}


def _j(o) -> bytes:
    return json.dumps(o).encode()


PATIENT = {"resourceType": "Patient", "id": "42", "meta": {"versionId": "1"},
           "name": [{"family": "Rossi", "given": ["Mario"]}], "birthDate": "1980-04-12"}

# (request bytes, response bytes, expected entry)
SCENARIO = [
    (http_request("GET", "/fhir/metadata", ACC),
     http_response(200, {**FJ, "Content-Encoding": "gzip"},
                   gzip.compress(_j({"resourceType": "CapabilityStatement", "fhirVersion": "4.0.1"})),
                   chunked=True, chunk_size=10),
     ("capabilities", None, True)),
    (http_request("POST", "/fhir/Patient", {**ACC, **{"Content-Type": "application/fhir+json"}}, _j(PATIENT)),
     http_response(201, FJ, _j(PATIENT), reason="Created"), ("create", "Patient", True)),
    (http_request("GET", "/fhir/Patient/42", {"Accept": "application/fhir+xml"}),
     http_response(200, {"Content-Type": "application/fhir+xml;charset=UTF-8"},
                   b'<Patient xmlns="http://hl7.org/fhir"><id value="42"/><name><family value="Rossi"/></name></Patient>',
                   chunked=True), ("read", "Patient", True)),
    (http_request("GET", "/fhir/Patient?family=Rossi&birthdate=1980-04-12",
                  {**ACC, "Authorization": "Bearer eyJhbGciOi.SECRET.SIG"}),
     http_response(200, FJ, _j({"resourceType": "Bundle", "type": "searchset", "total": 1,
                                "entry": [{"resource": PATIENT}]})), ("search-type", "Patient", True)),
    (http_request("POST", "/fhir", {**ACC, "Content-Type": "application/fhir+json"},
                  _j({"resourceType": "Bundle", "type": "transaction", "entry": [
                      {"fullUrl": "urn:uuid:1", "resource": PATIENT, "request": {"method": "POST", "url": "Patient"}}]})),
     http_response(200, FJ, _j({"resourceType": "Bundle", "type": "transaction-response",
                                "entry": [{"response": {"status": "201 Created"}}]})),
     ("transaction", None, True)),
    (http_request("GET", "/fhir/Patient/42/$everything", ACC),
     http_response(200, FJ, _j({"resourceType": "Bundle", "type": "searchset", "total": 1,
                                "entry": [{"resource": PATIENT}]})), ("operation", "Patient", True)),
    (http_request("DELETE", "/fhir/Patient/42", ACC),
     http_response(204, {}, b"", reason="No Content"), ("delete", "Patient", True)),
    (http_request("GET", "/fhir/Patient/999", ACC),
     http_response(404, FJ, _j({"resourceType": "OperationOutcome", "issue": [
         {"severity": "error", "code": "not-found", "diagnostics": "Patient Rossi 999 unknown"}]}),
                   reason="Not Found"), ("read", "Patient", True)),
    (http_request("GET", "/"), http_response(200, {"Content-Type": "text/html"}, b"<html>home</html>"),
     (None, None, False)),
    (http_request("GET", "/static/app.js"),
     http_response(200, {"Content-Type": "application/javascript"}, b"console.log(1)"), (None, None, False)),
]


def _expected() -> list[dict]:
    out = []
    for i, (rq, rs, (inter, rtype, is_fhir)) in enumerate(SCENARIO, 1):
        line = rq.split(b"\r\n", 1)[0].decode().split(" ")
        status = int(rs.split(b" ", 2)[1])
        out.append({"index": i, "method": line[0], "path": line[1], "expected_interaction": inter,
                    "expected_resource_type": rtype, "is_fhir": is_fhir, "actual_status": status})
    return out


@pytest.fixture(params=[{}, {"shuffle": True, "duplicate": True, "seed": 3}, {"ipv6": True, "handshake": False}],
                ids=["clean", "shuffled+retransmitted", "ipv6-midstream"])
def synthetic_pcap(tmp_path: Path, request: pytest.FixtureRequest) -> Path:
    pkts = build_conversation([(rq, rs) for rq, rs, _ in SCENARIO], segment_size=48, **request.param)
    return write_pcap(tmp_path / "synthetic.pcap", pkts)


def _run_cli(pcap: Path, out: Path, *extra: str) -> list[dict]:
    assert cli_main(["pcap", str(pcap), "-o", str(out), *extra]) == 0
    return [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_synthetic_pcap_through_cli(synthetic_pcap: Path, tmp_path: Path) -> None:
    events = _run_cli(synthetic_pcap, tmp_path / "events.jsonl")
    fhir_expected = [s for s in SCENARIO if s[2][2]]
    assert [(e["fhir"]["interaction"], e["fhir"]["resource_type"]) for e in events] == \
        [(inter, rtype) for _, _, (inter, rtype, _) in fhir_expected]
    assert [e["response"]["status"] for e in events] == [200, 201, 200, 200, 200, 200, 204, 404]
    assert all(e["fhir"]["is_fhir"] and e["errors"] == [] for e in events)
    assert all(e["fhir"]["version"] == "4.0.1" for e in events)
    # Redaction: no search values, tokens, patient fields or diagnostics.
    text = (tmp_path / "events.jsonl").read_text(encoding="utf-8")
    for secret in ("Rossi", "Mario", "1980", "SECRET", "eyJ", "diagnostics", "birthdate="):
        assert secret not in text, secret
    search = events[3]
    assert search["fhir"]["search_params"] == ["family", "birthdate"]
    assert search["request"]["path"] == "/fhir/Patient"
    assert search["request"]["auth"]["bearer_present"] is True
    assert events[4]["request"]["bundle"]["request_methods"] == {"POST": 1}


def test_synthetic_all_flag_and_evaluator(synthetic_pcap: Path, tmp_path: Path) -> None:
    events = _run_cli(synthetic_pcap, tmp_path / "all.jsonl", "--all")
    assert len(events) == len(SCENARIO)
    assert [e["fhir"]["is_fhir"] for e in events][-2:] == [False, False]
    rep = evaluate.evaluate(events, _expected())
    assert rep["all_ok"], evaluate.print_report(rep)
    assert (rep["precision"], rep["recall"], rep["interaction_accuracy"]) == (1.0, 1.0, 1.0)


def test_evaluator_detects_mismatch() -> None:
    exp = _expected()
    events: list[dict] = []
    rep = evaluate.evaluate(events, exp)
    assert not rep["all_ok"] and rep["recall"] == 0.0
    wrong = dict(exp[0], expected_interaction="read")
    d = FhirDissector(emit_non_fhir=True)
    for t in tcp_tuples(build_conversation([(SCENARIO[0][0], SCENARIO[0][1])])):
        events += d.process_tcp(*t)
    events += d.flush()
    rep = evaluate.evaluate(events, [wrong])
    assert not rep["all_ok"] and rep["interaction_accuracy"] == 0.0


@pytest.mark.parametrize("name", ["general", "ward", "laboratory", "icu"])
def test_real_network_lab_capture(name: str) -> None:
    """The captures of the network lab (netlab/) must keep a 100 % match with their answer keys."""
    pcap = ROOT / "captures" / "netlab" / f"{name}.pcap"
    answer = ROOT / "captures" / "netlab" / f"{name}_expected.jsonl"
    if not (pcap.is_file() and answer.is_file()):
        pytest.skip(f"captures/netlab/{name}.pcap or its answer key is missing (run netlab first)")
    rep = evaluate.evaluate_netlab(pcap, answer)
    assert rep["all_ok"], [r for r in rep["rows"] if not r["ok"]][:5]
    assert (rep["precision"], rep["recall"], rep["interaction_accuracy"]) == (1.0, 1.0, 1.0)
    assert rep["max_frame"] <= 1514 and rep["encrypted_seen"] == 0
