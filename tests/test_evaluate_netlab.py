"""Unit tests for the network-lab evaluation (lab/evaluate.py: match_netlab, evaluate_netlab)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from lab import evaluate
from tests.pcap_builder import build_conversation, http_request, http_response, write_pcap


def ev(ts: float, ip: str, method: str, path: str, status: int, is_fhir: bool = True,
       inter: str | None = "read", rtype: str | None = "Patient", port: int = 40000) -> dict:
    return {"ts": ts, "flow": {"client": f"{ip}:{port}", "server": "10.63.0.10:8080"}, "errors": [],
            "fhir": {"is_fhir": is_fhir, "confidence": 1.0 if is_fhir else 0.0,
                     "interaction": inter if is_fhir else "unknown", "resource_type": rtype if is_fhir else None},
            "request": {"method": method, "path": path}, "response": {"status": status}}


def exp(ts: float, ip: str, method: str, path: str, status: int | None, is_fhir: bool = True,
        inter: str | None = "read", rtype: str | None = "Patient", encrypted: bool = False) -> dict:
    return {"ts": ts, "client_ip": ip, "node": ip, "method": method, "path": path, "query": False,
            "expected_interaction": inter if is_fhir else None, "expected_resource_type": rtype if is_fhir else None,
            "is_fhir": is_fhir, "encrypted": encrypted, "status": status}


def test_client_ip_parsing() -> None:
    assert evaluate.client_ip(ev(0, "10.63.0.21", "GET", "/", 200)) == "10.63.0.21"
    e = ev(0, "x", "GET", "/", 200)
    e["flow"]["client"] = "[fd00::1]:51000"
    assert evaluate.client_ip(e) == "fd00::1"


def test_same_request_from_two_clients_is_matched_per_client() -> None:
    # two nodes read the same resource at almost the same time: each call must get its own event
    events = [ev(10.02, "10.63.0.25", "GET", "/fhir/Patient/1", 200),
              ev(10.01, "10.63.0.26", "GET", "/fhir/Patient/1", 200, inter="search-type")]
    expected = [exp(10.0, "10.63.0.25", "GET", "/fhir/Patient/1", 200),
                exp(10.0, "10.63.0.26", "GET", "/fhir/Patient/1", 200)]
    rep = evaluate.match_netlab(events, expected)
    assert rep["matched"] == 2 and rep["tp"] == 2
    bad = [r for r in rep["rows"] if not r["ok"]]
    assert len(bad) == 1 and bad[0]["client_ip"] == "10.63.0.26"  # wrong interaction stays with its client
    assert rep["interaction_accuracy"] == 0.5 and not rep["all_ok"]


def test_repeated_calls_match_closest_in_time_within_tolerance() -> None:
    events = [ev(t, "10.63.0.23", "POST", "/fhir/Observation", 201, inter="create", rtype="Observation")
              for t in (100.0, 103.0, 106.0)]
    expected = [exp(t, "10.63.0.23", "POST", "/fhir/Observation", 201, inter="create", rtype="Observation")
                for t in (105.9, 99.95, 103.1)]
    rep = evaluate.match_netlab(events, expected, tolerance=0.5)
    assert rep["all_ok"] and sorted(r["dt"] for r in rep["rows"]) == [0.05, 0.1, 0.1]


def test_event_outside_tolerance_is_a_miss_and_an_extra() -> None:
    rep = evaluate.match_netlab([ev(20.0, "10.63.0.21", "GET", "/fhir/Patient/1", 200)],
                                [exp(10.0, "10.63.0.21", "GET", "/fhir/Patient/1", 200)], tolerance=2.0)
    assert (rep["fn"], rep["fp"], rep["extra_fhir_events"]) == (1, 1, 1)


def test_status_and_method_must_match() -> None:
    events = [ev(1.0, "10.63.0.21", "GET", "/fhir/Encounter/5", 200, rtype="Encounter")]
    rep = evaluate.match_netlab(events, [exp(1.0, "10.63.0.21", "GET", "/fhir/Encounter/5", 410, rtype="Encounter")])
    assert rep["fn"] == 1 and not rep["rows"][0]["found"]


def test_encrypted_calls_are_reported_separately_not_as_misses() -> None:
    expected = [exp(1.0, "10.63.0.29", "GET", "/fhir/Patient/1", 200, encrypted=True),
                exp(2.0, "10.63.0.29", "GET", "/fhir/metadata", 200, inter="capabilities", rtype=None, encrypted=True),
                exp(3.0, "10.63.0.21", "GET", "/fhir/Patient/1", 200)]
    rep = evaluate.match_netlab([ev(3.0, "10.63.0.21", "GET", "/fhir/Patient/1", 200)], expected)
    assert (rep["encrypted_expected"], rep["plaintext_expected"], rep["encrypted_seen"]) == (2, 1, 0)
    assert (rep["tp"], rep["fn"], rep["recall"]) == (1, 0, 1.0) and rep["all_ok"]


def test_non_fhir_traffic_true_negative_and_false_positive() -> None:
    events = [ev(1.0, "10.63.0.28", "GET", "/news", 200, is_fhir=False),
              ev(2.0, "10.63.0.28", "GET", "/api/v1/beds", 200, is_fhir=True, inter="unknown", rtype=None)]
    expected = [exp(1.0, "10.63.0.28", "GET", "/news", 200, is_fhir=False),
                exp(2.0, "10.63.0.28", "GET", "/api/v1/beds", 200, is_fhir=False)]
    rep = evaluate.match_netlab(events, expected)
    assert (rep["tn"], rep["fp"], rep["precision"]) == (1, 1, 0.0)


def test_evaluate_netlab_end_to_end_two_clients(tmp_path: Path) -> None:
    body = json.dumps({"resourceType": "Patient", "id": "1"}).encode() * 40  # > 1 segment
    resp = http_response(200, {"Content-Type": "application/fhir+json"}, body)
    conv_a = build_conversation([(http_request("GET", "/fhir/Patient/1"), resp)] * 2,
                                client=("10.63.0.21", 41000), server=("10.63.0.10", 8080),
                                start_ts=1000.0, segment_size=1448)
    conv_b = build_conversation([(http_request("GET", "/fhir/Patient/1"), resp)],
                                client=("10.63.0.22", 42000), server=("10.63.0.10", 8080),
                                start_ts=1000.0005, segment_size=1448)
    pcap = write_pcap(tmp_path / "two.pcap", sorted(conv_a + conv_b, key=lambda p: float(p.time)))
    answer = tmp_path / "two_expected.jsonl"
    rows = [exp(1000.0, "10.63.0.21", "GET", "/fhir/Patient/1", 200),
            exp(1000.01, "10.63.0.21", "GET", "/fhir/Patient/1", 200),
            exp(1000.0, "10.63.0.22", "GET", "/fhir/Patient/1", 200)]
    answer.write_text("".join(json.dumps(r) + "\n" for r in rows))
    rep = evaluate.evaluate_netlab(pcap, answer)
    assert rep["all_ok"] and rep["tp"] == 3 and rep["connections"] == 2
    assert rep["max_frame"] <= 1514 and rep["frames_over_1514"] == 0
    assert rep["messages_multi_segment"] == 3 and rep["max_segments_per_message"] >= 2
    assert rep["clients"] == ["10.63.0.21", "10.63.0.22"]
    text = evaluate.format_netlab_report("two", rep)
    assert "RESULT: PASS" in text and "precision=100.00%" in text
    assert "TOTAL" in evaluate.format_netlab_summary({"two": rep})


def test_cli_network_lab_mode(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    conv = build_conversation([(http_request("GET", "/fhir/metadata"),
                                http_response(200, {"Content-Type": "application/fhir+json"},
                                              b'{"resourceType":"CapabilityStatement"}'))],
                              client=("10.63.0.21", 41000), server=("10.63.0.10", 8080), start_ts=50.0)
    pcap = write_pcap(tmp_path / "m.pcap", conv)
    answer = tmp_path / "m_expected.jsonl"
    answer.write_text(json.dumps(exp(50.0, "10.63.0.21", "GET", "/fhir/metadata", 200,
                                     inter="capabilities", rtype=None)) + "\n")
    assert evaluate.main(["--pcap", str(pcap), "--expected", str(answer)]) == 0
    assert "RESULT: PASS" in capsys.readouterr().out
