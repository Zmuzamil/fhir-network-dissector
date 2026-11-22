"""Unit tests for the network-lab node program (netlab/fhir_node.py) and labctl helpers.

No Docker, no network: only configuration parsing, answer-key records and data generation.
"""
from __future__ import annotations

import json
import random
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "netlab"))
import fhir_node  # noqa: E402
import labctl  # noqa: E402

GOOD = """
[node]
ip   = 10.63.0.21
mac  = 02:63:00:00:00:21
seed = ehr
duration = 120

[flow:adt]
kind = ehr
interval = 8

[flow:secure]
kind = clinician
server = https://10.63.0.30/fhir/
format = xml
gzip = no
connection = per-request
"""


def test_parse_valid_config_with_defaults() -> None:
    n = fhir_node.parse_config(GOOD, default_name="ehr-file")
    assert (n.name, n.ip, n.mac, n.seed, n.duration) == ("ehr-file", "10.63.0.21", "02:63:00:00:00:21", "ehr", 120)
    assert n.server == "http://10.63.0.10:8080/fhir" and n.web_port is None
    adt, secure = n.flows
    assert (adt.name, adt.kind, adt.interval, adt.format, adt.gzip, adt.keep_alive, adt.encrypted) == \
        ("adt", "ehr", 8.0, "json", True, True, False)
    assert adt.server == n.server
    assert (secure.server, secure.format, secure.gzip, secure.keep_alive, secure.encrypted) == \
        ("https://10.63.0.30/fhir", "xml", False, False, True)


def test_parse_web_server_node() -> None:
    n = fhir_node.parse_config("[node]\nip = 10.63.0.20\n[server:web]\nport = 8000\n", "intranet")
    assert n.web_port == 8000 and n.flows == []


@pytest.mark.parametrize("text, message", [
    ("[flow:x]\nkind = ehr\n", "missing [node]"),
    ("[node]\n[flow:x]\nkind = radiology\n", "kind must be one of"),
    ("[node]\n[flow:x]\nkind = ehr\nformat = yaml\n", "format must be json or xml"),
    ("[node]\n[flow:x]\nkind = ehr\nconnection = pooled\n", "keep-alive or per-request"),
    ("[node]\nserver = ftp://x/fhir\n[flow:x]\nkind = ehr\n", "expected http(s)://"),
    ("[node]\n[flow:x]\nkind = ehr\ngzip = maybe\n", "expected yes/no"),
    ("[node]\n[flow:x]\nkind = ehr\ninterval = 0\n", "interval must be > 0"),
    ("[node]\n[flow:x]\nkind = ehr\ninterval = soon\n", "could not convert"),
    ("[node]\n[server:ftp]\n", "unknown server type"),
    ("[node]\n[other]\n", "unknown section"),
    ("[node]\nip = 10.63.0.40\n", "no [flow:...]"),
    ("[node\n", "File contains"),
])
def test_parse_invalid_configs(text: str, message: str) -> None:
    with pytest.raises(fhir_node.ConfigError, match=re.escape(message)):
        fhir_node.parse_config(text)


@pytest.mark.parametrize("scenario", sorted(p.name for p in (ROOT / "netlab" / "scenari").iterdir() if p.is_dir()))
def test_shipped_scenarios_are_valid(scenario: str) -> None:
    nodes = labctl.scenario_nodes(scenario)
    ips = [n["ip"] for n in nodes]
    macs = [n["mac"] for n in nodes]
    assert len(set(ips)) == len(ips) and len(set(macs)) == len(macs)
    assert all(ip.startswith("10.63.0.") for ip in ips)
    for n in nodes:
        if n["role"] != "proxy":  # the TLS proxy file is read by labctl, not by fhir_node
            cfg = fhir_node.load_config(ROOT / "netlab" / "scenari" / scenario / n["file"])
            assert cfg.ip == n["ip"] and cfg.mac == n["mac"]


def test_truth_record_strips_host_and_query() -> None:
    r = fhir_node.truth_record(1.5, "10.63.0.25", "clinician", "round", "GET",
                               "http://10.63.0.10:8080/fhir/Patient?family=Rossi&_count=5",
                               "search-type", "Patient", True, False, 200)
    assert r["path"] == "/fhir/Patient" and r["query"] is True and r["status"] == 200
    assert (r["expected_interaction"], r["expected_resource_type"], r["encrypted"]) == ("search-type", "Patient", False)
    web = fhir_node.truth_record(2.0, "10.63.0.28", "browser", "intranet", "GET", "http://10.63.0.20/",
                                 "read", "Patient", False, False, 200)
    assert web["expected_interaction"] is None and web["expected_resource_type"] is None and web["query"] is False
    err = fhir_node.truth_record(3.0, "10.63.0.29", "s", "f", "GET", "https://10.63.0.30/fhir/metadata",
                                 "capabilities", None, True, True, None, "ConnectTimeout")
    assert err["encrypted"] is True and err["status"] is None and err["error"] == "ConnectTimeout"
    json.dumps(r)  # serialisable


def test_truth_log_writes_jsonl(tmp_path: Path) -> None:
    log = fhir_node.TruthLog(tmp_path / "a.jsonl")
    log.write({"x": 1})
    log.write({"x": 2})
    log.close()
    assert [json.loads(line)["x"] for line in (tmp_path / "a.jsonl").read_text().splitlines()] == [1, 2]
    assert log.count == 2


def test_synthetic_data_is_deterministic_and_fake() -> None:
    a = fhir_node.Data(random.Random("seed-1")).patient()
    b = fhir_node.Data(random.Random("seed-1")).patient()
    c = fhir_node.Data(random.Random("seed-2")).patient()
    assert a == b and a != c
    assert a["telecom"][0]["value"].startswith("06 0")  # non-assignable phone range
    obs = fhir_node.Data(random.Random(1)).vital("Patient/1", "bp")
    assert obs["resourceType"] == "Observation" and len(obs["component"]) == 2


class _Resp:
    def __init__(self, body: object, location: str = "") -> None:
        self._body, self.headers = body, {"Location": location}

    def json(self) -> object:
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


def test_created_id_from_body_or_location() -> None:
    assert fhir_node.created_id(_Resp({"id": "42"})) == "42"
    assert fhir_node.created_id(_Resp(ValueError("xml"), "http://h/fhir/Patient/77/_history/1")) == "77"
    assert fhir_node.created_id(_Resp(ValueError("xml"), "")) is None


def test_labctl_writes_compose_for_scenario(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(labctl, "GENERATED", tmp_path / "compose.scenario.yml")
    monkeypatch.setattr(labctl, "RUN_DIR", tmp_path / ".run")
    nodes = labctl.scenario_nodes("general")
    labctl.write_compose("general", nodes, 60)
    services = json.loads((tmp_path / "compose.scenario.yml").read_text())["services"]
    assert services["ehr"]["networks"]["fhir"] == {"ipv4_address": "10.63.0.21", "mac_address": "02:63:00:00:00:21"}
    assert services["ehr"]["command"][-2:] == ["--duration", "60"]
    assert "--duration" not in services["intranet"]["command"]  # servers run until stopped
    assert services["tlsproxy"]["networks"]["fhir-back"]["ipv4_address"] == "10.63.1.30"
    assert "reverse_proxy 10.63.1.10:8080" in (tmp_path / ".run" / "Caddyfile").read_text()


def test_labctl_rejects_unknown_scenario() -> None:
    with pytest.raises(SystemExit, match="unknown scenario"):
        labctl.scenario_nodes("does-not-exist")
