"""Generic FHIR hospital node for the network lab (netlab).

One program, many systems: an .ini file says what the node is. A node has an identity
(name, IP, MAC, seed), a default FHIR server, and one or more *flows*: workflows repeated on
a timer (EHR, laboratory, bedside monitor, clinician, plain web browsing). A node can also be
a plain (non-FHIR) web server. Every request a client node makes is written to its answer
key (JSONL), with the HTTP status it really received.

    python fhir_node.py --node scenari/ward/ehr.ini --out results/ehr.jsonl --duration 300
    python fhir_node.py --node scenari/ward/ehr.ini --show        # print the parsed config

Only the standard library and requests. All data is synthetic and deterministic per seed.
"""
from __future__ import annotations

import argparse
import configparser
import json
import random
import re
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import date, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

FLOW_KINDS = ("ehr", "lab", "monitor", "clinician", "web")
FHIR_JSON = "application/fhir+json"
FHIR_XML = "application/fhir+xml"
STOP = threading.Event()


# ===================================================================== configuration
class ConfigError(ValueError):
    """Raised for an invalid node file."""


@dataclass
class FlowConfig:
    """One [flow:NAME] section."""

    name: str
    kind: str
    server: str
    interval: float = 10.0
    start_delay: float = 1.0
    format: str = "json"            # json | xml (Accept of reads and searches)
    gzip: bool = True               # Accept-Encoding gzip, or identity
    keep_alive: bool = True         # one persistent connection, or one connection per request

    @property
    def encrypted(self) -> bool:
        return self.server.startswith("https://")


@dataclass
class NodeConfig:
    """A whole node file."""

    name: str
    ip: str
    mac: str
    seed: str
    server: str
    duration: float
    flows: list[FlowConfig] = field(default_factory=list)
    web_port: Optional[int] = None   # set when the node is a plain web server ([server:web])


def _bool(value: str, key: str) -> bool:
    v = value.strip().lower()
    if v in ("yes", "true", "on", "1"):
        return True
    if v in ("no", "false", "off", "0"):
        return False
    raise ConfigError(f"{key}: expected yes/no, got {value!r}")


def _url(value: str, key: str) -> str:
    v = value.strip().rstrip("/")
    if not re.match(r"^https?://[^/\s]+", v):
        raise ConfigError(f"{key}: expected http(s)://host[:port]/path, got {value!r}")
    return v


def parse_config(text: str, default_name: str = "node") -> NodeConfig:
    """Parse the text of a node file (see the reference in netlab/README.md)."""
    cp = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=("#",))
    try:
        cp.read_string(text)
    except configparser.Error as exc:
        raise ConfigError(str(exc)) from exc
    if "node" not in cp:
        raise ConfigError("missing [node] section")
    n = cp["node"]
    name = n.get("name", default_name).strip()
    server = _url(n.get("server", "http://10.63.0.10:8080/fhir"), "node.server")
    try:
        duration = float(n.get("duration", "300"))
    except ValueError as exc:
        raise ConfigError(f"node.duration: {exc}") from exc
    node = NodeConfig(name=name, ip=n.get("ip", "").strip(), mac=n.get("mac", "").strip(),
                      seed=n.get("seed", name).strip(), server=server, duration=duration)
    for sec in cp.sections():
        o = cp[sec]
        if sec.startswith("flow:"):
            fname = sec.split(":", 1)[1].strip()
            kind = o.get("kind", "").strip()
            if kind not in FLOW_KINDS:
                raise ConfigError(f"[{sec}] kind must be one of {', '.join(FLOW_KINDS)}, got {kind!r}")
            fmt = o.get("format", "json").strip()
            if fmt not in ("json", "xml"):
                raise ConfigError(f"[{sec}] format must be json or xml, got {fmt!r}")
            conn = o.get("connection", "keep-alive").strip()
            if conn not in ("keep-alive", "per-request"):
                raise ConfigError(f"[{sec}] connection must be keep-alive or per-request, got {conn!r}")
            try:
                interval = float(o.get("interval", "10"))
                start_delay = float(o.get("start_delay", "1"))
            except ValueError as exc:
                raise ConfigError(f"[{sec}] {exc}") from exc
            if interval <= 0:
                raise ConfigError(f"[{sec}] interval must be > 0")
            node.flows.append(FlowConfig(
                name=fname, kind=kind, server=_url(o.get("server", server), f"[{sec}] server"),
                interval=interval, start_delay=start_delay, format=fmt,
                gzip=_bool(o.get("gzip", "yes"), f"[{sec}] gzip"), keep_alive=conn == "keep-alive"))
        elif sec.startswith("server:"):
            if sec != "server:web":
                raise ConfigError(f"unknown server type [{sec}] (only [server:web])")
            node.web_port = int(o.get("port", "80"))
        elif sec != "node":
            raise ConfigError(f"unknown section [{sec}]")
    if not node.flows and node.web_port is None:
        raise ConfigError("the node has no [flow:...] and no [server:web]")
    return node


def load_config(path: str | Path) -> NodeConfig:
    path = Path(path)
    return parse_config(path.read_text(encoding="utf-8"), default_name=path.stem)


# ===================================================================== answer key
class TruthLog:
    """Thread-safe JSONL writer: one line per request, flushed immediately."""

    def __init__(self, path: Optional[str | Path]) -> None:
        self.lock = threading.Lock()
        self.fh = open(path, "a", encoding="utf-8") if path else None
        self.count = 0

    def write(self, record: dict[str, Any]) -> None:
        with self.lock:
            self.count += 1
            if self.fh:
                self.fh.write(json.dumps(record, separators=(",", ":")) + "\n")
                self.fh.flush()

    def close(self) -> None:
        if self.fh:
            self.fh.close()


def truth_record(ts: float, client_ip: str, node: str, flow: str, method: str, url: str,
                 interaction: Optional[str], resource_type: Optional[str], is_fhir: bool,
                 encrypted: bool, status: Optional[int], error: str = "") -> dict[str, Any]:
    """One answer-key line. ``path`` is without host and without query string."""
    parts = urlsplit(url)
    rec = {"ts": round(ts, 6), "client_ip": client_ip, "node": node, "flow": flow, "method": method,
           "path": parts.path or "/", "query": bool(parts.query),
           "expected_interaction": interaction if is_fhir else None,
           "expected_resource_type": resource_type if is_fhir else None,
           "is_fhir": is_fhir, "encrypted": encrypted, "status": status}
    if error:
        rec["error"] = error
    return rec


# ===================================================================== synthetic data
FAMILY = ["Rossi", "Bianchi", "Ferrari", "Esposito", "Romano", "Colombo", "Ricci", "Marino", "Greco",
          "Bruno", "Gallo", "Conti", "De Luca", "Mancini", "Costa", "Giordano", "Rizzo", "Lombardi"]
GIVEN_M = ["Marco", "Luca", "Giuseppe", "Andrea", "Francesco", "Matteo", "Alessandro", "Davide"]
GIVEN_F = ["Giulia", "Francesca", "Chiara", "Sara", "Martina", "Elena", "Valentina", "Alessia"]
LAB_TESTS = [  # LOINC code, display, unit, low, high
    ("2345-7", "Glucose [Mass/volume] in Serum or Plasma", "mg/dL", 70, 140),
    ("718-7", "Hemoglobin [Mass/volume] in Blood", "g/dL", 11, 17),
    ("2160-0", "Creatinine [Mass/volume] in Serum or Plasma", "mg/dL", 0.6, 1.3),
    ("2823-3", "Potassium [Moles/volume] in Serum or Plasma", "mmol/L", 3.5, 5.1),
    ("2951-2", "Sodium [Moles/volume] in Serum or Plasma", "mmol/L", 135, 145),
]


class Data:
    """Deterministic fake data from one seed (no real persons; identifiers are fake)."""

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng

    def patient(self) -> dict[str, Any]:
        r = self.rng
        female = r.random() < 0.5
        born = date(1935, 1, 1) + timedelta(days=r.randrange(0, 365 * 70))
        return {"resourceType": "Patient",
                "identifier": [{"system": "urn:netlab:mrn", "value": f"MRN{r.randrange(10**6, 10**7)}"}],
                "name": [{"family": r.choice(FAMILY), "given": [r.choice(GIVEN_F if female else GIVEN_M)]}],
                "gender": "female" if female else "male", "birthDate": born.isoformat(),
                "telecom": [{"system": "phone", "value": f"06 0{r.randrange(100000, 999999)}"}]}

    def encounter(self, patient_ref: str) -> dict[str, Any]:
        return {"resourceType": "Encounter", "status": "in-progress",
                "class": {"system": "http://terminology.hl7.org/CodeSystem/v3-ActCode", "code": "IMP"},
                "subject": {"reference": patient_ref},
                "serviceProvider": {"display": self.rng.choice(["Medicina", "Chirurgia", "Cardiologia", "TI"])}}

    def service_request(self, patient_ref: str) -> dict[str, Any]:
        code, display, *_ = self.rng.choice(LAB_TESTS)
        return {"resourceType": "ServiceRequest", "status": "active", "intent": "order",
                "code": {"coding": [{"system": "http://loinc.org", "code": code, "display": display}]},
                "subject": {"reference": patient_ref}}

    def lab_observation(self, patient_ref: str, order_ref: Optional[str]) -> dict[str, Any]:
        code, display, unit, lo, hi = self.rng.choice(LAB_TESTS)
        value = round(self.rng.uniform(lo * 0.8, hi * 1.2), 1)
        obs = {"resourceType": "Observation", "status": "final",
               "category": [{"coding": [{"system": "http://terminology.hl7.org/CodeSystem/observation-category",
                                         "code": "laboratory"}]}],
               "code": {"coding": [{"system": "http://loinc.org", "code": code, "display": display}]},
               "subject": {"reference": patient_ref},
               "valueQuantity": {"value": value, "unit": unit, "system": "http://unitsofmeasure.org", "code": unit}}
        if order_ref:
            obs["basedOn"] = [{"reference": order_ref}]
        return obs

    def vital(self, patient_ref: str, which: str) -> dict[str, Any]:
        r = self.rng
        cat = [{"coding": [{"system": "http://terminology.hl7.org/CodeSystem/observation-category",
                            "code": "vital-signs"}]}]
        base = {"resourceType": "Observation", "status": "final", "category": cat,
                "subject": {"reference": patient_ref}}
        if which == "hr":
            return {**base, "code": {"coding": [{"system": "http://loinc.org", "code": "8867-4", "display": "Heart rate"}]},
                    "valueQuantity": {"value": r.randrange(55, 125), "unit": "/min", "system": "http://unitsofmeasure.org", "code": "/min"}}
        if which == "spo2":
            return {**base, "code": {"coding": [{"system": "http://loinc.org", "code": "59408-5", "display": "Oxygen saturation"}]},
                    "valueQuantity": {"value": r.randrange(88, 100), "unit": "%", "system": "http://unitsofmeasure.org", "code": "%"}}
        sys_, dia = r.randrange(95, 170), r.randrange(55, 100)
        return {**base, "code": {"coding": [{"system": "http://loinc.org", "code": "85354-9", "display": "Blood pressure panel"}]},
                "component": [
                    {"code": {"coding": [{"system": "http://loinc.org", "code": "8480-6"}]},
                     "valueQuantity": {"value": sys_, "unit": "mm[Hg]", "system": "http://unitsofmeasure.org", "code": "mm[Hg]"}},
                    {"code": {"coding": [{"system": "http://loinc.org", "code": "8462-4"}]},
                     "valueQuantity": {"value": dia, "unit": "mm[Hg]", "system": "http://unitsofmeasure.org", "code": "mm[Hg]"}}]}

    def report(self, patient_ref: str, order_ref: str, result_refs: list[str]) -> dict[str, Any]:
        return {"resourceType": "DiagnosticReport", "status": "final",
                "code": {"coding": [{"system": "http://loinc.org", "code": "11502-2", "display": "Laboratory report"}]},
                "subject": {"reference": patient_ref}, "basedOn": [{"reference": order_ref}],
                "result": [{"reference": ref} for ref in result_refs]}


# ===================================================================== FHIR client
def created_id(resp: Any) -> Optional[str]:
    """Server-assigned id of a created resource (JSON body or Location header)."""
    try:
        body = resp.json()
        if isinstance(body, dict) and body.get("id"):
            return str(body["id"])
    except ValueError:
        pass
    m = re.search(r"/[A-Za-z]+/([^/]+)/_history/", resp.headers.get("Location", "") + "/_history/")
    return m.group(1) if m else None


class Client:
    """HTTP client of one flow: session, headers and answer-key logging."""

    def __init__(self, node: NodeConfig, flow: FlowConfig, truth: TruthLog) -> None:
        import requests

        self.node, self.flow, self.truth = node, flow, truth
        self.session = requests.Session()
        self.session.verify = False  # self-signed certificate of the TLS proxy
        self.session.headers["User-Agent"] = f"netlab-{node.name}/{flow.name}"
        self.session.headers["Accept-Encoding"] = "gzip, deflate" if flow.gzip else "identity"
        if not flow.keep_alive:
            self.session.headers["Connection"] = "close"  # server closes: next call opens a new connection
        if flow.encrypted:
            import urllib3

            urllib3.disable_warnings()

    def request(self, method: str, url: str, *, interaction: Optional[str], resource_type: Optional[str],
                is_fhir: bool = True, accept: Optional[str] = None, json_body: Any = None,
                form: Optional[str] = None) -> Any:
        """Send one request (no redirects) and log it in the answer key."""
        import requests

        if not url.startswith("http"):
            url = f"{self.flow.server}/{url}" if url else self.flow.server
        headers: dict[str, str] = {}
        if is_fhir:
            headers["Accept"] = accept or FHIR_JSON
        data = None
        if json_body is not None:
            data, headers["Content-Type"] = json.dumps(json_body), FHIR_JSON
        elif form is not None:
            data, headers["Content-Type"] = form, "application/x-www-form-urlencoded"
        ts = time.time()
        status, err, resp = None, "", None
        try:
            resp = self.session.request(method, url, headers=headers, data=data, timeout=60,
                                        allow_redirects=False)
            status = resp.status_code
            sent = resp.request.url or url
        except requests.RequestException as exc:
            err, sent = type(exc).__name__, url
        self.truth.write(truth_record(ts, self.node.ip, self.node.name, self.flow.name, method, sent,
                                      interaction, resource_type, is_fhir, self.flow.encrypted, status, err))
        print(f"[{self.flow.name}] {method} {urlsplit(sent).path} -> {status or err}", flush=True)
        return resp

    def read_accept(self) -> str:
        return FHIR_XML if self.flow.format == "xml" else FHIR_JSON


# ===================================================================== workflows
class Workflow:
    """State shared by the rounds of one flow."""

    def __init__(self, client: Client, rng: random.Random) -> None:
        self.c, self.rng, self.data = client, rng, Data(rng)
        self.patients: list[str] = []      # patient ids created or found by this flow
        self.deleted: list[tuple[str, str]] = []
        self.pending: list[tuple[float, str, str]] = []  # lab: (due, patient id, order id)

    # -- helpers --------------------------------------------------------------
    def create(self, rtype: str, body: dict[str, Any]) -> Optional[str]:
        r = self.c.request("POST", rtype, interaction="create", resource_type=rtype, json_body=body)
        return created_id(r) if r is not None and r.status_code in (200, 201) else None

    def ensure_patients(self, n: int) -> None:
        while len(self.patients) < n and not STOP.is_set():
            pid = self.create("Patient", self.data.patient())
            if pid is None:
                return
            self.patients.append(pid)

    def some_patient(self) -> Optional[str]:
        return self.rng.choice(self.patients) if self.patients else None

    # -- EHR / ADT system -----------------------------------------------------
    def round_ehr(self) -> None:
        c, rng = self.c, self.rng
        if rng.random() < 0.4:  # admission as one transaction: Patient + Encounter
            p_urn = f"urn:uuid:{uuid.UUID(int=rng.getrandbits(128))}"
            bundle = {"resourceType": "Bundle", "type": "transaction", "entry": [
                {"fullUrl": p_urn, "resource": self.data.patient(), "request": {"method": "POST", "url": "Patient"}},
                {"resource": self.data.encounter(p_urn), "request": {"method": "POST", "url": "Encounter"}}]}
            r = c.request("POST", "", interaction="transaction", resource_type=None, json_body=bundle)
            if r is not None and r.status_code == 200:
                try:
                    loc = r.json()["entry"][0]["response"]["location"]
                    self.patients.append(loc.split("/")[1])
                except (ValueError, KeyError, IndexError):
                    pass
        else:  # admission as two creates
            pid = self.create("Patient", self.data.patient())
            if pid:
                self.patients.append(pid)
                self.create("Encounter", self.data.encounter(f"Patient/{pid}"))
        family = rng.choice(FAMILY)
        c.request("GET", f"Patient?family={family}&_count=10", interaction="search-type",
                  resource_type="Patient", accept=c.read_accept())
        pid = self.some_patient()
        if not pid:
            return
        c.request("GET", f"Patient/{pid}", interaction="read", resource_type="Patient", accept=c.read_accept())
        if rng.random() < 0.5:  # update the demographics, then look at the history
            body = self.data.patient()
            body["id"] = pid
            c.request("PUT", f"Patient/{pid}", interaction="update", resource_type="Patient", json_body=body)
            if rng.random() < 0.5:
                c.request("GET", f"Patient/{pid}/_history", interaction="history-instance", resource_type="Patient")
                c.request("GET", f"Patient/{pid}/_history/1", interaction="vread", resource_type="Patient")
        if rng.random() < 0.1:  # cancel an encounter, then try to read it (410 Gone)
            eid = self.create("Encounter", self.data.encounter(f"Patient/{pid}"))
            if eid:
                c.request("DELETE", f"Encounter/{eid}", interaction="delete", resource_type="Encounter")
                c.request("GET", f"Encounter/{eid}", interaction="read", resource_type="Encounter")
        if rng.random() < 0.1:  # a stale link: unknown patient (404)
            c.request("GET", f"Patient/x-{rng.randrange(10**6)}", interaction="read", resource_type="Patient")

    # -- laboratory information system ----------------------------------------
    def round_lab(self) -> None:
        c, rng = self.c, self.rng
        now = time.time()
        due = [p for p in self.pending if p[0] <= now]
        self.pending = [p for p in self.pending if p[0] > now]
        for _, pid, oid in due:  # results for orders received earlier
            refs = []
            for _ in range(rng.randrange(2, 5)):
                obs = self.create("Observation", self.data.lab_observation(f"Patient/{pid}", f"ServiceRequest/{oid}"))
                if obs:
                    refs.append(f"Observation/{obs}")
            self.create("DiagnosticReport", self.data.report(f"Patient/{pid}", f"ServiceRequest/{oid}", refs))
        self.ensure_patients(3)
        pid = self.some_patient()
        if not pid:
            return
        oid = self.create("ServiceRequest", self.data.service_request(f"Patient/{pid}"))  # order entry
        c.request("GET", "ServiceRequest?status=active&_count=20", interaction="search-type",
                  resource_type="ServiceRequest", accept=c.read_accept())
        if oid:
            self.pending.append((now + rng.uniform(3, 8), pid, oid))
        if rng.random() < 0.25:  # worklist check as one batch
            batch = {"resourceType": "Bundle", "type": "batch", "entry": [
                {"request": {"method": "GET", "url": f"Patient/{pid}"}},
                {"request": {"method": "GET", "url": f"ServiceRequest?subject=Patient/{pid}"}},
                {"request": {"method": "GET", "url": f"DiagnosticReport?subject=Patient/{pid}&_count=5"}}]}
            c.request("POST", "", interaction="batch", resource_type=None, json_body=batch)

    # -- bedside monitor gateway ------------------------------------------------
    def round_monitor(self) -> None:
        c, rng = self.c, self.rng
        self.ensure_patients(3)
        if not self.patients:
            return
        vitals = ("hr", "spo2", "bp")
        if rng.random() < 0.2:  # store-and-forward: all beds in one batch
            entries = [{"resource": self.data.vital(f"Patient/{pid}", v), "request": {"method": "POST", "url": "Observation"}}
                       for pid in self.patients for v in vitals]
            c.request("POST", "", interaction="batch", resource_type=None,
                      json_body={"resourceType": "Bundle", "type": "batch", "entry": entries})
            return
        for pid in self.patients:
            for v in vitals:
                self.create("Observation", self.data.vital(f"Patient/{pid}", v))

    # -- clinician workstation --------------------------------------------------
    def round_clinician(self) -> None:
        c, rng = self.c, self.rng
        if not self.patients:  # find some patients on the ward
            r = c.request("GET", "Patient?_count=20&_sort=-_lastUpdated", interaction="search-type",
                          resource_type="Patient")
            try:
                self.patients = [e["resource"]["id"] for e in r.json().get("entry", [])][:10]
            except (AttributeError, ValueError, KeyError, TypeError):
                pass
            if not self.patients:
                self.ensure_patients(2)
        pid = self.some_patient()
        gender = rng.choice(["female", "male"])
        c.request("GET", f"Patient?gender={gender}&birthdate=ge{rng.randrange(1940, 1990)}-01-01&_count=5",
                  interaction="search-type", resource_type="Patient", accept=c.read_accept())
        if not pid:
            return
        c.request("GET", f"Patient/{pid}", interaction="read", resource_type="Patient", accept=FHIR_XML)
        c.request("GET", f"Observation?patient={pid}&category=vital-signs&_sort=-date&_count=10",
                  interaction="search-type", resource_type="Observation", accept=c.read_accept())
        if rng.random() < 0.5:
            c.request("GET", f"Patient/{pid}/Observation?_count=5", interaction="search-compartment",
                      resource_type="Observation")
        if rng.random() < 0.3:
            c.request("GET", f"Patient/{pid}/$everything", interaction="operation", resource_type="Patient")
        if rng.random() < 0.4:
            c.request("POST", "Patient/_search", interaction="search-type", resource_type="Patient",
                      form=f"family={rng.choice(FAMILY)}&_count=5")
        if rng.random() < 0.3:
            c.request("GET", f"Encounter?subject=Patient/{pid}&status=in-progress", interaction="search-type",
                      resource_type="Encounter")

    # -- non-FHIR browsing (negative traffic) -------------------------------------
    def round_web(self) -> None:
        for page in self.rng.sample(WEB_PAGES, k=self.rng.randrange(2, 5)):
            self.c.request("GET", f"{self.c.flow.server}{page}", interaction=None, resource_type=None, is_fhir=False)


class FlowRunner(threading.Thread):
    """Runs one flow: a round, then a pause of interval +-20%, until the deadline."""

    def __init__(self, node: NodeConfig, flow: FlowConfig, truth: TruthLog, deadline: float) -> None:
        super().__init__(daemon=True, name=flow.name)
        self.node, self.flow, self.deadline = node, flow, deadline
        self.rng = random.Random(f"{node.seed}/{flow.name}")
        self.wf = Workflow(Client(node, flow, truth), self.rng)

    def run(self) -> None:
        step = getattr(self.wf, f"round_{self.flow.kind}")
        STOP.wait(self.flow.start_delay + self.rng.uniform(0, 1))
        while not STOP.is_set() and time.time() < self.deadline:
            try:
                step()
            except Exception as exc:  # a failed round must not stop the node
                print(f"[{self.flow.name}] round failed: {exc!r}", flush=True)
            STOP.wait(min(self.flow.interval * self.rng.uniform(0.8, 1.2), max(0.0, self.deadline - time.time())))


# ===================================================================== web server (non-FHIR)
WEB_PAGES = ["/", "/news", "/static/app.js", "/static/style.css", "/api/v1/beds?ward=3",
             "/api/v1/menu?day=today", "/api/v1/staff/on-call", "/favicon.ico"]


class WebHandler(BaseHTTPRequestHandler):
    """Hospital intranet: HTML pages, static files and a small JSON API (not FHIR)."""

    protocol_version = "HTTP/1.1"
    server_version = "IntranetHTTP/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print("[web] " + fmt % args, flush=True)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        rng = random.Random(path)
        if path == "/":
            body, ctype = b"<!doctype html><html><head><title>Intranet</title></head><body><h1>Ospedale Lab</h1>" \
                          + b"<p>News, menu, on-call staff.</p>" * 20 + b"</body></html>", "text/html; charset=utf-8"
        elif path == "/news":
            body = ("<html><body>" + "".join(f"<article><h2>Avviso {i}</h2><p>{'Testo di prova. ' * 40}</p></article>"
                                             for i in range(12)) + "</body></html>").encode()
            ctype = "text/html; charset=utf-8"
        elif path == "/static/app.js":
            body, ctype = b"function f(n){return n*2}\n" * 300, "application/javascript"
        elif path == "/static/style.css":
            body, ctype = b"body{font-family:sans-serif;margin:0}\n" * 200, "text/css"
        elif path == "/api/v1/beds":
            body = json.dumps({"ward": 3, "beds": [{"bed": i, "free": rng.random() < 0.3} for i in range(1, 25)]}).encode()
            ctype = "application/json"
        elif path == "/api/v1/menu":
            body, ctype = json.dumps({"day": "today", "items": ["pasta", "pesce", "frutta"]}).encode(), "application/json"
        elif path == "/api/v1/staff/on-call":
            body = json.dumps({"on_call": [{"role": "medico", "ext": 4000 + i} for i in range(6)]}).encode()
            ctype = "application/json"
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "10")
            self.end_headers()
            self.wfile.write(b"not found\n")
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ===================================================================== main
def run_node(node: NodeConfig, out: Optional[str], duration: Optional[float]) -> int:
    duration = node.duration if duration is None else duration
    deadline = time.time() + duration
    truth = TruthLog(out)
    print(f"node {node.name} ip={node.ip} mac={node.mac} flows={[f.name for f in node.flows]} "
          f"web={node.web_port} duration={duration:.0f}s", flush=True)
    server = None
    if node.web_port is not None:
        server = ThreadingHTTPServer(("0.0.0.0", node.web_port), WebHandler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
    runners = [FlowRunner(node, f, truth, deadline) for f in node.flows]
    for r in runners:
        r.start()
    try:
        if runners:
            for r in runners:
                r.join()
        else:  # pure server: run until stopped (docker stop / Ctrl+C)
            while not STOP.wait(1):
                pass
    except KeyboardInterrupt:
        STOP.set()
    if server:
        server.shutdown()
    truth.close()
    print(f"node {node.name} done: {truth.count} requests logged", flush=True)
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Generic FHIR hospital node (netlab)")
    ap.add_argument("--node", required=True, help="node .ini file")
    ap.add_argument("--out", help="answer key output (JSONL)")
    ap.add_argument("--duration", type=float, help="seconds to run (default: [node] duration)")
    ap.add_argument("--show", action="store_true", help="print the parsed configuration and exit")
    args = ap.parse_args(argv)
    try:
        node = load_config(args.node)
    except (OSError, ConfigError) as exc:
        print(f"error: {args.node}: {exc}", file=sys.stderr)
        return 2
    if args.show:
        print(json.dumps({**node.__dict__, "flows": [f.__dict__ for f in node.flows]}, indent=2))
        return 0
    import signal

    signal.signal(signal.SIGTERM, lambda *_: STOP.set())  # docker stop
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    return run_node(node, args.out, args.duration)


if __name__ == "__main__":
    raise SystemExit(main())
