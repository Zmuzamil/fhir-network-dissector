"""Scripted FHIR + non-FHIR traffic generator; writes the ground-truth ``expected.json``.

Usage::

    python lab/gen_traffic.py --base http://localhost:8080/fhir --out captures/live_expected.json

All FHIR calls share one keep-alive ``requests.Session``; the non-FHIR calls use a
separate plain session (so they travel on a different TCP connection). Redirects are
never followed, so one call == one HTTP request/response pair on the wire.

Each call appends ``{index, method, path, expected_interaction, expected_resource_type,
is_fhir, actual_status}`` to the expected file. ``actual_status`` is what the client
really received, so the file is ground truth independent of the dissector.
"""
from __future__ import annotations

import argparse
import json
import re
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests

FHIR_JSON = "application/fhir+json"
FHIR_XML = "application/fhir+xml"


def _patient(family: str, given: str, gender: str, birth: str) -> dict[str, Any]:
    # Synthetic, made-up demo people. No real patient data.
    return {
        "resourceType": "Patient",
        "name": [{"family": family, "given": [given]}],
        "gender": gender,
        "birthDate": birth,
    }


def _observation(subject_ref: str, bpm: int) -> dict[str, Any]:
    return {
        "resourceType": "Observation",
        "status": "final",
        "code": {"coding": [{"system": "http://loinc.org", "code": "8867-4", "display": "Heart rate"}]},
        "subject": {"reference": subject_ref},
        "valueQuantity": {"value": bpm, "unit": "beats/minute",
                          "system": "http://unitsofmeasure.org", "code": "/min"},
    }


def _created_id(resp: requests.Response) -> str:
    """Get the server-assigned id from the body, or else from the Location header."""
    try:
        body = resp.json()
        if isinstance(body, dict) and body.get("id"):
            return str(body["id"])
    except ValueError:
        pass
    loc = resp.headers.get("Location") or resp.headers.get("Content-Location") or ""
    m = re.search(r"/([A-Za-z]+)/([^/]+)(?:/_history/[^/]+)?/?$", loc)
    if not m:
        raise RuntimeError(f"Cannot find created id (status {resp.status_code})")
    return m.group(2)


class TrafficRun:
    """Runs the scenario and records one expected entry per HTTP call."""

    def __init__(self, base: str, timeout: float = 60.0) -> None:
        self.base = base.rstrip("/")
        parts = urlsplit(self.base)
        self.origin = f"{parts.scheme}://{parts.netloc}"
        self.timeout = timeout
        self.fhir = requests.Session()
        self.fhir.headers.update({"Accept": FHIR_JSON})
        self.plain = requests.Session()
        self.entries: list[dict[str, Any]] = []

    def call(
        self,
        session: requests.Session,
        method: str,
        url: str,
        *,
        interaction: str | None,
        resource_type: str | None,
        is_fhir: bool,
        json_body: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Send one request (no redirects) and record the expected entry."""
        if not url.startswith("http"):
            url = f"{self.base}/{url}" if url else self.base
        if json_body is not None:
            kwargs["data"] = json.dumps(json_body)
            headers = dict(kwargs.pop("headers", {}) or {})
            headers.setdefault("Content-Type", FHIR_JSON)
            kwargs["headers"] = headers
        resp = session.request(method, url, allow_redirects=False, timeout=self.timeout, **kwargs)
        sent = urlsplit(resp.request.url or url)
        path = sent.path + (f"?{sent.query}" if sent.query else "")
        entry = {
            "index": len(self.entries) + 1,
            "method": method,
            "path": path,
            "expected_interaction": interaction,
            "expected_resource_type": resource_type,
            "is_fhir": is_fhir,
            "actual_status": resp.status_code,
        }
        self.entries.append(entry)
        print(f"{entry['index']:>3} {method:<6} {path:<55} -> {resp.status_code}")
        return resp

    def run(self) -> list[dict[str, Any]]:
        """Execute the scenario of plan §6.3."""
        f, c = self.fhir, self.call
        # 1. capabilities
        c(f, "GET", "metadata", interaction="capabilities", resource_type=None, is_fhir=True)
        # 2. create two patients
        r = c(f, "POST", "Patient", interaction="create", resource_type="Patient", is_fhir=True,
              json_body=_patient("Rossi", "Mario", "male", "1980-04-12"))
        pid = _created_id(r)
        r = c(f, "POST", "Patient", interaction="create", resource_type="Patient", is_fhir=True,
              json_body=_patient("Bianchi", "Giulia", "female", "1992-09-30"))
        _created_id(r)
        # 3. read (JSON)
        c(f, "GET", f"Patient/{pid}", interaction="read", resource_type="Patient", is_fhir=True)
        # 4. read (XML)
        c(f, "GET", f"Patient/{pid}", interaction="read", resource_type="Patient", is_fhir=True,
          headers={"Accept": FHIR_XML})
        # 5. update
        upd = _patient("Rossi", "Mario", "male", "1980-04-12")
        upd["id"] = pid
        upd["telecom"] = [{"system": "phone", "value": "+39 000 0000000"}]
        c(f, "PUT", f"Patient/{pid}", interaction="update", resource_type="Patient", is_fhir=True,
          json_body=upd)
        # 6. history + vread
        c(f, "GET", f"Patient/{pid}/_history", interaction="history-instance",
          resource_type="Patient", is_fhir=True)
        c(f, "GET", f"Patient/{pid}/_history/1", interaction="vread", resource_type="Patient", is_fhir=True)
        # 7. search-type (GET)
        c(f, "GET", "Patient?family=Rossi&_count=5", interaction="search-type",
          resource_type="Patient", is_fhir=True)
        # 8. search-type (POST _search, form body)
        c(f, "POST", "Patient/_search", interaction="search-type", resource_type="Patient",
          is_fhir=True, data="family=Rossi",
          headers={"Content-Type": "application/x-www-form-urlencoded"})
        # 9. create Observation
        r = c(f, "POST", "Observation", interaction="create", resource_type="Observation",
              is_fhir=True, json_body=_observation(f"Patient/{pid}", 72))
        oid = _created_id(r)
        # 10. transaction Bundle (Patient + Observation linked with urn:uuid)
        p_urn = f"urn:uuid:{uuid.uuid4()}"
        txn = {
            "resourceType": "Bundle",
            "type": "transaction",
            "entry": [
                {"fullUrl": p_urn, "resource": _patient("Verdi", "Luca", "male", "1975-01-20"),
                 "request": {"method": "POST", "url": "Patient"}},
                {"fullUrl": f"urn:uuid:{uuid.uuid4()}", "resource": _observation(p_urn, 64),
                 "request": {"method": "POST", "url": "Observation"}},
            ],
        }
        c(f, "POST", "", interaction="transaction", resource_type=None, is_fhir=True, json_body=txn)
        # 11. batch Bundle with two GET entries
        batch = {
            "resourceType": "Bundle",
            "type": "batch",
            "entry": [
                {"request": {"method": "GET", "url": f"Patient/{pid}"}},
                {"request": {"method": "GET", "url": f"Observation?subject=Patient/{pid}"}},
            ],
        }
        c(f, "POST", "", interaction="batch", resource_type=None, is_fhir=True, json_body=batch)
        # 12. operation $everything
        c(f, "GET", f"Patient/{pid}/$everything", interaction="operation",
          resource_type="Patient", is_fhir=True)
        # 13. delete then read the deleted resource (410 or 404 + OperationOutcome)
        c(f, "DELETE", f"Observation/{oid}", interaction="delete", resource_type="Observation", is_fhir=True)
        c(f, "GET", f"Observation/{oid}", interaction="read", resource_type="Observation", is_fhir=True)
        # 14. read a resource that does not exist (404)
        c(f, "GET", "Patient/does-not-exist-999", interaction="read", resource_type="Patient", is_fhir=True)
        # 15. non-FHIR calls on the same host, separate connection
        p = self.plain
        c(p, "GET", f"{self.origin}/", interaction=None, resource_type=None, is_fhir=False)
        c(p, "GET", f"{self.origin}/favicon.ico", interaction=None, resource_type=None, is_fhir=False)
        self.close()
        return self.entries

    def close(self) -> None:
        """Close both sessions so the TCP connections end (FIN) inside the capture."""
        self.fhir.close()
        self.plain.close()


def run(base: str, out: str | Path | None) -> list[dict[str, Any]]:
    """Run the scenario against ``base`` and write the expected file (if ``out``)."""
    entries = TrafficRun(base).run()
    if out:
        out_path = Path(out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
        print(f"Wrote {len(entries)} expected entries to {out_path}")
    return entries


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate lab FHIR traffic and expected.json")
    ap.add_argument("--base", default="http://localhost:8080/fhir", help="FHIR base URL")
    ap.add_argument("--out", default="captures/live_expected.json", help="answer key (JSON) path")
    args = ap.parse_args(argv)
    run(args.base, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
