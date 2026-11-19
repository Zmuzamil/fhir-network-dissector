"""Build the JSON event for one request/response pair, with redaction (plan §5.7).

Redaction (default on):

* search parameters: names only (values such as ``family=Rossi`` are patient data)
* the Authorization header: only ``bearer_present`` / ``scheme``, never the token
* bodies: only metadata from :mod:`fhir_dissector.body`, never resource contents
* ``request.path``: query string removed
* OperationOutcome ``diagnostics`` text dropped
"""
from __future__ import annotations

import json
from typing import Any, Optional
from urllib.parse import urlsplit

from fhir_dissector.detector import Detection
from fhir_dissector.http_parser import HttpMessage
from fhir_dissector.reassembly import Endpoint, Exchange


def fmt_endpoint(ep: Endpoint) -> str:
    """``1.2.3.4:80`` for IPv4, ``[::1]:80`` for IPv6."""
    ip, port = ep
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _auth(msg: Optional[HttpMessage]) -> dict[str, Any]:
    raw = msg.headers.get("authorization", "") if msg else ""
    scheme = raw.split(" ", 1)[0] if raw else None
    return {"bearer_present": bool(scheme and scheme.lower() == "bearer"), "scheme": scheme}


def _search_params(params: list[tuple[str, str]], redact: bool) -> list[str]:
    if redact:
        names: list[str] = []
        for k, _ in params:
            if k not in names:
                names.append(k)
        return names
    return [f"{k}={v}" for k, v in params]


def build_event(
    ex: Exchange,
    cls: dict[str, Any],
    det: Detection,
    req_summary: dict[str, Any],
    resp_summary: dict[str, Any],
    redact: bool = True,
    version: Optional[str] = None,
) -> dict[str, Any]:
    """Assemble one event dict (JSON-serialisable)."""
    req, resp = ex.request, ex.response
    first = req or resp
    ts = first.ts if first else 0.0
    end = resp.end_ts if resp else (req.end_ts if req else ts)
    errors: list[str] = list(ex.errors)
    for m in (req, resp):
        if m:
            errors += [e for e in m.errors if e not in errors]
            if m.truncated and "truncated" not in errors:
                errors.append("truncated")

    path = None
    if req and req.target is not None:
        path = urlsplit(req.target).path if redact else req.target

    event: dict[str, Any] = {
        "ts": round(ts, 6),
        "duration_ms": round(max(0.0, end - ts) * 1000.0, 3),
        "flow": {"client": fmt_endpoint(ex.client), "server": fmt_endpoint(ex.server)},
        "fhir": {
            "is_fhir": det.is_fhir,
            "confidence": det.confidence,
            "signals": det.signals,
            "version": det.version or version,
            "base": cls.get("base"),
            "interaction": cls.get("interaction"),
            "resource_type": cls.get("resource_type"),
            "resource_id": cls.get("resource_id"),
            "version_id": cls.get("version_id"),
            "operation": cls.get("operation"),
            "search_params": _search_params(cls.get("search_params") or [], redact),
        },
        "request": None,
        "response": None,
        "errors": errors,
    }
    if cls.get("compartment"):
        event["fhir"]["compartment"] = cls["compartment"]
    if req:
        event["request"] = {
            "method": req.method,
            "path": path,
            "content_type": req.headers.get("content-type"),
            "body_size": req.body_size,
            "auth": _auth(req),
            "resource_type": req_summary.get("resource_type"),
            "bundle": req_summary.get("bundle"),
        }
    if resp:
        event["response"] = {
            "status": resp.status,
            "content_type": resp.headers.get("content-type"),
            "body_size": resp.body_size,
            "resource_type": resp_summary.get("resource_type"),
            "bundle": resp_summary.get("bundle"),
            "outcome_issues": resp_summary.get("outcome_issues", []),
        }
    return event


def to_jsonl(event: dict[str, Any]) -> str:
    """One compact JSON line."""
    return json.dumps(event, separators=(",", ":"), ensure_ascii=False)
