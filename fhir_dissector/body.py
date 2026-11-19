"""Summarise FHIR JSON/XML bodies into *metadata only* (never patient content).

``summarize()`` never raises; it returns ``{}`` when the body is empty or unparseable.
"""
from __future__ import annotations

import json
from collections import Counter
from typing import Any, Optional

try:  # safer XML parsing when available (optional, not required)
    from defusedxml import ElementTree as ET  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - depends on environment
    import xml.etree.ElementTree as ET  # noqa: N817

FHIR_NS = "http://hl7.org/fhir"
_NS = "{" + FHIR_NS + "}"


def body_format(body: bytes, content_type: str) -> Optional[str]:
    """Guess ``json`` / ``xml`` / ``form`` / None from the content type or first byte."""
    ct = (content_type or "").lower()
    if "json" in ct:
        return "json"
    if "xml" in ct:
        return "xml"
    if "x-www-form-urlencoded" in ct:
        return "form"
    head = body.lstrip()[:1]
    if head in (b"{", b"["):
        return "json"
    if head == b"<":
        return "xml"
    return None


def summarize(body: bytes, content_type: str = "", redact: bool = True) -> dict[str, Any]:
    """Return metadata about a FHIR resource body (see plan §5.6)."""
    try:
        if not body:
            return {}
        fmt = body_format(body, content_type)
        if fmt == "json":
            return _summarize_json(body, redact)
        if fmt == "xml":
            return _summarize_xml(body, redact)
        return {}
    except Exception:
        return {}


# ------------------------------------------------------------------- JSON
def _summarize_json(body: bytes, redact: bool) -> dict[str, Any]:
    data = json.loads(body.decode("utf-8", errors="replace"))
    if not isinstance(data, dict):
        return {"format": "json"}
    out: dict[str, Any] = {"format": "json"}
    rtype = data.get("resourceType")
    if not isinstance(rtype, str):
        return out
    out["resource_type"] = rtype
    out["id"] = _str_or_none(data.get("id"))
    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    out["version_id"] = _str_or_none(meta.get("versionId"))
    out["last_updated"] = _str_or_none(meta.get("lastUpdated"))
    if rtype == "Bundle":
        entries = data.get("entry") if isinstance(data.get("entry"), list) else []
        types: Counter[str] = Counter()
        methods: Counter[str] = Counter()
        for e in entries:
            if not isinstance(e, dict):
                continue
            r = e.get("resource")
            if isinstance(r, dict) and isinstance(r.get("resourceType"), str):
                types[r["resourceType"]] += 1
            req = e.get("request")
            if isinstance(req, dict) and isinstance(req.get("method"), str):
                methods[req["method"]] += 1
        out["bundle"] = {
            "type": _str_or_none(data.get("type")),
            "total": data.get("total") if isinstance(data.get("total"), int) else None,
            "entry_count": len(entries),
            "entry_types": dict(types),
            "request_methods": dict(methods),
        }
    elif rtype == "OperationOutcome":
        out["outcome_issues"] = _issues_json(data.get("issue"), redact)
    elif rtype == "CapabilityStatement":
        out["fhir_version"] = _str_or_none(data.get("fhirVersion"))
        sw = data.get("software") if isinstance(data.get("software"), dict) else {}
        out["software"] = _str_or_none(sw.get("name"))
    return out


def _issues_json(issues: Any, redact: bool) -> list[dict[str, Any]]:
    out = []
    for i in issues if isinstance(issues, list) else []:
        if not isinstance(i, dict):
            continue
        item = {"severity": _str_or_none(i.get("severity")), "code": _str_or_none(i.get("code"))}
        if not redact and i.get("diagnostics") is not None:
            item["diagnostics"] = str(i.get("diagnostics"))
        out.append(item)
    return out


def _str_or_none(v: Any) -> Optional[str]:
    return None if v is None or isinstance(v, (dict, list)) else str(v)


# -------------------------------------------------------------------- XML
def _local(tag: str) -> str:
    return tag.split("}", 1)[1] if tag.startswith("{") else tag


def _val(el: Any, path: str) -> Optional[str]:
    child = el.find(path) if el is not None else None
    return child.get("value") if child is not None else None


def _summarize_xml(body: bytes, redact: bool) -> dict[str, Any]:
    root = ET.fromstring(body)
    out: dict[str, Any] = {"format": "xml"}
    if not root.tag.startswith(_NS):
        out["fhir_namespace"] = False
        return out
    out["fhir_namespace"] = True
    rtype = _local(root.tag)
    out["resource_type"] = rtype
    out["id"] = _val(root, f"{_NS}id")
    out["version_id"] = _val(root, f"{_NS}meta/{_NS}versionId")
    out["last_updated"] = _val(root, f"{_NS}meta/{_NS}lastUpdated")
    if rtype == "Bundle":
        entries = root.findall(f"{_NS}entry")
        types: Counter[str] = Counter()
        methods: Counter[str] = Counter()
        for e in entries:
            res = e.find(f"{_NS}resource")
            if res is not None and len(res):
                types[_local(res[0].tag)] += 1
            m = _val(e, f"{_NS}request/{_NS}method")
            if m:
                methods[m] += 1
        total = _val(root, f"{_NS}total")
        out["bundle"] = {
            "type": _val(root, f"{_NS}type"),
            "total": int(total) if total and total.isdigit() else None,
            "entry_count": len(entries),
            "entry_types": dict(types),
            "request_methods": dict(methods),
        }
    elif rtype == "OperationOutcome":
        issues = []
        for i in root.findall(f"{_NS}issue"):
            item: dict[str, Any] = {"severity": _val(i, f"{_NS}severity"), "code": _val(i, f"{_NS}code")}
            diag = _val(i, f"{_NS}diagnostics")
            if not redact and diag is not None:
                item["diagnostics"] = diag
            issues.append(item)
        out["outcome_issues"] = issues
    elif rtype == "CapabilityStatement":
        out["fhir_version"] = _val(root, f"{_NS}fhirVersion")
        out["software"] = _val(root, f"{_NS}software/{_NS}name")
    return out
