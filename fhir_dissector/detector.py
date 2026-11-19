"""Decide "is this request/response pair FHIR?" with an explainable score (plan §5.5)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import parse_qsl, urlsplit

from fhir_dissector.classifier import has_resource_segment
from fhir_dissector.http_parser import HttpMessage

WEIGHTS: dict[str, float] = {
    "content-type": 0.6,
    "accept": 0.4,
    "resourceType-body": 0.5,
    "xml-namespace": 0.5,
    "format-param": 0.3,
    "path-resource": 0.3,
    "path-metadata": 0.3,
    "path-fhir": 0.2,
}

_FHIR_MEDIA = ("application/fhir+json", "application/fhir+xml")
_FORMAT_VALUES = {"json", "xml", "application/json", "application/xml", "text/xml",
                  "application/fhir+json", "application/fhir+xml"}
_FHIR_VERSION_PARAM = re.compile(r"fhirVersion\s*=\s*\"?([0-9][0-9.]*)", re.IGNORECASE)


@dataclass
class Detection:
    """Result of FHIR detection."""

    is_fhir: bool
    confidence: float
    signals: list[str] = field(default_factory=list)
    version: Optional[str] = None


def _ct(msg: Optional[HttpMessage]) -> str:
    return msg.headers.get("content-type", "") if msg else ""


def fhir_version_from_content_type(*content_types: str) -> Optional[str]:
    """Extract ``fhirVersion=4.0`` from a Content-Type parameter, if present."""
    for ct in content_types:
        m = _FHIR_VERSION_PARAM.search(ct or "")
        if m:
            return m.group(1)
    return None


def detect(
    request: Optional[HttpMessage],
    response: Optional[HttpMessage],
    req_summary: dict[str, Any],
    resp_summary: dict[str, Any],
    min_confidence: float = 0.5,
) -> Detection:
    """Score the pair. Each signal counts once; the total is capped at 1.0."""
    signals: list[str] = []
    req_ct, resp_ct = _ct(request).lower(), _ct(response).lower()
    if any(m in req_ct or m in resp_ct for m in _FHIR_MEDIA):
        signals.append("content-type")
    if request and "fhir+" in request.headers.get("accept", "").lower():
        signals.append("accept")
    if any(s.get("format") == "json" and s.get("resource_type") for s in (req_summary, resp_summary)):
        signals.append("resourceType-body")
    if any(s.get("format") == "xml" and s.get("fhir_namespace") for s in (req_summary, resp_summary)):
        signals.append("xml-namespace")
    target = (request.target or "") if request else ""
    if target:
        parts = urlsplit(target)
        path = parts.path
        fmt = dict(parse_qsl(parts.query, keep_blank_values=True)).get("_format")
        if fmt is not None and fmt.strip().lower().split(";")[0] in _FORMAT_VALUES:
            signals.append("format-param")
        if has_resource_segment(path):
            signals.append("path-resource")
        if path.rstrip("/").endswith("/metadata"):
            signals.append("path-metadata")
        low = path.lower().rstrip("/")
        if "/fhir/" in path.lower() or low.endswith("/fhir"):
            signals.append("path-fhir")
    score = min(1.0, round(sum(WEIGHTS[s] for s in signals), 3))
    version = fhir_version_from_content_type(req_ct, resp_ct) or resp_summary.get("fhir_version")
    return Detection(is_fhir=score >= min_confidence, confidence=score, signals=signals, version=version)
