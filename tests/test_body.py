"""Unit tests for the body summariser: metadata only, never patient content."""
from __future__ import annotations

import json

from fhir_dissector.body import summarize

PATIENT = {"resourceType": "Patient", "id": "7", "meta": {"versionId": "2", "lastUpdated": "2026-01-01T00:00:00Z"},
           "name": [{"family": "Rossi", "given": ["Mario"]}], "birthDate": "1980-04-12"}


def j(obj) -> bytes:
    return json.dumps(obj).encode()


def test_patient_metadata_only() -> None:
    s = summarize(j(PATIENT), "application/fhir+json")
    assert s == {"format": "json", "resource_type": "Patient", "id": "7", "version_id": "2",
                 "last_updated": "2026-01-01T00:00:00Z"}
    assert "Rossi" not in json.dumps(s) and "1980" not in json.dumps(s)


def test_bundle_searchset() -> None:
    b = {"resourceType": "Bundle", "type": "searchset", "total": 3,
         "entry": [{"resource": PATIENT}, {"resource": PATIENT},
                   {"resource": {"resourceType": "Observation", "id": "1"}}]}
    s = summarize(j(b), "application/fhir+json")
    assert s["bundle"] == {"type": "searchset", "total": 3, "entry_count": 3,
                           "entry_types": {"Patient": 2, "Observation": 1}, "request_methods": {}}


def test_transaction_request_methods() -> None:
    b = {"resourceType": "Bundle", "type": "transaction", "entry": [
        {"resource": PATIENT, "request": {"method": "POST", "url": "Patient"}},
        {"request": {"method": "GET", "url": "Patient/1"}},
        {"request": {"method": "GET", "url": "Patient/2"}}]}
    s = summarize(j(b), "application/json")
    assert s["bundle"]["request_methods"] == {"POST": 1, "GET": 2}
    assert s["bundle"]["entry_types"] == {"Patient": 1}


def test_operation_outcome_redaction() -> None:
    oo = {"resourceType": "OperationOutcome",
          "issue": [{"severity": "error", "code": "not-found", "diagnostics": "Patient Rossi not found"}]}
    assert summarize(j(oo), "application/fhir+json")["outcome_issues"] == [
        {"severity": "error", "code": "not-found"}]
    assert summarize(j(oo), "application/fhir+json", redact=False)["outcome_issues"][0]["diagnostics"] == \
        "Patient Rossi not found"


def test_capability_statement() -> None:
    cs = {"resourceType": "CapabilityStatement", "fhirVersion": "4.0.1", "software": {"name": "HAPI FHIR Server"}}
    s = summarize(j(cs), "application/fhir+json")
    assert s["fhir_version"] == "4.0.1" and s["software"] == "HAPI FHIR Server"


XML_PATIENT = b"""<?xml version="1.0" encoding="UTF-8"?>
<Patient xmlns="http://hl7.org/fhir"><id value="7"/><meta><versionId value="3"/>
<lastUpdated value="2026-01-01T00:00:00Z"/></meta><name><family value="Rossi"/></name></Patient>"""


def test_xml_patient() -> None:
    s = summarize(XML_PATIENT, "application/fhir+xml")
    assert s == {"format": "xml", "fhir_namespace": True, "resource_type": "Patient", "id": "7",
                 "version_id": "3", "last_updated": "2026-01-01T00:00:00Z"}


def test_xml_bundle_and_outcome() -> None:
    bundle = b"""<Bundle xmlns="http://hl7.org/fhir"><type value="searchset"/><total value="1"/>
    <entry><resource><Patient><id value="1"/></Patient></resource></entry></Bundle>"""
    s = summarize(bundle, "application/fhir+xml")
    assert s["bundle"]["type"] == "searchset" and s["bundle"]["total"] == 1
    assert s["bundle"]["entry_types"] == {"Patient": 1}
    oo = b"""<OperationOutcome xmlns="http://hl7.org/fhir"><issue><severity value="error"/>
    <code value="processing"/><diagnostics value="secret"/></issue></OperationOutcome>"""
    assert summarize(oo, "application/fhir+xml")["outcome_issues"] == [{"severity": "error", "code": "processing"}]


def test_xml_not_fhir_namespace() -> None:
    s = summarize(b"<html><body>hi</body></html>", "text/xml")
    assert s == {"format": "xml", "fhir_namespace": False}


def test_sniffs_format_without_content_type() -> None:
    assert summarize(j(PATIENT), "")["resource_type"] == "Patient"
    assert summarize(XML_PATIENT, "")["resource_type"] == "Patient"


def test_never_fails() -> None:
    for body, ct in [(b"", ""), (b"{not json", "application/json"), (b"<a><b>", "application/xml"),
                     (b"[1,2,3]", "application/json"), (b"\xff\xfe\x00", ""), (b"family=Rossi",
                     "application/x-www-form-urlencoded"), (b'{"resourceType": 5}', "application/json"),
                     (b'{"resourceType":"Bundle","entry":"x"}', "application/json")]:
        assert isinstance(summarize(body, ct), dict)
