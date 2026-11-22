"""Unit tests for the URL/method -> FHIR interaction classifier (plan §5.4 table)."""
from __future__ import annotations

import pytest

from fhir_dissector.classifier import RESOURCE_TYPES, classify


@pytest.mark.parametrize(
    "method, target, interaction, rtype, rid, vid, op",
    [
        ("GET", "/fhir/metadata", "capabilities", None, None, None, None),
        ("GET", "/fhir/_history", "history-system", None, None, None, None),
        ("GET", "/fhir?_type=Patient", "search-system", None, None, None, None),
        ("POST", "/fhir/$convert", "operation", None, None, None, "$convert"),
        ("GET", "/fhir/Patient", "search-type", "Patient", None, None, None),
        ("GET", "/fhir/Patient?family=Rossi&_count=5", "search-type", "Patient", None, None, None),
        ("POST", "/fhir/Patient", "create", "Patient", None, None, None),
        ("PUT", "/fhir/Patient?identifier=x", "conditional-update", "Patient", None, None, None),
        ("PATCH", "/fhir/Patient?identifier=x", "conditional-patch", "Patient", None, None, None),
        ("DELETE", "/fhir/Patient?identifier=x", "conditional-delete", "Patient", None, None, None),
        ("POST", "/fhir/Patient/_search", "search-type", "Patient", None, None, None),
        ("GET", "/fhir/Patient/_history", "history-type", "Patient", None, None, None),
        ("POST", "/fhir/Patient/$match", "operation", "Patient", None, None, "$match"),
        ("GET", "/fhir/Patient/123", "read", "Patient", "123", None, None),
        ("PUT", "/fhir/Patient/123", "update", "Patient", "123", None, None),
        ("PATCH", "/fhir/Patient/123", "patch", "Patient", "123", None, None),
        ("DELETE", "/fhir/Patient/123", "delete", "Patient", "123", None, None),
        ("GET", "/fhir/Patient/123/_history", "history-instance", "Patient", "123", None, None),
        ("GET", "/fhir/Patient/123/_history/2", "vread", "Patient", "123", "2", None),
        ("GET", "/fhir/Patient/123/$everything", "operation", "Patient", "123", None, "$everything"),
        ("GET", "/fhir/Patient/123/Observation", "search-compartment", "Observation", None, None, None),
        ("GET", "/fhir/Patient/1/2/3/4", "unknown", "Patient", None, None, None),
        ("GET", "/", "unknown", None, None, None, None),
        ("GET", "/favicon.ico", "unknown", None, None, None, None),
    ],
)
def test_table(method, target, interaction, rtype, rid, vid, op) -> None:
    r = classify(method, target)
    assert (r["interaction"], r["resource_type"], r["resource_id"], r["version_id"], r["operation"]) == (
        interaction, rtype, rid, vid, op)


def test_operation_levels_and_compartment() -> None:
    assert classify("POST", "/fhir/$x")["level"] == "system"
    assert classify("POST", "/fhir/Patient/$x")["level"] == "type"
    assert classify("POST", "/fhir/Patient/1/$x")["level"] == "instance"
    assert classify("GET", "/fhir/Patient/1/Observation")["compartment"] == "Patient/1"


@pytest.mark.parametrize("bundle_type, expected", [
    ("transaction", "transaction"), ("batch", "batch"), (None, "batch/transaction"),
    ("searchset", "batch/transaction"),
])
def test_post_base_bundle(bundle_type, expected) -> None:
    r = classify("POST", "/fhir", bundle_type=bundle_type)
    assert r["interaction"] == expected and r["base"] == "/fhir"


@pytest.mark.parametrize("target, base", [
    ("/fhir/Patient/1", "/fhir"),
    ("/Patient/1", ""),
    ("/baseR4/Patient/1", "/baseR4"),
    ("/api/FHIR/r4/Patient/1", "/api/FHIR/r4"),  # known type wins over "Type-like" FHIR
    ("/hapi-fhir/fhir/metadata", "/hapi-fhir/fhir"),
])
def test_base_detection(target, base) -> None:
    assert classify("GET", target)["base"] == base


def test_unknown_type_like_segment_is_accepted() -> None:
    r = classify("GET", "/fhir/MyCustomResource/7")
    assert (r["interaction"], r["resource_type"], r["resource_id"]) == ("read", "MyCustomResource", "7")


def test_search_param_names_from_query_and_form() -> None:
    r = classify("GET", "/fhir/Patient?family=Rossi&given=Mario&family=Bianchi")
    assert r["search_param_names"] == ["family", "given"]
    r = classify("POST", "/fhir/Patient/_search?_count=5", form_body=b"family=Rossi&birthdate=gt2000")
    assert r["search_param_names"] == ["_count", "family", "birthdate"]


def test_percent_encoded_operation() -> None:
    r = classify("GET", "/fhir/Patient/1/%24everything")
    assert r["interaction"] == "operation" and r["operation"] == "$everything"


def test_resource_list_contains_r4_and_r5() -> None:
    for t in ("Patient", "Observation", "Bundle", "MedicinalProduct", "SubscriptionTopic", "Transport"):
        assert t in RESOURCE_TYPES
    assert len(RESOURCE_TYPES) > 170


def test_garbage_does_not_raise() -> None:
    for t in ("", "////", "%%%", "?a=b", "http://h/fhir/Patient/1", "*"):
        classify("GET", t)
