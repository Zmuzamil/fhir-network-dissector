"""Trivial smoke test: the package imports."""
import fhir_dissector


def test_package_imports() -> None:
    assert fhir_dissector.__version__
