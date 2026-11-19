"""HL7 FHIR dissector: detects and classifies FHIR REST exchanges in TCP traffic."""

__all__ = ["FhirDissector"]
__version__ = "0.1.0"


def __getattr__(name: str):
    # Lazy import so the package imports even before dissector.py exists.
    if name == "FhirDissector":
        from fhir_dissector.dissector import FhirDissector

        return FhirDissector
    raise AttributeError(name)
