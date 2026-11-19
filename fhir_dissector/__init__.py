"""HL7 FHIR dissector: detects and classifies FHIR REST exchanges in TCP traffic.

Typical use::

    from fhir_dissector import FhirDissector
    d = FhirDissector()
    events = d.process_tcp(ts, src, sport, dst, dport, flags, seq, payload)
    events += d.flush()
"""
from fhir_dissector.dissector import FhirDissector

__all__ = ["FhirDissector"]
__version__ = "0.1.0"
