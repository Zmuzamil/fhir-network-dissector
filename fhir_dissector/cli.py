"""Command-line interface (full implementation in Phase 4)."""
from __future__ import annotations

CAPTURE_SNAPLEN = 262_144  # Wireshark's standard maximum; loopback frames can exceed 65535


def prepare_scapy_capture() -> None:
    """Load scapy layers and raise its capture snaplen.

    * Importing the layer modules registers link types (e.g. the DLT_NULL loopback
      header used by Npcap's loopback adapter); without it frames stay raw bytes.
    * scapy opens libpcap with ``snaplen=MTU`` (65535). On loopback, TCP segments can
      be ~64 KB, so frames are cut and bytes go missing. Raising the module-level
      ``MTU`` that libpcap reads at open time fixes that.
    """
    import scapy.layers.inet  # noqa: F401
    import scapy.layers.inet6  # noqa: F401
    import scapy.layers.l2  # noqa: F401

    try:
        import scapy.arch.libpcap as libpcap

        if getattr(libpcap, "MTU", CAPTURE_SNAPLEN) < CAPTURE_SNAPLEN:
            libpcap.MTU = CAPTURE_SNAPLEN
    except ImportError:  # pragma: no cover - platform without libpcap support
        pass


def main(argv: list[str] | None = None) -> int:
    """Entry point placeholder."""
    print("fhir_dissector: CLI not implemented yet")
    return 1
