"""One-command lab capture: start sniffer -> generate traffic -> stop -> write PCAP.

Usage (Windows: terminal "as Administrator" if Npcap is admin-only)::

    python lab/run_scenario.py --base http://localhost:8080/fhir --port 8080 --out captures/lab.pcap

The default interface is scapy's loopback interface (``conf.loopback_name``).
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_traffic  # noqa: E402


def wait_ready(base: str, timeout: float = 240.0) -> None:
    """Poll ``[base]/metadata`` until the server answers (HAPI can take minutes to boot).

    This runs *before* the sniffer starts, so these probes are not in the capture.
    """
    deadline = time.time() + timeout
    last = "no answer"
    while time.time() < deadline:
        try:
            r = requests.get(base.rstrip("/") + "/metadata", timeout=10,
                             headers={"Accept": "application/fhir+json"})
            if r.status_code == 200:
                return
            last = f"HTTP {r.status_code}"
        except requests.RequestException as exc:
            last = type(exc).__name__
        print(f"Waiting for FHIR server at {base} ({last}) ...")
        time.sleep(5)
    raise SystemExit(f"FHIR server at {base} not ready after {timeout:.0f}s ({last})")


def main(argv: list[str] | None = None) -> int:
    # Importing the layer modules registers the link types (e.g. DLT_NULL loopback),
    # otherwise captured frames are stored as undecodable raw bytes.
    import scapy.layers.inet  # noqa: F401
    import scapy.layers.inet6  # noqa: F401
    import scapy.layers.l2  # noqa: F401
    from scapy.config import conf
    from scapy.sendrecv import AsyncSniffer
    from scapy.utils import wrpcap

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", default="http://localhost:8080/fhir", help="FHIR base URL")
    ap.add_argument("--iface", default=None, help="capture interface (default: loopback)")
    ap.add_argument("--port", type=int, default=None, help="TCP port to capture (default: from --base)")
    ap.add_argument("--out", default="captures/lab.pcap", help="output PCAP")
    ap.add_argument("--expected", default="captures/expected.json", help="output expected.json")
    args = ap.parse_args(argv)

    port = args.port or urlsplit(args.base).port or 80
    iface = args.iface or conf.loopback_name
    wait_ready(args.base)

    print(f"Capturing on {iface!r} with filter 'tcp port {port}'")
    sniffer = AsyncSniffer(iface=iface, filter=f"tcp port {port}", store=True)
    try:
        sniffer.start()
    except (PermissionError, OSError) as exc:
        raise SystemExit(f"Cannot start capture: {exc}\nRun this terminal as Administrator.")
    time.sleep(1.0)
    if not sniffer.running:
        raise SystemExit("Sniffer did not start (permission?). Run this terminal as Administrator.")
    try:
        gen_traffic.run(args.base, args.expected)
    finally:
        time.sleep(2.0)
        packets = sniffer.stop()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out), packets)
    print(f"Captured {len(packets)} packets -> {out}")
    if len(packets) == 0:
        print("WARNING: no packets captured. Check Npcap loopback support and admin rights.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
