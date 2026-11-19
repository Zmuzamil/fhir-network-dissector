"""Command-line interface: ``pcap`` (offline) and ``live`` (sniffing) subcommands.

Examples::

    python -m fhir_dissector pcap captures/lab.pcap -o captures/events.jsonl
    python -m fhir_dissector pcap captures/lab.pcap --all --no-redact
    python -m fhir_dissector live --bpf "tcp port 8080" -o captures/live_events.jsonl

Both modes use the same code path: scapy packet -> FhirDissector.process_packet().
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import IO, Any, Iterator, Optional

from fhir_dissector.dissector import FhirDissector
from fhir_dissector.events import to_jsonl

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


def iter_pcap(path: str | Path) -> Iterator[Any]:
    """Stream packets from a PCAP/PCAPNG file without the default 65535-byte read cut."""
    prepare_scapy_capture()
    from scapy.utils import PcapReader

    with PcapReader(str(path)) as reader:
        while True:
            try:
                yield reader.read_packet(size=CAPTURE_SNAPLEN)
            except EOFError:
                return


def dissect_pcap(path: str | Path, dissector: FhirDissector) -> list[dict]:
    """Run ``dissector`` over a whole PCAP and return all events (flushes at the end)."""
    events: list[dict] = []
    for pkt in iter_pcap(path):
        events += dissector.process_packet(pkt)
    events += dissector.flush()
    return events


def _summary(d: FhirDissector, out: IO[str]) -> None:
    s = d.stats
    print(f"packets: {s['packets']}  tcp: {s['tcp_packets']}  connections: {d.connections}  "
          f"http exchanges: {s['http_exchanges']}  events written: {s['events']}  "
          f"FHIR events: {s['fhir_events']}", file=out)
    if s["truncated_packets"]:
        print(f"WARNING: {s['truncated_packets']} packets were cut by the capture snaplen", file=out)
    if s["internal_errors"]:
        print(f"WARNING: {s['internal_errors']} internal errors (skipped)", file=out)
    for inter, n in sorted(d.by_interaction.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {inter:<20} {n}", file=out)


def _make_dissector(args: argparse.Namespace) -> FhirDissector:
    return FhirDissector(redact=not args.no_redact, min_confidence=args.min_confidence,
                         emit_non_fhir=args.all)


def cmd_pcap(args: argparse.Namespace) -> int:
    """Offline mode: read a PCAP, write JSONL, print a summary."""
    if not Path(args.pcap).is_file():
        print(f"error: no such file: {args.pcap}", file=sys.stderr)
        return 2
    d = _make_dissector(args)
    events = dissect_pcap(args.pcap, d)
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            for e in events:
                f.write(to_jsonl(e) + "\n")
        print(f"wrote {len(events)} events to {out_path}", file=sys.stderr)
    else:
        for e in events:
            print(to_jsonl(e))
    _summary(d, sys.stderr)
    return 0


def cmd_live(args: argparse.Namespace) -> int:
    """Live mode: sniff, print each event as one line, flush on Ctrl+C / timeout."""
    prepare_scapy_capture()
    from scapy.config import conf
    from scapy.sendrecv import sniff

    iface = args.iface or conf.loopback_name
    d = _make_dissector(args)
    out_file: Optional[IO[str]] = None
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        out_file = open(args.output, "w", encoding="utf-8")
    last_expire = [time.time()]

    def emit(events: list[dict]) -> None:
        for e in events:
            line = to_jsonl(e)
            print(line, flush=True)
            if out_file:
                out_file.write(line + "\n")
                out_file.flush()

    def on_packet(pkt: Any) -> None:
        emit(d.process_packet(pkt))
        now = time.time()
        if now - last_expire[0] > 10:  # look for idle connections every ~10 s
            last_expire[0] = now
            emit(d.expire_idle(float(pkt.time)))

    print(f"Live capture on {iface!r} filter={args.bpf!r} (Ctrl+C to stop)", file=sys.stderr, flush=True)
    try:
        sniff(iface=iface, filter=args.bpf or None, store=False, prn=on_packet,
              timeout=args.timeout)
    except KeyboardInterrupt:
        pass
    except (PermissionError, OSError) as exc:
        print(f"error: cannot capture on {iface!r}: {exc}\n"
              "Run the terminal as Administrator (Windows) or with sudo (Linux/macOS).",
              file=sys.stderr)
        return 1
    finally:
        emit(d.flush())
        if out_file:
            out_file.close()
        _summary(d, sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="python -m fhir_dissector",
                                 description="Detect and classify HL7 FHIR exchanges in TCP traffic.")
    sub = ap.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("-o", "--output", help="write events as JSONL to this file")
        p.add_argument("--no-redact", action="store_true",
                       help="keep search values and OperationOutcome diagnostics (contains patient data!)")
        p.add_argument("--all", action="store_true", help="also emit non-FHIR HTTP events (is_fhir: false)")
        p.add_argument("--min-confidence", type=float, default=0.5, help="detection threshold (default 0.5)")

    p = sub.add_parser("pcap", help="dissect a PCAP/PCAPNG file")
    p.add_argument("pcap", help="input capture file")
    common(p)
    p.set_defaults(func=cmd_pcap)

    p = sub.add_parser("live", help="capture live traffic (needs capture rights)")
    p.add_argument("--iface", default=None, help="interface (default: loopback)")
    p.add_argument("--bpf", default="tcp", help='capture filter, e.g. "tcp port 8080"')
    p.add_argument("--timeout", type=float, default=None, help="stop after N seconds")
    common(p)
    p.set_defaults(func=cmd_live)
    return ap


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point."""
    args = build_parser().parse_args(argv)
    return int(args.func(args))
