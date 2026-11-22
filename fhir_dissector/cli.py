"""Command-line interface: ``pcap`` (offline) and ``live`` (sniffing) subcommands.

Examples::

    python -m fhir_dissector pcap captures/pcaps/fhir_hapi.pcap -o captures/events.jsonl
    python -m fhir_dissector pcap captures/pcaps/fhir_hapi.pcap --all --no-redact
    python -m fhir_dissector live --bpf "tcp port 8080" -o captures/live_events.jsonl --quiet

Both modes end in the same code path (FhirDissector). Classic PCAP files and libpcap live
captures use the fast raw-frame decoder; PCAPNG files and other sources go through scapy.
"""
from __future__ import annotations

import argparse
import signal
import struct
import sys
import time
from pathlib import Path
from typing import IO, Any, Iterator, Optional

from fhir_dissector.dissector import SUPPORTED_LINKTYPES, FhirDissector
from fhir_dissector.events import to_jsonl
from fhir_dissector.reassembly import DEFAULT_MAX_CONNECTIONS

CAPTURE_SNAPLEN = 262_144  # Wireshark's standard maximum; loopback frames can exceed 65535
_PCAP_MAGIC = {  # magic -> (byte order, timestamp fraction unit)
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}


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


def iter_pcap_frames(path: str | Path) -> Optional[Iterator[tuple[float, int, bytes]]]:
    """Yield ``(ts, linktype, frame)`` from a classic PCAP file (no scapy needed).

    Returns None if the file is not a classic PCAP (e.g. PCAPNG).
    """
    f = open(path, "rb")
    header = f.read(24)
    fmt = _PCAP_MAGIC.get(header[:4])
    if fmt is None or len(header) < 24:
        f.close()
        return None
    order, unit = fmt
    linktype = struct.unpack(order + "I", header[20:24])[0] & 0x0FFFFFFF

    def gen() -> Iterator[tuple[float, int, bytes]]:
        with f:
            while True:
                rec = f.read(16)
                if len(rec) < 16:
                    return
                sec, frac, caplen, _ = struct.unpack(order + "IIII", rec)
                data = f.read(caplen)
                if len(data) < caplen:
                    return  # file cut in the middle of a packet
                yield sec + frac * unit, linktype, data
    return gen()


def iter_pcap(path: str | Path) -> Iterator[Any]:
    """Stream scapy packets from a PCAP/PCAPNG file without the default 65535-byte read cut."""
    prepare_scapy_capture()
    from scapy.utils import PcapReader

    with PcapReader(str(path)) as reader:
        while True:
            try:
                yield reader.read_packet(size=CAPTURE_SNAPLEN)
            except EOFError:
                return


def dissect_pcap(path: str | Path, dissector: FhirDissector) -> list[dict]:
    """Run ``dissector`` over a whole capture file and return all events (flushes at the end)."""
    events: list[dict] = []
    frames = iter_pcap_frames(path)
    if frames is not None:
        for ts, linktype, frame in frames:
            if linktype not in SUPPORTED_LINKTYPES:  # unusual link type: let scapy decode it
                frames = None
                break
            events += dissector.process_frame(ts, linktype, frame)
    if frames is None and not events:
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
    if d.reassembler.evicted:
        print(f"WARNING: {d.reassembler.evicted} connections evicted (raise --max-connections)", file=out)
    if s["internal_errors"]:
        print(f"WARNING: {s['internal_errors']} internal errors (skipped)", file=out)
    for inter, n in sorted(d.by_interaction.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {inter:<20} {n}", file=out)


def _make_dissector(args: argparse.Namespace) -> FhirDissector:
    return FhirDissector(redact=not args.no_redact, min_confidence=args.min_confidence,
                         emit_non_fhir=args.all, max_body=args.max_body,
                         idle_timeout=args.idle_timeout or None, max_connections=args.max_connections)


def cmd_pcap(args: argparse.Namespace) -> int:
    """Offline mode: read a capture file, write JSONL, print a summary."""
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
    """Live mode: sniff, emit each event as one line, flush on Ctrl+C / SIGTERM / timeout."""
    prepare_scapy_capture()
    from scapy.config import conf
    from scapy.sendrecv import AsyncSniffer

    iface = args.iface or conf.loopback_name
    d = _make_dissector(args)
    try:
        sock = conf.L2listen(iface=iface, filter=args.bpf or None)
    except (PermissionError, OSError) as exc:
        print(f"error: cannot capture on {iface!r}: {exc}\n"
              "Run the terminal as Administrator (Windows) or with sudo (Linux/macOS).",
              file=sys.stderr)
        return 1
    # Fast path: with libpcap we know the link type, so frames are kept as raw bytes
    # (scapy's Raw layer) and decoded by decode_frame() instead of full scapy dissection.
    linktype = sock.pcap_fd.datalink() if hasattr(sock, "pcap_fd") else None
    fast = linktype in SUPPORTED_LINKTYPES
    if fast:
        sock.LL = conf.raw_layer

    out_file: Optional[IO[str]] = None
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        out_file = open(args.output, "a", encoding="utf-8")  # append: survive restarts
    last_expire = [time.time()]

    def emit(events: list[dict]) -> None:
        for e in events:
            line = to_jsonl(e)
            if not (args.quiet and out_file):
                print(line, flush=True)
            if out_file:
                out_file.write(line + "\n")
                out_file.flush()

    def on_packet(pkt: Any) -> None:
        if fast and isinstance(pkt, conf.raw_layer):
            emit(d.process_frame(float(pkt.time), linktype, bytes(pkt)))
        else:
            emit(d.process_packet(pkt))
        now = time.time()
        if now - last_expire[0] > 10:  # look for idle connections every ~10 s
            last_expire[0] = now
            emit(d.expire_idle(float(pkt.time)))

    def on_stop_signal(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt  # stop sniffing, then flush and print the summary

    # SIGTERM: sent by service managers (systemctl stop). SIGBREAK: Ctrl+Break on Windows,
    # also used by lab/live_demo.py to stop this process cleanly.
    for name in ("SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), on_stop_signal)
    print(f"Live capture on {iface!r} filter={args.bpf!r} ({'fast' if fast else 'scapy'} decoding; "
          f"Ctrl+C to stop)", file=sys.stderr, flush=True)
    # Capture runs in a background thread; the main thread only waits. That way Ctrl+C and
    # stop signals are handled at once, even when no packets arrive (a blocking capture
    # call would delay them until the next packet).
    sniffer = AsyncSniffer(opened_socket=sock, store=False, prn=on_packet)
    sniffer.start()
    deadline = time.monotonic() + args.timeout if args.timeout else None
    try:
        while sniffer.thread is not None and sniffer.thread.is_alive():
            if deadline is not None and time.monotonic() >= deadline:
                break  # --timeout reached
            sniffer.thread.join(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        if sniffer.running:
            try:
                sniffer.stop()
            except Exception:  # already stopping
                pass
        emit(d.flush())
        sock.close()
        if out_file:
            out_file.close()
        _summary(d, sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="python -m fhir_dissector",
                                 description="Detect and classify HL7 FHIR exchanges in TCP traffic.")
    sub = ap.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("-o", "--output", help="write events as JSONL to this file (live: appends)")
        p.add_argument("--no-redact", action="store_true",
                       help="keep search values and OperationOutcome diagnostics (contains patient data!)")
        p.add_argument("--all", action="store_true", help="also emit non-FHIR HTTP events (is_fhir: false)")
        p.add_argument("--min-confidence", type=float, default=0.5, help="detection threshold (default 0.5)")
        p.add_argument("--max-body", type=int, default=10_000_000,
                       help="max stored body bytes per message (default 10000000)")
        p.add_argument("--idle-timeout", type=float, default=120.0,
                       help="close connections idle this many seconds; 0 = never (default 120)")
        p.add_argument("--max-connections", type=int, default=DEFAULT_MAX_CONNECTIONS,
                       help=f"max tracked TCP connections (default {DEFAULT_MAX_CONNECTIONS})")

    p = sub.add_parser("pcap", help="dissect a PCAP/PCAPNG file")
    p.add_argument("pcap", help="input capture file")
    common(p)
    p.set_defaults(func=cmd_pcap)

    p = sub.add_parser("live", help="capture live traffic (needs capture rights)")
    p.add_argument("--iface", default=None, help="interface (default: loopback)")
    p.add_argument("--bpf", default="tcp", help='capture filter, e.g. "tcp port 8080"')
    p.add_argument("--timeout", type=float, default=None, help="stop after N seconds")
    p.add_argument("--quiet", action="store_true", help="with -o: do not also print events to the screen")
    common(p)
    p.set_defaults(func=cmd_live)
    return ap


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point."""
    args = build_parser().parse_args(argv)
    return int(args.func(args))
