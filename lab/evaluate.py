"""Compare dissector output with the ground truth in ``expected.json`` (plan §6.5).

Usage::

    python lab/evaluate.py --pcap capture.pcap --expected expected.json          # single client, JSON list
    python lab/evaluate.py --events events.jsonl --expected expected.json        # events from live mode

With ``--pcap`` the dissector runs with ``emit_non_fhir=True``. With ``--events`` an existing
JSONL file is evaluated (e.g. from live mode; produce it with ``--all`` for full results).

Matching: each expected entry is matched to the first unused event with the same
``(method, path without query, status)``. Exit code 0 only if everything matches.

Network lab (many clients, interleaved connections): give the merged ``.jsonl`` answer key::

    python lab/evaluate.py --pcap captures/netlab/icu.pcap --expected captures/netlab/icu_expected.jsonl

Each call is matched per client IP to the closest event in time with the same
``(method, path, status)`` (``--tolerance`` seconds, default 2). Encrypted (TLS) calls are
reported separately: the dissector cannot see them, so they are never counted as misses.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fhir_dissector.cli import dissect_pcap  # noqa: E402
from fhir_dissector.dissector import FhirDissector  # noqa: E402

Key = tuple[str, str, Optional[int]]


def _key_expected(e: dict[str, Any]) -> Key:
    return (e["method"], urlsplit(e["path"]).path, e.get("actual_status"))


def _key_event(ev: dict[str, Any]) -> Key:
    req, resp = ev.get("request") or {}, ev.get("response") or {}
    return (req.get("method") or "", urlsplit(req.get("path") or "").path, resp.get("status"))


def _ratio(num: int, den: int) -> float:
    return num / den if den else 1.0


def evaluate(events: list[dict[str, Any]], expected: list[dict[str, Any]]) -> dict[str, Any]:
    """Match events to expected entries and compute the metrics."""
    used: set[int] = set()
    rows: list[dict[str, Any]] = []
    for exp in expected:
        k = _key_expected(exp)
        idx = next((i for i, ev in enumerate(events) if i not in used and _key_event(ev) == k), None)
        ev = events[idx] if idx is not None else None
        if idx is not None:
            used.add(idx)
        got_fhir = bool(ev and ev["fhir"]["is_fhir"])
        got_inter = ev["fhir"]["interaction"] if ev and got_fhir else None
        got_type = ev["fhir"]["resource_type"] if ev and got_fhir else None
        exp_inter = exp["expected_interaction"] if exp["is_fhir"] else None
        exp_type = exp["expected_resource_type"] if exp["is_fhir"] else None
        rows.append({
            "index": exp["index"], "method": exp["method"], "path": urlsplit(exp["path"]).path,
            "status": exp.get("actual_status"), "found": ev is not None,
            "exp_fhir": exp["is_fhir"], "got_fhir": got_fhir,
            "exp_interaction": exp_inter, "got_interaction": got_inter,
            "exp_type": exp_type, "got_type": got_type,
            "confidence": ev["fhir"]["confidence"] if ev else None,
            "ok": ev is not None and got_fhir == exp["is_fhir"] and got_inter == exp_inter and got_type == exp_type,
        })
    extra = [ev for i, ev in enumerate(events) if i not in used]
    extra_fhir = [ev for ev in extra if ev["fhir"]["is_fhir"]]

    tp = sum(1 for r in rows if r["exp_fhir"] and r["got_fhir"])
    fn = sum(1 for r in rows if r["exp_fhir"] and not r["got_fhir"])
    fp = sum(1 for r in rows if not r["exp_fhir"] and r["got_fhir"]) + len(extra_fhir)
    tn = sum(1 for r in rows if not r["exp_fhir"] and r["found"] and not r["got_fhir"])
    fhir_rows = [r for r in rows if r["exp_fhir"]]
    inter_ok = sum(1 for r in fhir_rows if r["got_interaction"] == r["exp_interaction"])
    type_ok = sum(1 for r in fhir_rows if r["got_type"] == r["exp_type"])
    return {
        "rows": rows,
        "expected": len(expected), "events": len(events), "matched": len(used),
        "extra_events": len(extra), "extra_fhir_events": len(extra_fhir),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": _ratio(tp, tp + fp), "recall": _ratio(tp, tp + fn),
        "interaction_accuracy": _ratio(inter_ok, len(fhir_rows)),
        "resource_type_accuracy": _ratio(type_ok, len(fhir_rows)),
        "all_ok": all(r["ok"] for r in rows) and not extra_fhir,
    }


def print_report(rep: dict[str, Any], out: Any = sys.stdout) -> None:
    """Human-readable table + totals."""
    hdr = (f"{'#':>3} {'method':<6} {'path':<34} {'st':>3}  {'fhir exp/got':<12} "
           f"{'interaction expected':<20} {'interaction got':<20} {'type exp/got':<26} ok")
    print(hdr, file=out)
    print("-" * len(hdr), file=out)
    for r in rep["rows"]:
        fhir = f"{'Y' if r['exp_fhir'] else 'N'}/{'Y' if r['got_fhir'] else ('N' if r['found'] else '-')}"
        types = f"{r['exp_type'] or '-'}/{r['got_type'] or '-'}"
        path = r["path"] if len(r["path"]) <= 34 else r["path"][:31] + "..."
        print(f"{r['index']:>3} {r['method']:<6} {path:<34} {r['status'] or '-':>3}  {fhir:<12} "
              f"{r['exp_interaction'] or '-':<20} {r['got_interaction'] or '-':<20} {types:<26} "
              f"{'OK' if r['ok'] else 'MISMATCH'}", file=out)
    print("-" * len(hdr), file=out)
    print(f"expected calls: {rep['expected']}  events: {rep['events']}  matched: {rep['matched']}  "
          f"extra events: {rep['extra_events']} (FHIR: {rep['extra_fhir_events']})", file=out)
    print(f"detection: TP={rep['tp']} FP={rep['fp']} FN={rep['fn']} TN={rep['tn']}  "
          f"precision={rep['precision']:.1%}  recall={rep['recall']:.1%}", file=out)
    print(f"interaction accuracy={rep['interaction_accuracy']:.1%}  "
          f"resource type accuracy={rep['resource_type_accuracy']:.1%}", file=out)
    print("RESULT: PASS (everything matches)" if rep["all_ok"] else "RESULT: FAIL (see MISMATCH rows)", file=out)


def load_events(path: str | Path) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


# ===================================================================== network lab (many clients)
# Answer-key lines (netlab/fhir_node.py): ts, client_ip, node, flow, method, path (no query),
# query, expected_interaction, expected_resource_type, is_fhir, encrypted, status.
DEFAULT_TOLERANCE = 2.0  # seconds between the client's log time and the captured request


def client_ip(event: dict[str, Any]) -> str:
    """'10.63.0.21:43122' or '[fd00::1]:80' -> the IP part."""
    flow = event["flow"]["client"]
    return flow[1:flow.index("]")] if flow.startswith("[") else flow.rsplit(":", 1)[0]


def match_netlab(events: list[dict[str, Any]], expected: list[dict[str, Any]],
                 tolerance: float = DEFAULT_TOLERANCE) -> dict[str, Any]:
    """Match answer-key calls to dissector events, per client IP, in time order.

    A plaintext expected call matches the closest-in-time unused event of the same client IP
    with the same (method, path without query, status) and |time difference| <= tolerance.
    Encrypted calls (TLS) cannot be seen by the dissector: they are counted separately and
    never as misses.
    """
    plain = [e for e in expected if not e.get("encrypted")]
    encrypted = [e for e in expected if e.get("encrypted")]
    by_client: dict[str, list[int]] = {}
    for i, ev in enumerate(events):
        by_client.setdefault(client_ip(ev), []).append(i)
    used: set[int] = set()
    rows: list[dict[str, Any]] = []
    for exp in sorted(plain, key=lambda e: e["ts"]):
        key = (exp["method"], urlsplit(exp["path"]).path, exp.get("status"))
        best, best_dt = None, None
        for i in by_client.get(exp["client_ip"], []):
            if i in used:
                continue
            ev = events[i]
            dt = abs(ev["ts"] - exp["ts"])
            if dt > tolerance or _key_event(ev) != key:
                continue
            if best_dt is None or dt < best_dt:
                best, best_dt = i, dt
        ev = events[best] if best is not None else None
        if best is not None:
            used.add(best)
        got_fhir = bool(ev and ev["fhir"]["is_fhir"])
        exp_inter = exp["expected_interaction"] if exp["is_fhir"] else None
        exp_type = exp["expected_resource_type"] if exp["is_fhir"] else None
        got_inter = ev["fhir"]["interaction"] if got_fhir else None
        got_type = ev["fhir"]["resource_type"] if got_fhir else None
        rows.append({
            "ts": exp["ts"], "client_ip": exp["client_ip"], "node": exp.get("node"), "method": exp["method"],
            "path": exp["path"], "status": exp.get("status"), "found": ev is not None,
            "exp_fhir": exp["is_fhir"], "got_fhir": got_fhir, "exp_interaction": exp_inter,
            "got_interaction": got_inter, "exp_type": exp_type, "got_type": got_type,
            "dt": round(best_dt, 4) if best_dt is not None else None,
            "errors": ev["errors"] if ev else [],
            "ok": ev is not None and got_fhir == exp["is_fhir"] and got_inter == exp_inter and got_type == exp_type,
        })
    extra = [events[i] for i in range(len(events)) if i not in used]
    extra_fhir = [ev for ev in extra if ev["fhir"]["is_fhir"]]
    enc_ips = {e["client_ip"] for e in encrypted}
    tp = sum(1 for r in rows if r["exp_fhir"] and r["got_fhir"])
    fn = sum(1 for r in rows if r["exp_fhir"] and not r["got_fhir"])
    fp = sum(1 for r in rows if not r["exp_fhir"] and r["got_fhir"]) + len(extra_fhir)
    tn = sum(1 for r in rows if not r["exp_fhir"] and r["found"] and not r["got_fhir"])
    fhir_rows = [r for r in rows if r["exp_fhir"]]
    return {
        "rows": rows, "expected": len(expected), "plaintext_expected": len(plain),
        "encrypted_expected": len(encrypted),
        "encrypted_seen": sum(1 for ev in events if client_ip(ev) in enc_ips),  # should be 0
        "events": len(events), "matched": len(used), "extra_events": len(extra),
        "extra_fhir_events": len(extra_fhir), "extra_fhir_samples": [
            {k: ev[k] for k in ("ts", "flow", "request", "response")} for ev in extra_fhir[:5]],
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": _ratio(tp, tp + fp), "recall": _ratio(tp, tp + fn),
        "interaction_accuracy": _ratio(sum(1 for r in fhir_rows if r["got_interaction"] == r["exp_interaction"]),
                                       len(fhir_rows)),
        "resource_type_accuracy": _ratio(sum(1 for r in fhir_rows if r["got_type"] == r["exp_type"]), len(fhir_rows)),
        "all_ok": all(r["ok"] for r in rows) and not extra_fhir,
    }


def capture_stats(pcap: str | Path, events: list[dict[str, Any]]) -> dict[str, Any]:
    """Frame sizes and duration of a classic PCAP (no scapy needed)."""
    from fhir_dissector.cli import iter_pcap_frames

    frames = iter_pcap_frames(pcap)
    sizes, first, last = [], None, None
    for ts, _, frame in frames or []:
        sizes.append(len(frame))
        first = ts if first is None else first
        last = ts
    return {"frames": len(sizes), "max_frame": max(sizes, default=0),
            "frames_over_1514": sum(1 for s in sizes if s > 1514),
            "capture_seconds": round((last or 0) - (first or 0), 1),
            "pcap_bytes": Path(pcap).stat().st_size}


def dissect_with_segment_stats(pcap: str | Path) -> tuple[list[dict[str, Any]], FhirDissector, dict[str, Any], float]:
    """Run the dissector and count, per HTTP message, the TCP segments it was delivered in.

    Each call of HttpParser.feed() delivers one in-order TCP segment, so the number of feed()
    calls between two completed messages is the number of segments of that message (approximate
    at message boundaries that fall inside a segment). The dissector itself is not changed.
    """
    import time as _time

    from fhir_dissector import http_parser

    seg_counts: list[tuple[int, int]] = []  # (body bytes on the wire, segments)
    original = http_parser.HttpParser.feed

    def counting_feed(self: Any, data: bytes, ts: float = 0.0) -> list:
        self._netlab_feeds = getattr(self, "_netlab_feeds", 0) + 1
        msgs = original(self, data, ts)
        for m in msgs:
            seg_counts.append((m.body_size, self._netlab_feeds))
            self._netlab_feeds = 0
        return msgs

    d = FhirDissector(emit_non_fhir=True)
    http_parser.HttpParser.feed = counting_feed
    try:
        t0 = _time.perf_counter()
        events = dissect_pcap(pcap, d)
        seconds = _time.perf_counter() - t0
    finally:
        http_parser.HttpParser.feed = original
    big = sorted(n for size, n in seg_counts if size > 1448)
    stats = {"messages": len(seg_counts), "messages_multi_segment": len(big),
             "max_segments_per_message": max((n for _, n in seg_counts), default=0),
             "median_segments_large_message": big[len(big) // 2] if big else 0}
    return events, d, stats, seconds


def evaluate_netlab(pcap: str | Path, expected_path: str | Path,
                    tolerance: float = DEFAULT_TOLERANCE) -> dict[str, Any]:
    """Full evaluation of one network-lab capture against its merged answer key."""
    expected = load_events(expected_path)
    events, d, seg, seconds = dissect_with_segment_stats(pcap)
    rep = match_netlab(events, expected, tolerance)
    rep.update(capture_stats(pcap, events))
    rep.update(seg)
    rep["connections"] = d.connections
    rep["tcp_packets"] = d.stats["tcp_packets"]
    rep["events_per_second"] = round(len(events) / seconds, 1) if seconds else 0.0
    rep["packets_per_second"] = round(d.stats["packets"] / seconds, 1) if seconds else 0.0
    rep["clients"] = sorted({e["client_ip"] for e in expected})
    rep["nodes"] = sorted({e.get("node", "?") for e in expected})
    mix: dict[str, int] = {}
    for e in expected:
        k = "encrypted (TLS)" if e.get("encrypted") else (e["expected_interaction"] or "non-FHIR")
        mix[k] = mix.get(k, 0) + 1
    rep["mix"] = dict(sorted(mix.items(), key=lambda kv: -kv[1]))
    rep["tolerance"] = tolerance
    return rep


def format_netlab_report(name: str, rep: dict[str, Any]) -> str:
    lines = [f"=== {name} ===",
             f"capture: {rep['frames']} frames, {rep['capture_seconds']} s, {rep['pcap_bytes'] / 1e6:.1f} MB, "
             f"max frame {rep['max_frame']} bytes ({rep['frames_over_1514']} frames > 1514), "
             f"{rep['connections']} TCP connections",
             f"segments: {rep['messages_multi_segment']} of {rep['messages']} HTTP messages span several TCP "
             f"segments; median {rep['median_segments_large_message']}, max {rep['max_segments_per_message']} "
             f"segments per message",
             f"systems: {len(rep['nodes'])} nodes with traffic ({', '.join(rep['nodes'])})",
             f"answer key: {rep['expected']} calls = {rep['plaintext_expected']} plaintext + "
             f"{rep['encrypted_expected']} encrypted (TLS, expected not visible; events seen from those "
             f"clients: {rep['encrypted_seen']})",
             f"dissector: {rep['events']} events, matched {rep['matched']}, extra {rep['extra_events']} "
             f"(FHIR {rep['extra_fhir_events']}); {rep['events_per_second']} events/s, "
             f"{rep['packets_per_second']} packets/s",
             f"detection: TP={rep['tp']} FP={rep['fp']} FN={rep['fn']} TN={rep['tn']}  "
             f"precision={rep['precision']:.2%}  recall={rep['recall']:.2%}",
             f"interaction accuracy={rep['interaction_accuracy']:.2%}  "
             f"resource type accuracy={rep['resource_type_accuracy']:.2%}",
             "message mix: " + ", ".join(f"{k} {v}" for k, v in rep["mix"].items())]
    bad = [r for r in rep["rows"] if not r["ok"]]
    if bad:
        lines.append(f"MISMATCHES ({len(bad)}):")
        for r in bad[:40]:
            lines.append(f"  {r['client_ip']:<11} {r['method']:<6} {r['path']:<40} st={r['status']} "
                         f"fhir {r['exp_fhir']}/{r['got_fhir']} inter {r['exp_interaction']}/{r['got_interaction']} "
                         f"type {r['exp_type']}/{r['got_type']} found={r['found']} errors={r['errors']}")
    for ev in rep["extra_fhir_samples"]:
        lines.append(f"  extra FHIR event: {ev['flow']['client']} {ev['request'] and ev['request']['method']} "
                     f"{ev['request'] and ev['request']['path']} -> {ev['response'] and ev['response']['status']}")
    lines.append("RESULT: PASS (everything matches)" if rep["all_ok"] else "RESULT: FAIL (see MISMATCHES)")
    return "\n".join(lines) + "\n"


def format_netlab_summary(reports: dict[str, dict[str, Any]]) -> str:
    hdr = (f"{'scenario':<11} {'min':>4} {'nodes':>5} {'calls':>6} {'TLS':>4} {'TP':>5} {'FP':>3} {'FN':>3} "
           f"{'TN':>4} {'prec':>7} {'recall':>7} {'inter':>7} {'type':>7} {'maxfr':>5} {'conns':>5} {'ev/s':>7}")
    lines = [hdr, "-" * len(hdr)]
    tot = {k: 0 for k in ("expected", "encrypted_expected", "tp", "fp", "fn", "tn", "inter_ok", "type_ok", "fhir")}
    for name, r in reports.items():
        fhir = sum(1 for x in r["rows"] if x["exp_fhir"])
        tot["fhir"] += fhir
        tot["inter_ok"] += sum(1 for x in r["rows"] if x["exp_fhir"] and x["got_interaction"] == x["exp_interaction"])
        tot["type_ok"] += sum(1 for x in r["rows"] if x["exp_fhir"] and x["got_type"] == x["exp_type"])
        for k in ("expected", "encrypted_expected", "tp", "fp", "fn", "tn"):
            tot[k] += r[k]
        lines.append(f"{name:<11} {r['capture_seconds'] / 60:>4.1f} {len(r['nodes']):>5} {r['expected']:>6} "
                     f"{r['encrypted_expected']:>4} {r['tp']:>5} {r['fp']:>3} {r['fn']:>3} {r['tn']:>4} "
                     f"{r['precision']:>7.2%} {r['recall']:>7.2%} {r['interaction_accuracy']:>7.2%} "
                     f"{r['resource_type_accuracy']:>7.2%} {r['max_frame']:>5} {r['connections']:>5} "
                     f"{r['events_per_second']:>7.0f}")
    lines.append("-" * len(hdr))
    p = _ratio(tot["tp"], tot["tp"] + tot["fp"])
    rc = _ratio(tot["tp"], tot["tp"] + tot["fn"])
    lines.append(f"{'TOTAL':<11} {'':>4} {'':>5} {tot['expected']:>6} {tot['encrypted_expected']:>4} {tot['tp']:>5} "
                 f"{tot['fp']:>3} {tot['fn']:>3} {tot['tn']:>4} {p:>7.2%} {rc:>7.2%} "
                 f"{_ratio(tot['inter_ok'], tot['fhir']):>7.2%} {_ratio(tot['type_ok'], tot['fhir']):>7.2%}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Evaluate the FHIR dissector against expected.json")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="capture to dissect")
    src.add_argument("--events", help="existing events JSONL (e.g. from live mode with --all)")
    ap.add_argument("--expected", required=True, help="answer key (*_expected.json) of the same run")
    ap.add_argument("--tolerance", type=float, default=DEFAULT_TOLERANCE,
                    help="network lab: max seconds between answer-key and captured time")
    args = ap.parse_args(argv)

    if args.expected.endswith(".jsonl"):  # network lab: many clients, per-client matching
        if not args.pcap:
            ap.error("a network-lab answer key (.jsonl) needs --pcap")
        rep = evaluate_netlab(args.pcap, args.expected, args.tolerance)
        print(format_netlab_report(Path(args.pcap).stem, rep), end="")
        return 0 if rep["all_ok"] else 1

    expected = json.loads(Path(args.expected).read_text(encoding="utf-8"))
    if args.pcap:
        events = dissect_pcap(args.pcap, FhirDissector(emit_non_fhir=True))
    else:
        events = load_events(args.events)
    rep = evaluate(events, expected)
    print_report(rep)
    return 0 if rep["all_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
