"""Compare dissector output with the ground truth in ``expected.json`` (plan §6.5).

Usage::

    python lab/evaluate.py --pcap captures/pcaps/fhir_hapi.pcap --expected captures/pcaps/fhir_hapi_expected.json
    python lab/evaluate.py --events captures/live_events.jsonl --expected captures/live_expected.json

With ``--pcap`` the dissector runs with ``emit_non_fhir=True``. With ``--events`` an existing
JSONL file is evaluated (e.g. from live mode; produce it with ``--all`` for full results).

Matching: each expected entry is matched to the first unused event with the same
``(method, path without query, status)``. Exit code 0 only if everything matches.
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


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Evaluate the FHIR dissector against expected.json")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="capture to dissect")
    src.add_argument("--events", help="existing events JSONL (e.g. from live mode with --all)")
    ap.add_argument("--expected", required=True, help="answer key (*_expected.json) of the same run")
    args = ap.parse_args(argv)

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
