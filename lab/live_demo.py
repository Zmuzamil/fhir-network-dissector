"""Two-button live test: ``start`` the FHIR server, then ``run`` the whole live test.

Usage::

    python lab/live_demo.py start     # button 1: start HAPI (port 8080, or 8090 if 8080 is busy)
    python lab/live_demo.py run       # button 2: live dissector + 19 calls + grade
    python lab/live_demo.py stop      # stop HAPI

``run`` finds the FHIR server by itself (HAPI on 8080/8090, or the mock server on 8081),
starts ``python -m fhir_dissector live`` in the background, sends the scripted traffic,
stops the dissector cleanly, and prints the evaluation. Results:

* captures/live_events.jsonl   - one line per request/response (what the dissector saw)
* captures/live_expected.json  - the answer key written by the traffic generator
* captures/evaluation_live.txt - the grade (precision, recall, interaction accuracy)
"""
from __future__ import annotations

import argparse
import json
import io
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from contextlib import redirect_stdout
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "lab"))
import evaluate  # noqa: E402
import gen_traffic  # noqa: E402

CAPTURES = ROOT / "captures"
EVENTS = CAPTURES / "live_events.jsonl"
EXPECTED = CAPTURES / "live_expected.json"
REPORT = CAPTURES / "evaluation_live.txt"
CANDIDATE_PORTS = (8080, 8090, 8081)  # HAPI default, HAPI alternative, mock server


def fhir_ready(port: int) -> bool:
    """True if a FHIR server answers /fhir/metadata on this port."""
    try:
        r = requests.get(f"http://localhost:{port}/fhir/metadata", timeout=5,
                         headers={"Accept": "application/fhir+json"})
        return r.status_code == 200 and "CapabilityStatement" in r.text[:2000]
    except requests.RequestException:
        return False


def port_in_use(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


def find_server() -> int | None:
    return next((p for p in CANDIDATE_PORTS if fhir_ready(p)), None)


# ------------------------------------------------------------------ button 1
def cmd_start() -> int:
    running = find_server()
    if running:
        print(f"OK: a FHIR server is already running on port {running}.")
        return 0
    port = 8080 if not port_in_use(8080) else 8090
    if port == 8090:
        print("Port 8080 is used by another program -> starting HAPI on port 8090.")
    env = dict(os.environ, HAPI_PORT=str(port))
    try:
        r = subprocess.run(["docker", "compose", "up", "-d"], cwd=ROOT, env=env, capture_output=True, text=True)
    except FileNotFoundError:
        print("ERROR: Docker is not installed (or not on PATH).")
        return 1
    if r.returncode != 0:
        print("ERROR: could not start HAPI. Is Docker Desktop running ('Engine running')?")
        print((r.stderr or r.stdout).strip().splitlines()[-1] if (r.stderr or r.stdout) else "")
        return 1
    print(f"HAPI is starting on port {port} (Java needs 1-2 minutes)", end="", flush=True)
    deadline = time.time() + 240
    while time.time() < deadline:
        if fhir_ready(port):
            print(f"\nOK: FHIR server ready at http://localhost:{port}/fhir  ->  now run button 2.")
            return 0
        print(".", end="", flush=True)
        time.sleep(5)
    print("\nERROR: HAPI did not become ready in 4 minutes. Check: docker compose logs --tail 30 hapi")
    return 1


# ------------------------------------------------------------------ button 2
def cmd_run() -> int:
    port = find_server()
    if port is None:
        print("ERROR: no FHIR server found on ports 8080/8090/8081. Run button 1 first.")
        return 1
    base = f"http://localhost:{port}/fhir"
    print(f"FHIR server: {base}")
    CAPTURES.mkdir(exist_ok=True)
    EVENTS.unlink(missing_ok=True)  # live mode appends: start from an empty file

    cmd = [sys.executable, "-m", "fhir_dissector", "live", "--bpf", f"tcp port {port}", "--all",
           "--quiet", "-o", str(EVENTS), "--timeout", "300"]
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    proc = subprocess.Popen(cmd, cwd=ROOT, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True,
                            creationflags=flags)
    lines: list[str] = []
    started = threading.Event()

    def read_stderr() -> None:
        for line in proc.stderr:  # type: ignore[union-attr]
            lines.append(line.rstrip())
            if line.startswith("Live capture on"):
                started.set()
    threading.Thread(target=read_stderr, daemon=True).start()
    if not started.wait(30):
        proc.kill()
        print("ERROR: the live dissector did not start:\n" + "\n".join(lines))
        return 1
    print(lines[0])
    time.sleep(1.0)

    print("Sending 19 calls (17 FHIR + 2 normal web pages)...")
    try:
        with redirect_stdout(io.StringIO()):
            gen_traffic.run(base, EXPECTED)
    except Exception as exc:  # server problem: still stop the dissector cleanly
        print(f"ERROR while sending traffic: {exc}")
    time.sleep(2.0)

    # stop the dissector like Ctrl+C would: it flushes and prints its summary
    proc.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGTERM)
    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
    time.sleep(0.3)
    print("\n--- dissector summary ---")
    print("\n".join(line for line in lines[1:] if line.strip()))

    if not EXPECTED.is_file() or not EVENTS.is_file():
        print("ERROR: no results to grade.")
        return 1
    rep = evaluate.evaluate(evaluate.load_events(EVENTS), json.loads(EXPECTED.read_text(encoding="utf-8")))
    buf = io.StringIO()
    evaluate.print_report(rep, buf)
    REPORT.write_text(buf.getvalue(), encoding="utf-8")
    print("\n--- grade (also saved in captures/evaluation_live.txt) ---")
    print(buf.getvalue())
    print(f"Results: {EVENTS.relative_to(ROOT)} ({rep['events']} events)")
    return 0 if rep["all_ok"] else 1


def cmd_stop() -> int:
    r = subprocess.run(["docker", "compose", "down"], cwd=ROOT)
    return r.returncode


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Two-button live test of the FHIR dissector")
    ap.add_argument("action", choices=["start", "run", "stop"])
    args = ap.parse_args(argv)
    return {"start": cmd_start, "run": cmd_run, "stop": cmd_stop}[args.action]()


if __name__ == "__main__":
    raise SystemExit(main())
