"""One-click live test of the FHIR dissector (and helpers to start/stop the server, record PCAPs).

Usage::

    python lab/live_demo.py all       # 1 click: Docker + HAPI if needed, then the live test
    python lab/live_demo.py start     # only start HAPI (port 8080, or 8090 if 8080 is busy)
    python lab/live_demo.py run       # only the live test: live dissector + 19 calls + grade
    python lab/live_demo.py record    # record the 19 calls into a PCAP file (+ answer key + score)
    python lab/live_demo.py stop      # stop HAPI

``run`` finds the FHIR server by itself (HAPI on 8080/8090, or the mock server on 8081),
starts ``python -m fhir_dissector live`` in the background, sends the scripted traffic,
stops the dissector cleanly, and prints the evaluation. Results:

* captures/live_events.jsonl   - one line per request/response (what the dissector saw)
* captures/live_expected.json  - the answer key written by the traffic generator
* captures/evaluation_live.txt - the grade (precision, recall, interaction accuracy)

``record`` saves the traffic itself, for Wireshark or later analysis, in captures/pcaps/:
<name>.pcap, <name>_expected.json (answer key) and <name>_evaluation.txt (dissector score).
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
PCAPS = CAPTURES / "pcaps"
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


DOCKER_DESKTOP = Path(r"C:\Program Files\Docker\Docker\Docker Desktop.exe")


def docker_ready() -> bool:
    try:
        return subprocess.run(["docker", "version"], capture_output=True, timeout=20).returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def ensure_docker() -> bool:
    """Make sure the Docker engine runs; on Windows start Docker Desktop if needed."""
    if docker_ready():
        return True
    if os.name == "nt" and DOCKER_DESKTOP.is_file():
        print("Starting Docker Desktop", end="", flush=True)
        subprocess.Popen([str(DOCKER_DESKTOP)])
        deadline = time.time() + 180
        while time.time() < deadline:
            time.sleep(5)
            if docker_ready():
                print(" -> engine running.")
                return True
            print(".", end="", flush=True)
        print()
    print("ERROR: Docker is not running. Open Docker Desktop and wait for 'Engine running'.")
    return False


# ------------------------------------------------------------------ start server
def cmd_start() -> int:
    running = find_server()
    if running:
        print(f"OK: a FHIR server is already running on port {running}.")
        return 0
    if not ensure_docker():
        return 1
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
            print(f"\nOK: FHIR server ready at http://localhost:{port}/fhir")
            return 0
        print(".", end="", flush=True)
        time.sleep(5)
    print("\nERROR: HAPI did not become ready in 4 minutes. Check: docker compose logs --tail 30 hapi")
    return 1


# ------------------------------------------------------------------ live test
def cmd_run() -> int:
    port = find_server()
    if port is None:
        print("ERROR: no FHIR server found on ports 8080/8090/8081. Start one first (action 'start').")
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


# ------------------------------------------------------------------ record
def cmd_record(name: str | None, port: int | None) -> int:
    port = port or find_server()
    if port is None or not fhir_ready(port):
        print("ERROR: no FHIR server found. Start one first (action 'start', or the mock server).")
        return 1
    server = "mock" if port == 8081 else "hapi"
    name = name or f"fhir_{server}_{time.strftime('%Y%m%d_%H%M%S')}"
    PCAPS.mkdir(parents=True, exist_ok=True)
    pcap, expected = PCAPS / f"{name}.pcap", PCAPS / f"{name}_expected.json"
    report = PCAPS / f"{name}_evaluation.txt"
    print(f"Recording the 19 calls against http://localhost:{port}/fhir ...")
    r = subprocess.run([sys.executable, "lab/run_scenario.py", "--base", f"http://localhost:{port}/fhir",
                        "--port", str(port), "--out", str(pcap), "--expected", str(expected)],
                       cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        print("ERROR while recording:\n" + (r.stdout + r.stderr)[-1500:])
        return 1
    print(r.stdout.strip().splitlines()[-1])  # "Captured N packets -> ..."
    from fhir_dissector import FhirDissector
    from fhir_dissector.cli import dissect_pcap

    rep = evaluate.evaluate(dissect_pcap(pcap, FhirDissector(emit_non_fhir=True)),
                            json.loads(expected.read_text(encoding="utf-8")))
    buf = io.StringIO()
    evaluate.print_report(rep, buf)
    report.write_text(buf.getvalue(), encoding="utf-8")
    print("\n".join(buf.getvalue().strip().splitlines()[-4:]))
    print(f"Saved: {pcap.relative_to(ROOT)}, {expected.name}, {report.name}  (open the .pcap in Wireshark)")
    return 0 if rep["all_ok"] else 1


def cmd_all() -> int:
    """1 click: make sure a FHIR server runs, then do the live test."""
    rc = cmd_start()
    if rc != 0:
        return rc
    print()
    return cmd_run()


def cmd_stop() -> int:
    r = subprocess.run(["docker", "compose", "down"], cwd=ROOT)
    return r.returncode


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="One-click live test of the FHIR dissector")
    ap.add_argument("action", choices=["all", "start", "run", "record", "stop"])
    ap.add_argument("--name", help="record: file name without extension (default: fhir_<server>_<time>)")
    ap.add_argument("--port", type=int, help="record: server port (default: found automatically)")
    args = ap.parse_args(argv)
    if args.action == "record":
        return cmd_record(args.name, args.port)
    return {"all": cmd_all, "start": cmd_start, "run": cmd_run, "stop": cmd_stop}[args.action]()


if __name__ == "__main__":
    raise SystemExit(main())
