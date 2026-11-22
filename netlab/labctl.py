"""Control the FHIR network lab (netlab): up, down, run, generate, evaluate.

    python netlab/labctl.py up icu --duration 60      start a scenario (capture on)
    python netlab/labctl.py down                     stop it, merge the answer keys
    python netlab/labctl.py run icu --duration 60    up + wait for the clients + down + evaluate
    python netlab/labctl.py generate                 every scenario in turn (default 300 s each)
    python netlab/labctl.py evaluate                 evaluate all captures in captures/netlab/

Order of "up" (like hl7-sim's lab-up.sh): network + HAPI, wait until HAPI answers, start the
capture, then the servers of the scenario (intranet, TLS proxy), then the clients. A scenario
is a folder netlab/scenari/NAME with one .ini file per node.

Results in captures/netlab/: NAME.pcap, NAME_expected.jsonl (merged answer key),
NAME_evaluation.txt, summary.txt. Per-node answer keys in captures/netlab/run/NAME/.
"""
from __future__ import annotations

import argparse
import configparser
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SCENARI = HERE / "scenari"
OUT = ROOT / "captures" / "netlab"
RUN_DIR = HERE / ".run"
STATE = RUN_DIR / "state.json"
GENERATED = HERE / "compose.scenario.yml"
PROJECT = "fhir-netlab"
IMAGE = "fhir-netlab-node"
CADDY_IMAGE = "caddy:2-alpine"
DEFAULT_DURATION = 300


# ------------------------------------------------------------------ helpers
def log(msg: str) -> None:
    print(f"[labctl {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def sh(args: list[str], check: bool = True, quiet: bool = False, env: Optional[dict] = None,
       timeout: Optional[float] = None) -> subprocess.CompletedProcess:
    import os

    full_env = dict(os.environ, **(env or {}))
    r = subprocess.run(args, cwd=HERE, capture_output=True, text=True, env=full_env, timeout=timeout)
    if check and r.returncode != 0:
        raise SystemExit(f"command failed ({r.returncode}): {' '.join(args)}\n{r.stdout}{r.stderr}")
    if not quiet and r.stdout.strip():
        print(r.stdout.strip())
    return r


def compose(*args: str, check: bool = True, env: Optional[dict] = None, files: bool = True,
            timeout: Optional[float] = None) -> subprocess.CompletedProcess:
    base = ["docker", "compose", "-p", PROJECT]
    if files:
        base += ["-f", "docker-compose.yml"] + (["-f", GENERATED.name] if GENERATED.is_file() else [])
    return sh(base + list(args), check=check, quiet=True, env=env, timeout=timeout)


def read_ini(path: Path) -> configparser.ConfigParser:
    cp = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=("#",))
    cp.read(path, encoding="utf-8")
    return cp


def scenario_nodes(scenario: str) -> list[dict[str, Any]]:
    """Describe the nodes of a scenario: name, ip, mac, role (client | web | proxy)."""
    folder = SCENARI / scenario
    if not folder.is_dir():
        names = ", ".join(sorted(p.name for p in SCENARI.iterdir() if p.is_dir()))
        raise SystemExit(f"unknown scenario {scenario!r} (available: {names})")
    nodes = []
    for ini in sorted(folder.glob("*.ini")):
        cp = read_ini(ini)
        n = cp["node"]
        role = "proxy" if cp.has_section("proxy:tls") else "web" if cp.has_section("server:web") else "client"
        nodes.append({"name": ini.stem, "file": ini.name, "ip": n.get("ip", "").strip(),
                      "mac": n.get("mac", "").strip(), "role": role,
                      "upstream": cp.get("proxy:tls", "upstream", fallback="").strip()})
    if not any(x["role"] == "client" for x in nodes):
        raise SystemExit(f"scenario {scenario!r} has no client nodes")
    return nodes


def write_compose(scenario: str, nodes: list[dict[str, Any]], duration: int) -> None:
    """Generate compose.scenario.yml: one service per node file (JSON is valid YAML)."""
    services: dict[str, Any] = {}
    results = f"../captures/netlab/run/{scenario}"
    for n in nodes:
        net = {"fhir": {"ipv4_address": n["ip"], "mac_address": n["mac"]}}
        if n["role"] == "proxy":
            RUN_DIR.mkdir(exist_ok=True)
            (RUN_DIR / "Caddyfile").write_text(
                "{\n\tauto_https disable_redirects\n\tlocal_certs\n\tskip_install_trust\n"
                f"\tdefault_sni {n['ip']}\n}}\n\nhttps://{n['ip']} {{\n\ttls internal\n"
                f"\treverse_proxy {n['upstream']}\n}}\n", encoding="utf-8", newline="\n")
            services[n["name"]] = {
                "image": CADDY_IMAGE,
                # same host number on the back network: 10.63.0.30 -> 10.63.1.30
                "networks": {**net, "fhir-back": {"ipv4_address": "10.63.1." + n["ip"].rsplit(".", 1)[1]}},
                "volumes": ["./.run/Caddyfile:/etc/caddy/Caddyfile:ro"]}
            services[f"{n['name']}-offload"] = {
                "image": IMAGE, "network_mode": f"service:{n['name']}", "cap_add": ["NET_ADMIN"],
                "depends_on": [n["name"]], "command": ["sh", "-c", "echo offload-off"]}
            continue
        cmd = ["python", "/netlab/fhir_node.py", "--node", f"/netlab/scenari/{scenario}/{n['file']}",
               "--out", f"/results/{n['name']}.jsonl"]
        if n["role"] == "client":
            cmd += ["--duration", str(duration)]
        services[n["name"]] = {
            "image": IMAGE, "cap_add": ["NET_ADMIN"], "networks": net, "stop_grace_period": "5s",
            "volumes": ["./:/netlab:ro", f"{results}:/results"], "command": cmd,
            "labels": {"netlab.role": n["role"]}}
    GENERATED.write_text(json.dumps({"services": services}, indent=2), encoding="utf-8", newline="\n")


def docker_ok() -> None:
    if sh(["docker", "version"], check=False, quiet=True).returncode != 0:
        raise SystemExit("Docker is not running: open Docker Desktop and wait for 'Engine running'.")
    if sh(["docker", "image", "inspect", IMAGE], check=False, quiet=True).returncode != 0:
        log(f"building image {IMAGE} (once; needs internet)")
        sh(["docker", "build", "-t", IMAGE, "."], quiet=True)


def save_state(state: dict[str, Any]) -> None:
    RUN_DIR.mkdir(exist_ok=True)
    STATE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def load_state() -> dict[str, Any]:
    try:
        return json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


# ------------------------------------------------------------------ up / down
def cmd_up(scenario: str, duration: int, capture: bool = True) -> dict[str, Any]:
    docker_ok()
    if load_state() or compose("ps", "-a", "-q", check=False).stdout.strip():
        log("a previous lab is still up: stopping it first")
        cmd_down(collect=False)
    nodes = scenario_nodes(scenario)
    results = OUT / "run" / scenario
    results.mkdir(parents=True, exist_ok=True)
    for old in results.glob("*.jsonl"):
        old.unlink()
    write_compose(scenario, nodes, duration)
    state = {"scenario": scenario, "duration": duration, "started": time.time(),
             "nodes": nodes, "capture": f"{scenario}.pcap" if capture else None}
    save_state(state)  # from here on, "down" knows what to clean up even if "up" is interrupted

    log(f"scenario {scenario}: {len(nodes)} nodes, {duration} s")
    log("starting network + HAPI (first start of HAPI takes 1-2 minutes)")
    compose("up", "-d", "hapi", "hapi-offload")
    r = compose("up", "--exit-code-from", "wait-hapi", "wait-hapi", check=False, timeout=420)
    if r.returncode != 0:
        raise SystemExit("HAPI did not become ready. Check: docker compose -p fhir-netlab logs hapi")
    log("HAPI ready at http://10.63.0.10:8080/fhir")
    if capture:
        OUT.mkdir(parents=True, exist_ok=True)
        pcap = OUT / state["capture"]
        if pcap.exists():
            pcap.unlink()
        compose("--profile", "capture", "up", "-d", "capture", env={"CAPTURE_FILE": state["capture"]})
        time.sleep(1.5)
        log(f"capture on br-fhir -> captures/netlab/{state['capture']}")
    servers = [n["name"] for n in nodes if n["role"] != "client"]
    if servers:
        extra = [f"{n['name']}-offload" for n in nodes if n["role"] == "proxy"]
        compose("up", "-d", "--no-deps", *servers, *extra)
        time.sleep(2)
        log("servers up: " + ", ".join(servers))
    clients = [n["name"] for n in nodes if n["role"] == "client"]
    compose("up", "-d", "--no-deps", *clients)
    log("clients up: " + ", ".join(f"{n['name']} ({n['ip']})" for n in nodes if n["role"] == "client"))
    return state


def wait_clients(state: dict[str, Any]) -> None:
    clients = [n["name"] for n in state["nodes"] if n["role"] == "client"]
    deadline = time.time() + state["duration"] + 120
    next_note = time.time() + 60
    while time.time() < deadline:
        running = compose("ps", "--status", "running", "--services", check=False).stdout.split()
        if not any(c in running for c in clients):
            log("all clients finished")
            return
        if time.time() >= next_note:
            left = max(0, int(state["started"] + state["duration"] - time.time()))
            log(f"running... about {left} s left")
            next_note = time.time() + 60
        time.sleep(3)
    log("clients still running after the expected time: stopping them")


def merge_truth(scenario: str) -> Optional[Path]:
    rows: list[dict[str, Any]] = []
    for f in sorted((OUT / "run" / scenario).glob("*.jsonl")):
        rows += [json.loads(line) for line in f.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        return None
    rows.sort(key=lambda r: r["ts"])
    out = OUT / f"{scenario}_expected.jsonl"
    out.write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows), encoding="utf-8")
    return out


def cmd_down(collect: bool = True) -> None:
    """Stop clients, capture, servers; merge the answer keys; remove containers and networks."""
    state = load_state()
    clients = [n["name"] for n in state.get("nodes", []) if n["role"] == "client"]
    if clients:
        compose("stop", "-t", "5", *clients, check=False)
    time.sleep(2)  # let the last packets (FIN) reach the capture
    compose("--profile", "capture", "stop", "-t", "5", "capture", check=False)
    compose("--profile", "capture", "down", "-v", "--remove-orphans", "-t", "5", check=False)
    if GENERATED.exists():  # also works when the generated file is missing (interrupted start)
        GENERATED.unlink()
    # by project name only: works even if the compose files of an interrupted start are gone;
    # removing the Docker networks also removes the br-fhir / br-fhir-back bridges
    compose("down", "-v", "--remove-orphans", "-t", "5", check=False, files=False)
    if collect and state.get("scenario"):
        merged = merge_truth(state["scenario"])
        if merged:
            log(f"answer key: captures/netlab/{merged.name}")
    if STATE.exists():
        STATE.unlink()
    log("lab down")


# ------------------------------------------------------------------ run / generate / evaluate
def evaluate_scenario(scenario: str, quiet_missing: bool = False) -> Optional[dict[str, Any]]:
    pcap, expected = OUT / f"{scenario}.pcap", OUT / f"{scenario}_expected.jsonl"
    if not (pcap.is_file() and expected.is_file()):
        if not quiet_missing:
            log(f"{scenario}: no capture/answer key to evaluate")
        return None
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "lab"))
    import evaluate  # lab/evaluate.py

    rep = evaluate.evaluate_netlab(pcap, expected)
    text = evaluate.format_netlab_report(scenario, rep)
    (OUT / f"{scenario}_evaluation.txt").write_text(text, encoding="utf-8")
    print(text)
    return rep


def write_summary(reports: dict[str, dict[str, Any]]) -> None:
    sys.path.insert(0, str(ROOT / "lab"))
    import evaluate

    text = evaluate.format_netlab_summary(reports)
    (OUT / "summary.txt").write_text(text, encoding="utf-8")
    print(text)


def all_scenarios() -> list[str]:
    preferred = ["general", "ward", "laboratory", "icu"]
    found = sorted(p.name for p in SCENARI.iterdir() if p.is_dir())
    return [s for s in preferred if s in found] + [s for s in found if s not in preferred]


def cmd_run(scenario: str, duration: int, evaluate: bool = True) -> Optional[dict[str, Any]]:
    try:
        state = cmd_up(scenario, duration)
        wait_clients(state)
    finally:
        cmd_down()
    return evaluate_scenario(scenario) if evaluate else None


def cmd_generate(scenarios: list[str], duration: int) -> None:
    scenarios = scenarios or all_scenarios()
    log(f"generating {len(scenarios)} captures of {duration} s: {', '.join(scenarios)}")
    for s in scenarios:
        cmd_run(s, duration, evaluate=False)
    cmd_evaluate([])  # every scenario that has a capture, plus the summary table


def cmd_evaluate(scenarios: list[str]) -> None:
    reports = {}
    for s in scenarios or all_scenarios():
        rep = evaluate_scenario(s, quiet_missing=not scenarios)
        if rep:
            reports[s] = rep
    if reports:
        write_summary(reports)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="FHIR network lab control")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("up", "run"):
        p = sub.add_parser(name)
        p.add_argument("scenario")
        p.add_argument("--duration", type=int, default=DEFAULT_DURATION, help="client run time in seconds")
    sub.add_parser("down")
    p = sub.add_parser("generate")
    p.add_argument("scenarios", nargs="*")
    p.add_argument("--duration", type=int, default=DEFAULT_DURATION)
    p = sub.add_parser("evaluate")
    p.add_argument("scenarios", nargs="*")
    args = ap.parse_args(argv)
    if args.cmd == "up":
        cmd_up(args.scenario, args.duration)
        log("lab is up. Stop it with: python netlab/labctl.py down")
    elif args.cmd == "down":
        cmd_down()
    elif args.cmd == "run":
        cmd_run(args.scenario, args.duration)
    elif args.cmd == "generate":
        cmd_generate(args.scenarios, args.duration)
    else:
        cmd_evaluate(args.scenarios)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
