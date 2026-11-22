# HL7 FHIR Dissector

A Python module that finds **HL7 FHIR** exchanges in network traffic (live or from PCAP files) and emits one structured, privacy-preserving JSON event per HTTP request/response pair.

```
packets → TCP reassembly → HTTP/1.1 parsing → FHIR detection → FHIR classification → JSON event
```

FHIR is not a binary protocol: it is a REST API on top of HTTP, with JSON or XML *resources* (`Patient`, `Observation`, `Bundle`, …). The dissector rebuilds the HTTP conversation from TCP segments, decides whether it is FHIR (with an explainable confidence score), and labels the FHIR *interaction* (read, search, create, transaction, …).

**Status:** evaluated on an emulated hospital network (Docker, separate hosts, 1500-byte MTU): 3,762 calls from up to 6 concurrent client systems over 4 scenarios of 5 minutes, with automatic ground truth: **100% precision, 100% recall, 100% interaction accuracy**, 0 false positives (details in section 5).

---

## 1. Setup

### Windows (tested: Windows 11, Python 3.13, Docker Desktop with WSL2)

1. Install **Python 3.10+**, **Docker Desktop**, optionally **Wireshark** and **Npcap** (only for live capture on a real interface), and the VS Code **Python** extension.
2. In PowerShell, in the project folder:
   ```powershell
   py -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   pytest -q                                  # unit tests: no Docker, network or admin rights
   ```
   If PowerShell blocks `activate`, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or call `.venv\Scripts\python.exe` directly.
3. Run the network lab (see section 2); the first run builds the node image and downloads HAPI (internet needed once).

### Linux / macOS

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
pytest -q
DURATION=60 ./netlab/lab.sh generate
```

---

## 2. Usage

### The network lab (test bed)

[`netlab/`](netlab/README.md) builds a small hospital network in Docker: HAPI FHIR and several systems (EHR, laboratory, bedside monitors, clinician workstations, an intranet server and browser, an HTTPS proxy), each in its own container with its own IP and MAC on the bridge `br-fhir`. A capture container records the bridge; every client writes an answer key; the evaluator compares the dissector with it.

```powershell
.\netlab\lab.ps1 generate                 # every scenario, 5 min each, then evaluate (~28 min)
.\netlab\lab.ps1 generate -Short          # 60 s each (~10 min)
.\netlab\lab.ps1 run -Scenario icu        # one scenario
.\netlab\lab.ps1 up -Scenario ward ; .\netlab\lab.ps1 down
```
In VS Code: **Ctrl+Shift+B** → *Network lab: all scenarios* or *quick run*. Results: `captures/netlab/` (PCAP, answer key, evaluation per scenario, `summary.txt`).

### Offline (PCAP / PCAPNG)

```powershell
python -m fhir_dissector pcap captures/netlab/general.pcap -o captures/events.jsonl
python -m fhir_dissector pcap captures/netlab/general.pcap --all          # also non-FHIR HTTP (is_fhir: false)
python -m fhir_dissector pcap captures/netlab/general.pcap --no-redact    # keep search values (patient data!)
python -m fhir_dissector pcap captures/netlab/general.pcap --min-confidence 0.8
```
Without `-o`, events are printed to the terminal. A summary (packets, connections, events, FHIR events per interaction) is always printed at the end.

### Live

```powershell
python -m fhir_dissector live --iface "Ethernet" --bpf "tcp port 8080" -o captures/live.jsonl
python -m fhir_dissector live --iface "Ethernet" --bpf "tcp port 8080" --timeout 60   # stop after 60 s
```
Each event is printed as one JSON line when the response completes. Press **Ctrl+C** to stop: open connections are flushed and the summary is printed. (On Windows the network lab's bridge is inside Docker's Linux VM, so the lab is analysed from its captures.)

### Evaluation

| Command | What it does |
|---|---|
| `python lab/evaluate.py --pcap captures/netlab/icu.pcap --expected captures/netlab/icu_expected.jsonl` | network lab: per-client matching, metrics, capture statistics; exit 0 only if all match |
| `python lab/evaluate.py --pcap X.pcap --expected X.json` | single-client answer key (JSON list) |

### VS Code

- **Tasks** (*Terminal → Run Task*): *Network lab: all scenarios (5 min each)*, *Network lab: quick run (60 s each)* (both on **Ctrl+Shift+B**), *Network lab: evaluate captures*, *Network lab: stop (down)*, *Run unit tests*.
- **Debug configurations**: *Network lab: run icu (60 s)*, *Dissect a network-lab capture*, *Evaluate a network-lab capture*, *Show a node config*, *Debug current test file*.

### As a library (integration point)

```python
from fhir_dissector import FhirDissector

d = FhirDissector(redact=True, min_confidence=0.5, emit_non_fhir=False)

# Framework-agnostic: call once per TCP segment (flags in scapy letters: S, A, F, R, P).
events = d.process_tcp(ts, src_ip, sport, dst_ip, dport, "PA", seq, payload, ack=ack)  # ack is optional

# Or with scapy packets (IPv4/IPv6):
events = d.process_packet(pkt)

events += d.flush()   # end of capture / shutdown
```
The core modules do not import scapy, so any packet framework can feed `process_tcp`. The optional `ack` argument (an extension to the plan's signature) lets reassembly recover at once from bytes the capture missed.

---

## 3. Event schema

One JSON object per line (JSONL). Example (a real event from the lab, redacted by default):

```json
{
  "ts": 1795085894.194635,
  "duration_ms": 8.804,
  "flow": {"client": "[::1]:56105", "server": "[::1]:8080"},
  "fhir": {
    "is_fhir": true,
    "confidence": 1.0,
    "signals": ["content-type", "accept", "xml-namespace", "path-resource", "path-fhir"],
    "version": "4.0.1",
    "base": "/fhir",
    "interaction": "read",
    "resource_type": "Patient",
    "resource_id": "1005",
    "version_id": null,
    "operation": null,
    "search_params": []
  },
  "request": {"method": "GET", "path": "/fhir/Patient/1005", "content_type": null, "body_size": 0,
              "auth": {"bearer_present": false, "scheme": null}, "resource_type": null, "bundle": null},
  "response": {"status": 200, "content_type": "application/fhir+xml;charset=UTF-8", "body_size": 213,
               "resource_type": "Patient", "bundle": null, "outcome_issues": []},
  "errors": []
}
```

| Field | Meaning |
|---|---|
| `ts`, `duration_ms` | first byte of the request; time until the last byte of the response |
| `flow` | client and server `ip:port` (`[ip]:port` for IPv6) |
| `fhir.confidence`, `fhir.signals` | detection score (0–1) and the clues that fired |
| `fhir.version` | from `fhirVersion=` in Content-Type or the server's CapabilityStatement (remembered per server) |
| `fhir.interaction` | `capabilities`, `read`, `vread`, `update`, `patch`, `delete`, `create`, `search-type`, `search-system`, `search-compartment`, `history-instance/type/system`, `batch`, `transaction`, `batch/transaction`, `operation`, `conditional-update/patch/delete`, `unknown` |
| `fhir.compartment` | only for `search-compartment` (e.g. `Patient/1`) |
| `request.bundle` / `response.bundle` | `{type, total, entry_count, entry_types, request_methods}` |
| `response.outcome_issues` | OperationOutcome `[{severity, code}]` |
| `errors` | e.g. `gap`, `truncated`, `incomplete-message-at-close`, `response-without-request`, `decompress-failed` |
| `response` | `null` if the connection ended before a response was seen |

**Redaction (default on).** Search parameters keep **names only** (`family`, not `family=Rossi`). `request.path` has no query string. Authorization tokens are never stored (only `bearer_present` / `scheme`). Resource contents (names, birth dates, identifiers, addresses, free text) are never copied. OperationOutcome `diagnostics` text is dropped. `--no-redact` keeps search values and diagnostics only; tokens and resource contents are never output.

---

## 4. Design overview

| Module | Role |
|---|---|
| `fhir_dissector/reassembly.py` | Tracks TCP connections. Client = sender of SYN, or the side whose first payload starts with an HTTP method. Per direction: unwrapped sequence offsets (handles 2³² wrap-around), in-order delivery, trimming of retransmissions/overlaps, buffering of out-of-order segments. **Gap recovery**: if the peer ACKs bytes that were never captured, or more than 1000 segments / 4 MB are buffered, or at close, the hole is skipped and the HTTP parser resyncs. Requests wait in a FIFO and each response pops the oldest. Idle timeout of 120 s. |
| `fhir_dissector/http_parser.py` | Incremental HTTP/1.1 state machine (`HEADERS → LENGTH / CHUNKED / UNTIL_CLOSE / NONE`). Handles chunked transfer and trailers, gzip/deflate, HEAD/204/304 (no body), 1xx (skipped), 101 (stop), until-close bodies, pipelining, 64 KB header cap, 10 MB body cap (`truncated`). Resyncs on garbage. After a gap it returns the *partial* message so pairing stays correct. |
| `fhir_dissector/detector.py` | Weighted signals (content type 0.6, `resourceType` in JSON 0.5, FHIR XML namespace 0.5, Accept 0.4, `_format` 0.3, resource-type path segment 0.3, `/metadata` 0.3, `/fhir` in path 0.2), capped at 1.0. FHIR if ≥ `min_confidence` (0.5). |
| `fhir_dissector/classifier.py` | Segment-based URL analysis with the full R4+R5 resource list. Finds the base (`/fhir`), then maps the remaining segments and the method to the interaction (plan §5.4 table). |
| `fhir_dissector/body.py` | JSON/XML metadata summary. Never fails. |
| `fhir_dissector/events.py` | Event assembly and redaction. |
| `fhir_dissector/dissector.py` | `FhirDissector`: `process_tcp`, `process_packet`, `flush`. Fails soft. |
| `fhir_dissector/cli.py` | `pcap` (streaming `PcapReader`) and `live` (`sniff`) subcommands, sharing the same code path. |

**Capture detail.** Reading and live capture use a 262,144-byte limit (*snaplen*), not scapy's default 65,535: on loopback interfaces TCP segments can reach ~65 KB, and 4 bytes per frame were silently cut in an early test. On a normal network (and in the network lab) frames are at most 1514 bytes.

---

## 5. Results

**Network lab** (`netlab/`, Docker Desktop on Windows 11): HAPI FHIR 8.12.0 (R4) and up to 6 concurrent client systems, each its own host (own IP and MAC) on one bridge, MTU 1500 with TCP offload off; 4 scenarios × 5 minutes; answer keys written by the clients themselves.

| Scenario | Calls | Encrypted | TP | FP | FN | TN | Precision | Recall | Interaction acc. | Resource-type acc. | Max frame | TCP conns |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| general (6 clients) | 1,080 | 135 | 796 | 0 | 0 | 149 | 100% | 100% | 100% | 100% | 1514 | 173 |
| ward (4 clients) | 683 | 0 | 504 | 0 | 0 | 179 | 100% | 100% | 100% | 100% | 1514 | 185 |
| laboratory (2 clients) | 437 | 0 | 437 | 0 | 0 | 0 | 100% | 100% | 100% | 100% | 1514 | 299 |
| icu (3 clients) | 1,562 | 0 | 1,562 | 0 | 0 | 0 | 100% | 100% | 100% | 100% | 1514 | 17 |
| **total** | **3,762** | **135** | **3,299** | **0** | **0** | **328** | **100%** | **100%** | **100%** | **100%** | | |

The traffic covers 11 FHIR interaction types (create, read, vread, update, delete, search-type incl. POST `_search`, search-compartment, history-instance, transaction, batch, operation `$everything`), JSON and XML, gzip on/off, keep-alive and one-connection-per-request clients, statuses 200/201/400/404/410, and 328 non-FHIR intranet requests on the same network. Large messages were split into up to 356 TCP segments. The 135 HTTPS calls through the TLS proxy are invisible to the dissector, as expected (0 events), and are reported separately. Details and capture table: [captures/netlab/README.md](captures/netlab/README.md).

**Robustness and performance** (one CPU core, Windows 11 laptop, Python 3.13):

| Check | Result |
|---|---|
| Unit tests (`pytest`) | 192 pass: chunked splits at every byte, gzip, HEAD/1xx/204/304/101, shuffled/duplicated/lost segments, missing handshake, IPv6, sequence wrap-around, node configuration, evaluator matching |
| 100,000 random garbage TCP segments | 0 crashes, 0 internal errors |
| Speed on the lab captures | 1,500–4,400 events/s, 35,000–89,000 packets/s |
| Memory: 20,000 never-closing connections | capped by `--max-connections` (default 10,000, least-recently-active evicted) |

---

## 6. Deployment (live use)

### Is it ready?

| Area | Status |
|---|---|
| Correctness on plaintext HTTP/1.1 FHIR | ready: 100% on a live HAPI server and on a recorded capture |
| Robustness (garbage, loss, reordering) | ready: fails soft, fuzz-tested |
| Privacy | ready: redaction on by default; no tokens or resource contents ever written |
| Resource limits | ready: connections, request queue, body size, header size, out-of-order buffer are all capped |
| Throughput | fine for one or a few FHIR servers (thousands of packets/s); **not** for multi-Gbit/s core links (single Python process) |
| **HTTPS / TLS** | **not supported**: encrypted FHIR traffic is invisible (see below) |
| HTTP/2, WebSocket subscriptions | not supported |

### Where to capture

The dissector only understands **plaintext** HTTP. In practice FHIR is usually served over HTTPS, so capture where the traffic is plaintext:
- **behind the TLS terminator**: between a reverse proxy / load balancer / API gateway and the FHIR server, or on the FHIR server host itself if it listens on HTTP behind the proxy;
- on an internal integration network that uses plain HTTP;
- from a **mirror / SPAN port** of a switch on such a segment (a passive copy of the traffic, which is safest: nothing on the path changes).

Always use a BPF filter for the FHIR port(s), e.g. `--bpf "tcp port 8080"`, so that only relevant packets are processed.

### Install on the monitoring machine

```powershell
pip install .                      # from the project folder; gives the command `fhir-dissector`
fhir-dissector live --iface "Ethernet 2" --bpf "tcp port 8080" -o C:\fhir\events.jsonl --quiet
```
On Windows, Npcap is required. On Linux/macOS run as root, or give Python the `cap_net_raw,cap_net_admin` capabilities.

### Recommended options for long-running use

| Option | Default | Advice |
|---|---|---|
| `-o FILE` | none | always set; live mode **appends**, so a restart keeps old events |
| `--quiet` | off | set when running as a service (no screen output) |
| `--bpf` | `tcp` | restrict to the FHIR server's port(s) |
| `--max-connections` | 10,000 | raise for very busy servers; a WARNING at exit shows evictions |
| `--max-body` | 10 MB | lower (e.g. 2 MB) to save memory; only metadata is needed, but large Bundles need a full body to be summarised |
| `--idle-timeout` | 120 s | connections silent for this long are closed and their pending requests emitted |

### Run as a service

**Linux (systemd)**, file `/etc/systemd/system/fhir-dissector.service`:
```ini
[Unit]
Description=HL7 FHIR dissector
After=network-online.target

[Service]
ExecStart=/opt/fhir-dissector/.venv/bin/fhir-dissector live --iface eth1 --bpf "tcp port 8080" -o /var/log/fhir/events.jsonl --quiet
Restart=on-failure
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```
`systemctl stop` sends SIGTERM; the dissector then flushes open connections and writes its summary before exiting.

**Windows**: run the same command at start-up with Task Scheduler (*Create Task → Run whether user is logged on or not → Run with highest privileges*; trigger *At startup*; action: the `fhir-dissector.exe` path from the venv with the arguments above), or wrap it as a service with a service wrapper such as NSSM.

**Log rotation**: the events file grows (about 0.8 KB per event). Rotate it with `logrotate` (Linux, `copytruncate`) or a scheduled task that renames the file; the dissector re-creates it on restart.

### Privacy and compliance checklist

- Keep redaction **on** (never use `--no-redact` in production).
- Events still contain IP addresses, resource ids and timestamps, which can be personal data in combination: store the events file with access control, and define a retention period with the data protection officer.
- Do not store the PCAP files in production; the live mode does not write packets to disk.

---

## 7. Limitations

- **No TLS**: only plaintext HTTP. Real deployments use HTTPS.
- **No HTTP/2**, and no FHIR Subscriptions over WebSocket (the parser stops at `101 Switching Protocols`).
- **HTTP/1.1 only**, with responses matched to requests in FIFO order.
- **No profile validation**: the dissector recognises FHIR; it does not check that resources are valid.
- **Tested against one server implementation** (HAPI FHIR R4) on an emulated network: separate hosts and realistic packet sizes, but no packet loss, reordering or latency (those cases are covered by the unit tests) and no real hospital traffic. The workflows and their rates are designed, not measured.
- 3,762 calls in 20 minutes of traffic: correctness on the covered interactions, not performance at scale.
- XML support is basic (resource type, id, meta, Bundle, OperationOutcome, CapabilityStatement).
- Detection is heuristic: a non-FHIR API using FHIR-like paths *and* a `resourceType` field would be counted as FHIR.

## 8. Future work

- TLS decryption with key log files (`SSLKEYLOGFILE`) or integration with a TLS-terminating proxy.
- HTTP/2 (HPACK, streams) and WebSocket subscriptions.
- HL7 v2 over MLLP as a sibling module.
- Optional profile validation (e.g. US Core / IPS) and SMART-on-FHIR (OAuth) flow detection.
- Performance tuning and benchmarks on large captures; tests against other servers (Firely, Microsoft FHIR, IBM LinuxForHealth).
- Larger, more varied traffic generation (more resource types, PATCH, conditional operations, paging).

---

## Project layout

```
fhir_dissector/   core package (http_parser, reassembly, detector, classifier, body, events, dissector, cli)
netlab/           the emulated hospital network: fhir_node.py, scenari/, docker-compose.yml, labctl.py, lab.ps1/lab.sh
lab/              evaluate.py (answer key vs. dissector events)
tests/            unit tests (pytest) + pcap_builder.py (synthetic packets)
captures/netlab/  one PCAP + answer key + evaluation per scenario, summary.txt
docs/             TESTING_GUIDE.md, REPORT_SUMMARY.md, LEARNING_NOTES.md, PDFs
.vscode/          settings, tasks, launch configurations, recommended extensions
```

See also: [docs/FHIR_Dissector_Visual_Guide.pdf](docs/FHIR_Dissector_Visual_Guide.pdf) (13-page visual guide with diagrams), [docs/TESTING_GUIDE.md](docs/TESTING_GUIDE.md) (network lab, step by step), [docs/REPORT_SUMMARY.md](docs/REPORT_SUMMARY.md) (one-page summary for a report), [docs/LEARNING_NOTES.md](docs/LEARNING_NOTES.md) (what we did and why), [FHIR_DISSECTOR_PLAN.md](FHIR_DISSECTOR_PLAN.md) (original plan).
