# HL7 FHIR Dissector

A Python module that finds **HL7 FHIR** exchanges in network traffic (live or from PCAP files) and emits one structured, privacy-preserving JSON event per HTTP request/response pair.

```
packets → TCP reassembly → HTTP/1.1 parsing → FHIR detection → FHIR classification → JSON event
```

FHIR is not a binary protocol: it is a REST API on top of HTTP, with JSON or XML *resources* (`Patient`, `Observation`, `Bundle`, …). The dissector rebuilds the HTTP conversation from TCP segments, decides whether it is FHIR (with an explainable confidence score), and labels the FHIR *interaction* (read, search, create, transaction, …).

**Status:** all items of the plan's definition of done are met. 139 automated tests pass. On a real capture against HAPI FHIR, both offline and live: **100% precision, 100% recall, 100% interaction accuracy**, with 0 false positives.

---

## 1. Setup

### Windows (tested: Windows 11, Python 3.13, Docker Desktop, Npcap)

1. Install **Python 3.10+**, **Docker Desktop**, **Npcap** (tick *"Support loopback traffic"*), optionally **Wireshark**, and the VS Code **Python** extension.
2. In PowerShell, in the project folder:
   ```powershell
   py -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   ```
   If PowerShell blocks `activate`, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or call `.venv\Scripts\python.exe` directly.
3. Start the FHIR server (the first start downloads the image and takes 1–2 minutes):
   ```powershell
   docker compose up -d
   curl.exe http://localhost:8080/fhir/metadata      # JSON CapabilityStatement = ready
   ```
4. Run the tests: `pytest` (no Docker, network or admin rights needed).

**Capture rights on Windows:** if Npcap was installed with *"Restrict Npcap driver's access to Administrators only"*, run the terminal **as Administrator** for `run_scenario.py` and `live`. On the development PC this option was off, so capture worked as a normal user.

### Linux / macOS

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
docker compose up -d
pytest
sudo .venv/bin/python lab/run_scenario.py --out captures/lab.pcap      # capture needs root
```
The loopback interface is `lo` (Linux) or `lo0` (macOS), chosen automatically.

### Without Docker (fallback)

```powershell
python lab/mock_fhir_server.py --port 8081           # terminal 1
python lab/run_scenario.py --base http://localhost:8081/fhir --port 8081 --out captures/mock_lab.pcap --expected captures/mock_expected.json
```

---

## 2. Usage

### Offline (PCAP / PCAPNG)

```powershell
python -m fhir_dissector pcap captures/lab.pcap -o captures/events.jsonl
python -m fhir_dissector pcap captures/lab.pcap --all              # also non-FHIR HTTP (is_fhir: false)
python -m fhir_dissector pcap captures/lab.pcap --no-redact        # keep search values (patient data!)
python -m fhir_dissector pcap captures/lab.pcap --min-confidence 0.8
```
Without `-o`, events are printed to the terminal. A summary (packets, connections, events, FHIR events per interaction) is always printed at the end.

### Live

```powershell
python -m fhir_dissector live --bpf "tcp port 8080"                       # loopback by default
python -m fhir_dissector live --iface "Ethernet" --bpf "tcp port 80" -o captures/live.jsonl
python -m fhir_dissector live --bpf "tcp port 8080" --timeout 60          # stop after 60 s
```
Each event is printed as one JSON line when the response completes. Press **Ctrl+C** to stop: open connections are flushed and the summary is printed.

### Lab

| Command | What it does |
|---|---|
| `python lab/gen_traffic.py --base http://localhost:8080/fhir --out captures/expected.json` | 19 scripted calls (17 FHIR + 2 non-FHIR); writes the ground truth |
| `python lab/run_scenario.py --base http://localhost:8080/fhir --port 8080 --out captures/lab.pcap` | capture → traffic → save PCAP + `expected.json` |
| `python lab/evaluate.py --pcap captures/lab.pcap --expected captures/expected.json` | table + precision / recall / accuracy; exit 0 only if all match |
| `python lab/evaluate.py --events captures/live_events.jsonl --expected captures/live_expected.json` | evaluate events from a live run (use `live --all`) |

### VS Code

- **Tasks** (*Terminal → Run Task*): `Start HAPI`, `Stop HAPI`, `Run tests`, `Run scenario`, `Dissect lab PCAP`, `Evaluate`.
- **Debug configurations** (*Run and Debug*): *Dissect lab PCAP*, *Live capture (needs admin)*, *Mock FHIR server*, *Generate traffic*, *Evaluate*, *Debug current test file*.

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

**Capture detail (loopback).** On loopback, TCP segments can reach ~65,475 data bytes, so frames are 65,539 bytes: bigger than scapy's default 65,535-byte capture and read limit (*snaplen*). The tools raise the limit to 262,144 when capturing, writing and reading. Without this, 4 bytes per large frame are lost; the dissector would still pair correctly, but it would flag `gap`.

---

## 5. Test results

**Unit, integration and end-to-end tests:** `pytest` → **139 passed** (no Docker, network or admin rights).

| File | Tests | Covers |
|---|---|---|
| `test_http_parser.py` | 25 | Content-Length, chunked split at **every byte boundary**, gzip/deflate, HEAD, 204/304, 1xx, 101, until-close, pipelining, oversized headers, random garbage, body cap, gaps |
| `test_reassembly.py` | 37 | in-order, **shuffled** (10 seeds), **retransmissions + overlaps** (10 seeds), both combined, **missing handshake**, **IPv6**, sequence wrap-around, no FIN, HEAD pairing, two connections, gaps with/without ACK info, RST |
| `test_classifier.py` | 39 | every row of the interaction table, base detection, operations, compartments, form search, percent-encoding |
| `test_detector.py` | 20 | each signal weight, non-FHIR cases, threshold, version, redaction, `--all`, IPv6 via scapy |
| `test_body.py` | 10 | Patient/Bundle/OperationOutcome/CapabilityStatement in JSON and XML, never fails |
| `test_end_to_end.py` | 8 | synthetic PCAP → CLI (clean, shuffled+retransmitted, IPv6 mid-stream), evaluator, real lab capture |

**Lab evaluation** (HAPI FHIR 8.12.0, FHIR R4 4.0.1, Docker; IPv6 loopback; gzip + chunked responses):

| Run | Calls | TP | FP | FN | TN | Precision | Recall | Interaction accuracy | Resource-type accuracy |
|---|---|---|---|---|---|---|---|---|---|
| Offline (`captures/lab.pcap`, 268 packets) | 19 | 17 | 0 | 0 | 2 | **100%** | **100%** | **100%** | **100%** |
| Live capture (260 packets) | 19 | 17 | 0 | 0 | 2 | **100%** | **100%** | **100%** | **100%** |
| Mock server (fallback) | 19 | 17 | 0 | 0 | 2 | 100% | 100% | 100% | 100% |

Interactions covered by the lab: capabilities, create ×3, read ×4 (JSON, XML, 410 Gone, 404), update, history-instance, vread, search-type (GET and POST `_search`), transaction, batch, operation (`$everything`), delete. Non-FHIR: the HAPI HTML home page (1.78 MB) and `/favicon.ico`. Full tables: `captures/evaluation_lab.txt`, `captures/evaluation_live.txt`.

---

## 6. Limitations

- **No TLS**: only plaintext HTTP. Real deployments use HTTPS.
- **No HTTP/2**, and no FHIR Subscriptions over WebSocket (the parser stops at `101 Switching Protocols`).
- **HTTP/1.1 only**, with responses matched to requests in FIFO order.
- **No profile validation**: the dissector recognises FHIR; it does not check that resources are valid.
- **Tested against HAPI FHIR (R4) only**, plus a mock server, in a lab on loopback; no real hospital traffic.
- Small lab dataset (19 calls per run). Results show correctness on the covered interactions, not performance at scale.
- XML support is basic (resource type, id, meta, Bundle, OperationOutcome, CapabilityStatement).
- Detection is heuristic: a non-FHIR API using FHIR-like paths *and* a `resourceType` field would be counted as FHIR.

## 7. Future work

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
lab/              mock_fhir_server.py, gen_traffic.py, run_scenario.py, evaluate.py
tests/            pcap_builder.py (synthetic packets) + 6 test files
captures/         lab.pcap, expected.json, events.jsonl, evaluation reports (PCAP/JSONL git-ignored)
docs/             TESTING_GUIDE.md, REPORT_SUMMARY.md, LEARNING_NOTES.md
.vscode/          settings, tasks, launch configurations, recommended extensions
```

See also: [docs/TESTING_GUIDE.md](docs/TESTING_GUIDE.md) (hands-on testing from zero), [docs/REPORT_SUMMARY.md](docs/REPORT_SUMMARY.md) (one-page summary for a report), [docs/LEARNING_NOTES.md](docs/LEARNING_NOTES.md) (what we did and why), [FHIR_DISSECTOR_PLAN.md](FHIR_DISSECTOR_PLAN.md) (original plan).
