# HL7 FHIR Dissector — 3-Day MVP Plan

This file is the single source of truth for building an HL7 FHIR protocol module for a modular Python network protocol dissector. It is written so that Claude (Claude Code in VS Code) can execute it phase by phase, and so that a human knows exactly which steps they must do themselves.

**How to use this file with Claude in VS Code**

1. Put this file in the root of the repository (the existing dissector repo, or a new empty folder).
2. Open the folder in VS Code and start Claude Code.
3. Work one phase at a time. Paste the prompt given at the start of each phase, e.g. `Read FHIR_DISSECTOR_PLAN.md and do Phase 1.`
4. After each phase, check the acceptance criteria yourself before moving on. Commit to git after each phase.
5. Steps marked **👤 HUMAN** must be done by you (installing software, running with admin rights, checking results).

---

## 1. Context

- **FHIR is not a binary wire protocol.** It is a REST API convention on top of HTTP(S). Payloads are JSON or XML "resources" (Patient, Observation, Bundle, OperationOutcome, ...).
- So the dissector pipeline is: **packets → TCP reassembly → HTTP/1.1 parsing → FHIR detection → FHIR classification → structured event.**
- Not to be confused with **HL7 v2** (pipe-delimited `MSH|^~\&|` messages over MLLP/TCP). HL7 v2 is out of scope.
- No real hospital network is available, so traffic is generated locally with a FHIR server (HAPI FHIR in Docker) and a scripted client.

## 2. Aim and scope

**Aim:** detect HL7 FHIR exchanges in live traffic and in PCAP files, and emit one structured JSON event per request/response pair.

**In scope (MVP):**

- Plaintext HTTP/1.1 (no TLS).
- JSON bodies (required) and XML bodies (basic: resource type, id, bundle type).
- Interactions: capabilities, read, vread, search (type, system, `_search`), create, update, patch, delete, history (instance/type/system), batch/transaction, operations (`$name`).
- Offline PCAP mode and live capture mode sharing one code path.
- `Content-Encoding: gzip/deflate` and `Transfer-Encoding: chunked`.
- Keep-alive connections with several requests per connection.
- Out-of-order and retransmitted TCP segments.
- Privacy-preserving output (redaction on by default).

**Out of scope (document as future work):** TLS decryption, HTTP/2, FHIR subscriptions over WebSocket, full profile validation, HL7 v2/MLLP, performance tuning.

## 3. Technical constraints

- Python **3.10+**.
- Runtime dependency: `scapy` (packet reading, live sniffing, PCAP writing). No tshark/pyshark dependency.
- Lab/test dependencies: `requests`, `pytest`.
- Use only the standard library for HTTP parsing, JSON, XML (`xml.etree.ElementTree`; use `defusedxml` if installed), and compression (`zlib`).
- The FHIR module must not crash on malformed, truncated, or non-FHIR traffic. Every parse step fails soft.
- Keep the core logic **independent of scapy**, so it can be plugged into the existing dissector framework (see §5.3).

## 4. Project layout (target)

```
.
├── FHIR_DISSECTOR_PLAN.md          # this file
├── README.md                       # setup + usage (generated in Phase 6)
├── requirements.txt                # scapy, requests, pytest
├── docker-compose.yml              # HAPI FHIR server
├── .gitignore                      # .venv, __pycache__, captures/*.pcap
├── .vscode/
│   ├── settings.json               # pytest enabled, .venv interpreter
│   ├── launch.json                 # debug configs (see §9)
│   ├── tasks.json                  # one-click tasks (see §9)
│   └── extensions.json             # ms-python.python, ms-azuretools.vscode-docker
├── fhir_dissector/
│   ├── __init__.py                 # exports FhirDissector
│   ├── __main__.py                 # enables `python -m fhir_dissector`
│   ├── http_parser.py              # incremental HTTP/1.1 parser
│   ├── reassembly.py               # TCP stream reassembly + connection tracking
│   ├── detector.py                 # "is this FHIR?" scoring
│   ├── classifier.py               # URL/method -> FHIR interaction
│   ├── body.py                     # JSON/XML body summarizer
│   ├── events.py                   # event building + redaction
│   ├── dissector.py                # FhirDissector: public entry point
│   └── cli.py                      # `pcap` and `live` subcommands
├── lab/
│   ├── mock_fhir_server.py         # tiny in-memory FHIR server (fallback if Docker fails)
│   ├── gen_traffic.py              # scripted FHIR + non-FHIR traffic, writes expected.json
│   ├── run_scenario.py             # start capture -> run traffic -> stop capture
│   └── evaluate.py                 # compare dissector output with expected.json
├── tests/
│   ├── pcap_builder.py             # build synthetic TCP/HTTP PCAPs with scapy
│   ├── test_http_parser.py
│   ├── test_reassembly.py
│   ├── test_classifier.py
│   ├── test_detector.py
│   ├── test_body.py
│   └── test_end_to_end.py          # synthetic PCAP -> events; real capture if present
└── captures/                       # PCAPs, expected.json, events.jsonl (git-ignored)
```

If working **inside the existing dissector repo**, place `fhir_dissector/` where the framework expects protocol modules and adapt names to its conventions (see Phase 0).

## 5. Design

### 5.1 HTTP/1.1 parser (`http_parser.py`)

Incremental state machine, one instance per direction of a connection.

- `feed(data: bytes, ts: float) -> list[HttpMessage]`, and `close() -> list[HttpMessage]` for end-of-stream.
- `HttpMessage` fields: `kind` (`request`/`response`), `method`, `target` (path + query), `status`, `reason`, `version`, `headers` (dict, lower-case keys; keep multi-values joined with `, `), `body` (decoded bytes), `body_size`, `truncated` (bool), `errors` (list of strings), `ts` (timestamp of first byte).
- States: `HEADERS` → one of `LENGTH(n)`, `CHUNKED`, `UNTIL_CLOSE`, `NONE` → back to `HEADERS`.
- Body rules:
  - Request: `Transfer-Encoding: chunked` → chunked; else `Content-Length`; else no body.
  - Response: `1xx` (except 101) → no body, do not emit, continue; `101` → stop parsing this connection; response to `HEAD`, `204`, `304` → no body; chunked; `Content-Length`; otherwise read until connection close.
  - The response parser needs the method of the matching request (for HEAD). Provide it via a callback from the connection.
- Decompression: `gzip`/`deflate` via `zlib.decompressobj(wbits=47)`; on failure keep raw body and add an error.
- Limits: header block max 64 KB (on overflow: record error, discard buffer, resync on next line that looks like a request/status line). Stored body max 10 MB (configurable); beyond that keep consuming but set `truncated=True` and stop storing.

### 5.2 TCP reassembly (`reassembly.py`)

- Connection key: `(client_ip, client_port, server_ip, server_port)`.
- **Client detection:** sender of SYN without ACK. If the handshake was not captured: the side whose first payload starts with an HTTP method (`GET `, `POST `, `PUT `, `PATCH `, `DELETE `, `HEAD `, `OPTIONS `) is the client.
- Per direction: track initial sequence number; use offsets relative to it modulo 2³²; deliver data in order; trim retransmitted overlap; buffer out-of-order segments.
- Gap handling: if more than 1,000 out-of-order segments are buffered (or 4 MB), skip to the lowest buffered offset, reset that direction's HTTP parser, record a `gap` error.
- Pairing: each connection keeps a FIFO queue of parsed requests; each parsed response pops the oldest request.
- End of connection: on FIN/RST from both sides or RST, call `close()` on both parsers, then emit any requests left without a response (`response = null`).
- Live mode: idle timeout (default 120 s) to flush and drop stale connections; check every N packets.

### 5.3 Public API (`dissector.py`) — the integration point

```python
class FhirDissector:
    def __init__(self, redact: bool = True, min_confidence: float = 0.5,
                 emit_non_fhir: bool = False, max_body: int = 10_000_000): ...

    # Framework-agnostic entry point. Use this to plug into the existing dissector.
    def process_tcp(self, ts: float, src: str, sport: int, dst: str, dport: int,
                    flags: str, seq: int, payload: bytes) -> list[dict]: ...

    # Convenience wrapper for scapy packets (IPv4 and IPv6).
    def process_packet(self, pkt) -> list[dict]: ...

    # Flush all open connections (end of PCAP, shutdown).
    def flush(self) -> list[dict]: ...
```

`flags` uses scapy-style letters (`S`, `A`, `F`, `R`, `P`).

### 5.4 Classifier (`classifier.py`)

Segment-based, not one big regex.

1. Strip query; split path into segments.
2. Find the first segment that is either a known FHIR resource type (include the full R4/R5 resource list as a constant), or matches `^[A-Z][A-Za-z]+$`, or equals `metadata`, `_history`, or starts with `$`. Segments before it are the **base** (e.g. `/fhir`).
3. Map the rest:

| Remaining segments | Method | Interaction |
|---|---|---|
| *(empty)* | POST | `batch` or `transaction` (decided from request Bundle `type`; default `batch/transaction`) |
| *(empty)* | GET with query | `search-system` |
| `metadata` | GET | `capabilities` |
| `_history` | GET | `history-system` |
| `$op` | any | `operation` (level `system`) |
| `Type` | GET | `search-type` |
| `Type` | POST | `create` |
| `Type` | PUT / PATCH / DELETE | `conditional-update` / `conditional-patch` / `conditional-delete` |
| `Type/_search` | POST | `search-type` |
| `Type/_history` | GET | `history-type` |
| `Type/$op` | any | `operation` (level `type`) |
| `Type/id` | GET / PUT / PATCH / DELETE | `read` / `update` / `patch` / `delete` |
| `Type/id/_history` | GET | `history-instance` |
| `Type/id/_history/vid` | GET | `vread` |
| `Type/id/$op` | any | `operation` (level `instance`) |
| `Type/id/Type2` | GET | `search-compartment` |
| anything else | — | `unknown` |

Return: `interaction`, `resource_type`, `resource_id`, `version_id`, `operation`, `base`, `search_param_names`.

### 5.5 Detector (`detector.py`)

Score the request/response pair; cap at 1.0; FHIR if `score >= min_confidence` (default 0.5). Return the score and the list of signals that fired (for explainability).

| Signal | Weight |
|---|---|
| `Content-Type` of request or response contains `application/fhir+json` or `application/fhir+xml` | 0.6 |
| `Accept` header contains `fhir+` | 0.4 |
| JSON body has top-level `resourceType` | 0.5 |
| XML root in namespace `http://hl7.org/fhir` | 0.5 |
| `_format` query param is `json`, `xml`, or a fhir media type | 0.3 |
| Path contains a known FHIR resource type segment | 0.3 |
| Path ends with `/metadata` | 0.3 |
| Path contains `/fhir/` or ends with `/fhir` | 0.2 |

FHIR version: `fhirVersion=` parameter in Content-Type, or `fhirVersion` field of a CapabilityStatement response.

### 5.6 Body summarizer (`body.py`)

Never fail; return `{}` on any error. Extract:

- `resource_type`, `id`, `meta.versionId`, `meta.lastUpdated`
- Bundle: `type`, `total`, `entry_count`, list of entry resource types with counts, request methods in transaction/batch entries
- OperationOutcome: list of `{severity, code}` (do **not** copy `diagnostics` text unless redaction is off)
- CapabilityStatement: `fhirVersion`, `software.name`
- Format: `json` or `xml`

### 5.7 Event schema (`events.py`)

One JSON object per line (JSONL):

```json
{
  "ts": 1763550000.123,
  "duration_ms": 12.4,
  "flow": {"client": "127.0.0.1:51544", "server": "127.0.0.1:8080"},
  "fhir": {
    "is_fhir": true,
    "confidence": 0.9,
    "signals": ["content-type", "resourceType-body", "path-resource"],
    "version": "4.0.1",
    "base": "/fhir",
    "interaction": "read",
    "resource_type": "Patient",
    "resource_id": "123",
    "version_id": null,
    "operation": null,
    "search_params": ["family", "_count"]
  },
  "request": {"method": "GET", "path": "/fhir/Patient/123", "content_type": null,
              "body_size": 0, "auth": {"bearer_present": false}},
  "response": {"status": 200, "content_type": "application/fhir+json;charset=UTF-8",
               "body_size": 812, "resource_type": "Patient", "bundle": null,
               "outcome_issues": []},
  "errors": []
}
```

**Redaction (default on):**

- Search parameters: keep **names only**, drop values (values like `name=Rossi` are patient data). With `--no-redact`, keep values.
- Never store the Authorization token; only `bearer_present`.
- Never copy resource contents (names, birth dates, identifiers, addresses, free text). Only the metadata listed in §5.6.
- The `path` field: query string removed when redacting.

### 5.8 CLI (`cli.py`)

```
python -m fhir_dissector pcap captures/lab.pcap -o captures/events.jsonl [--no-redact] [--all] [--min-confidence 0.5]
python -m fhir_dissector live --iface <iface> [--bpf "tcp port 8080"] [-o events.jsonl] [--no-redact]
```

- `pcap`: read with `scapy.utils.PcapReader` (streaming, not `rdpcap`), call `flush()` at the end, print a summary (packets, connections, events, FHIR events by interaction).
- `live`: `scapy.sendrecv.sniff(..., store=False, prn=...)`; default iface `scapy.config.conf.loopback_name`; print each event as one line; flush on Ctrl+C.
- `--all` also emits non-FHIR HTTP events (with `is_fhir: false`), useful for evaluation.

## 6. Local FHIR lab

### 6.1 HAPI FHIR server (`docker-compose.yml`)

```yaml
services:
  hapi:
    image: hapiproject/hapi:latest
    ports:
      - "8080:8080"
```

- Base URL: `http://localhost:8080/fhir`. Health check: `http://localhost:8080/fhir/metadata`.
- First start can take 1–2 minutes.

### 6.2 Mock server (`lab/mock_fhir_server.py`) — fallback

Standard-library `http.server.ThreadingHTTPServer`, `protocol_version = "HTTP/1.1"` (keep-alive), in-memory store. Supports exactly what `gen_traffic.py` uses: `/fhir/metadata`, create/read/vread/update/delete/history on any type, search by type with simple params, POST Bundle (transaction/batch), `$everything` on Patient, JSON and XML (`Accept: application/fhir+xml` → minimal XML), 404/410 with OperationOutcome, HTML page at `/` (non-FHIR). Port configurable (default 8081). Used when Docker is unavailable and in CI-style end-to-end tests.

### 6.3 Traffic generator (`lab/gen_traffic.py`)

`python lab/gen_traffic.py --base http://localhost:8080/fhir --out captures/expected.json`

Uses one `requests.Session` (keep-alive) for FHIR calls plus a separate plain session for non-FHIR calls. All bodies use `Content-Type: application/fhir+json`. Scenario order:

1. `GET /metadata`
2. `POST Patient` ×2 (synthetic names, e.g. "Mario Rossi", "Giulia Bianchi")
3. `GET Patient/{id}` (read)
4. `GET Patient/{id}` with `Accept: application/fhir+xml` (XML read)
5. `PUT Patient/{id}` (update)
6. `GET Patient/{id}/_history` and `GET Patient/{id}/_history/1` (history, vread)
7. `GET Patient?family=Rossi&_count=5` (search-type)
8. `POST Patient/_search` with form body `family=Rossi` (search-type via POST)
9. `POST Observation` referencing the patient (create)
10. `POST [base]` transaction Bundle with a Patient + Observation using `urn:uuid` references
11. `POST [base]` batch Bundle with two GET entries
12. `GET Patient/{id}/$everything` (operation)
13. `DELETE Observation/{id}` then `GET Observation/{id}` (expect 410 or 404 + OperationOutcome)
14. `GET Patient/does-not-exist-999` (404)
15. Non-FHIR: `GET /` (HTML UI) and `GET /favicon.ico` or another non-FHIR path on the same host

For every call, append to `expected.json`: `{index, method, path (without host), expected_interaction, expected_resource_type, is_fhir, actual_status}`. The `actual_status` comes from what the client really received, so the file is ground truth independent of the dissector.

### 6.4 One-command capture (`lab/run_scenario.py`)

`python lab/run_scenario.py --base http://localhost:8080/fhir --iface <iface> --port 8080 --out captures/lab.pcap`

Start `scapy.AsyncSniffer(iface, filter="tcp port <port>")`, wait 1 s, run `gen_traffic` in-process, wait 2 s, stop sniffer, write PCAP with `wrpcap`. Default iface: `conf.loopback_name`. Needs admin/root rights.

### 6.5 Evaluation (`lab/evaluate.py`)

`python lab/evaluate.py --pcap captures/lab.pcap --expected captures/expected.json`

Run `FhirDissector(emit_non_fhir=True)` over the PCAP; match events to expected entries by `(method, path-without-query, status)` in order; print a table (expected vs got for interaction, resource type, is_fhir) and totals: detection precision, recall, interaction accuracy. Exit code 0 only if everything matches.

## 7. Testing strategy

- **Unit tests** for `classifier`, `detector`, `body`, `http_parser` (Content-Length, chunked split across feeds at every byte boundary, gzip, HEAD, 204, 1xx, until-close, two pipelined messages in one buffer, oversized headers, garbage input).
- **Reassembly tests** with `tests/pcap_builder.py`: helper that builds a full TCP conversation (handshake, data split into small segments, FIN) for given request/response byte strings, with options to **shuffle segment order**, **duplicate segments** (retransmissions), **drop the handshake** (mid-stream capture), and **use IPv6**.
- **End-to-end synthetic test:** build a PCAP in a temp dir with several FHIR and non-FHIR exchanges on one keep-alive connection; run the CLI path; assert interactions, resource types, statuses, and that redaction removed search values.
- **End-to-end real test:** if `captures/lab.pcap` and `captures/expected.json` exist, run the evaluator logic and assert 100% match; otherwise `pytest.skip`.
- All tests must run with plain `pytest` without Docker, network, or root.

## 8. Phased execution (3 days)

### Phase 0 — Inspect the existing framework (Day 1, ~1 h)

**Prompt:** `Read FHIR_DISSECTOR_PLAN.md. Do Phase 0: inspect this repository and explain how protocol modules are structured, registered, and fed with packets or streams, and what output format they use. Do not write code yet. Propose how to adapt §4 and §5.3 to this framework.`

- If the repo is empty / standalone: Claude says so and the plan is followed as written.
- 👤 HUMAN: read the proposal, agree on the adaptation, then continue.

### Phase 1 — Project setup (Day 1)

**Prompt:** `Do Phase 1 of FHIR_DISSECTOR_PLAN.md.`

Claude creates: `requirements.txt`, `.gitignore`, `docker-compose.yml`, `.vscode/*` (see §9), empty package with `__init__.py` and `__main__.py`, `tests/` folder with a trivial passing test.

👤 HUMAN:

1. Install Python 3.10+, Docker Desktop (or Docker Engine), and the VS Code Python extension.
2. Create the virtual env and install deps:
   - Linux/macOS: `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
   - Windows: `py -m venv .venv` then `.venv\Scripts\activate` then `pip install -r requirements.txt`
3. Windows only: install **Npcap** with "Support loopback traffic" enabled (needed by scapy for capture).
4. `docker compose up -d`, then open `http://localhost:8080/fhir/metadata` in a browser.
5. In VS Code: select the `.venv` interpreter; run `pytest`.

**Accept when:** metadata page loads; `pytest` passes.

### Phase 2 — Lab traffic and capture (Day 1)

**Prompt:** `Do Phase 2 of FHIR_DISSECTOR_PLAN.md: implement lab/mock_fhir_server.py, lab/gen_traffic.py and lab/run_scenario.py as specified in §6.`

👤 HUMAN:

1. Run the scenario with admin rights:
   - Linux: `sudo .venv/bin/python lab/run_scenario.py --out captures/lab.pcap`
   - macOS: same with `sudo`; iface `lo0` is the default
   - Windows: run the VS Code terminal "as Administrator"
2. Open `captures/lab.pcap` in Wireshark; use *Follow → HTTP Stream* and check you see every request/response.
3. If Docker is a problem, start `python lab/mock_fhir_server.py` and use `--base http://localhost:8081/fhir --port 8081`.

**Accept when:** `captures/lab.pcap` and `captures/expected.json` exist and Wireshark shows the traffic.

### Phase 3 — HTTP parser and TCP reassembly (Day 2, morning)

**Prompt:** `Do Phase 3 of FHIR_DISSECTOR_PLAN.md: implement http_parser.py and reassembly.py per §5.1–5.2, plus tests/pcap_builder.py, test_http_parser.py and test_reassembly.py per §7. Run pytest and fix failures.`

**Accept when:** all parser and reassembly tests pass, including shuffled segments, retransmissions, chunked splits at every byte boundary, and missing handshake.

### Phase 4 — FHIR logic and public API (Day 2, afternoon)

**Prompt:** `Do Phase 4 of FHIR_DISSECTOR_PLAN.md: implement classifier.py, detector.py, body.py, events.py, dissector.py and cli.py per §5.3–5.8, with their unit tests. Run pytest and fix failures.`

👤 HUMAN: `python -m fhir_dissector pcap captures/lab.pcap -o captures/events.jsonl` and skim the output.

**Accept when:** unit tests pass; CLI produces one event per FHIR exchange with correct interactions.

### Phase 5 — Evaluation and live mode (Day 3, morning)

**Prompt:** `Do Phase 5 of FHIR_DISSECTOR_PLAN.md: implement lab/evaluate.py and tests/test_end_to_end.py per §6.5 and §7. Run the evaluator on captures/lab.pcap, investigate every mismatch, and fix the dissector (not the expected file) unless the expected entry is genuinely wrong — explain any such case.`

👤 HUMAN:

1. `python lab/evaluate.py --pcap captures/lab.pcap --expected captures/expected.json`
2. Live test: in one terminal (admin) run `python -m fhir_dissector live --bpf "tcp port 8080"`; in another run `python lab/gen_traffic.py`. Events must appear live and match the offline run.

**Accept when:** evaluator reports 100% detection and interaction accuracy, zero false positives on non-FHIR calls; live mode prints the same events.

### Phase 6 — Integration and documentation (Day 3, afternoon)

**Prompt:** `Do Phase 6 of FHIR_DISSECTOR_PLAN.md: wire FhirDissector into the existing framework as agreed in Phase 0 (skip if standalone), write README.md (setup per OS, usage, event schema, design overview, test results from the evaluator, limitations and future work from §2), and run the full test suite.`

**Accept when:** module runs through the framework's normal entry point; README is complete; all tests green.

## 9. VS Code configuration

**`.vscode/settings.json`:** `python.defaultInterpreterPath` → `.venv`; `python.testing.pytestEnabled: true`; `python.testing.pytestArgs: ["tests"]`.

**`.vscode/launch.json`** (debug configurations):

- *Dissect lab PCAP* — module `fhir_dissector`, args `pcap captures/lab.pcap -o captures/events.jsonl`
- *Live capture* — module `fhir_dissector`, args `live --bpf "tcp port 8080"` (VS Code must run with admin rights)
- *Mock FHIR server* — program `lab/mock_fhir_server.py`
- *Generate traffic* — program `lab/gen_traffic.py`
- *Evaluate* — program `lab/evaluate.py`
- *Debug current test file* — pytest on `${file}`

**`.vscode/tasks.json`:** `Start HAPI` (`docker compose up -d`), `Stop HAPI` (`docker compose down`), `Run tests` (`pytest -q`), `Run scenario` (`lab/run_scenario.py`), `Evaluate` (`lab/evaluate.py`).

## 10. Definition of done

- [ ] `pytest` green with no Docker, network, or root.
- [ ] Lab PCAP evaluated: 100% FHIR detection, 100% interaction accuracy, 0 false positives.
- [ ] Same results in live mode.
- [ ] Redaction verified: no search values, tokens, or patient fields in default output.
- [ ] Module usable from the existing framework via `process_tcp(...)` / `process_packet(...)`.
- [ ] README with limitations: no TLS, no HTTP/2, no subscriptions, tested against HAPI (FHIR R4) only.

## 11. Rules for Claude while executing

- Work only on the current phase; do not start the next one unprompted.
- Run `pytest` after every change set and report results honestly, including failures.
- Prefer small, readable modules with docstrings and type hints.
- Never weaken a test or edit `expected.json` just to make results match; explain the root cause instead.
- Never print, log, or store full resource bodies from captures.
- Ask before adding any dependency not listed in §3.
