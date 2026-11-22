# Learning Notes — HL7 FHIR Dissector

A running diary of what we built, why, the commands we used, and the errors we hit.
Machine: Windows 11, Python 3.13 (in `.venv`), Docker Desktop, Npcap.

## Glossary (words you will meet)

| Word | Simple meaning |
|---|---|
| **FHIR** | "Fast Healthcare Interoperability Resources". A standard from HL7 for exchanging health data. It is a web API: normal HTTP requests carrying JSON or XML. |
| **Resource** | One FHIR "thing": `Patient`, `Observation`, `Bundle` (a list of resources), `OperationOutcome` (an error/warning report), `CapabilityStatement` (what the server supports). |
| **Interaction** | The kind of FHIR action: `read` (get one), `search-type` (find many), `create`, `update`, `delete`, `history`, `vread` (read an old version), `transaction`/`batch` (many actions in one call), `operation` (`$name`, e.g. `$everything`). |
| **HTTP** | The text protocol of the web. A *request* (`GET /fhir/Patient/1`) gets a *response* (`200 OK` + body). |
| **TCP** | The transport under HTTP. It splits data into numbered *segments*. The receiver puts them back in order. |
| **Packet** | One unit sent on the network. Contains headers (IP addresses, ports, TCP sequence number) plus a piece of data (*payload*). |
| **Dissector** | A program that reads raw packets and explains what they mean (like Wireshark does). |
| **PCAP** | A file format that stores captured packets. Wireshark opens it. |
| **Loopback** | The virtual network a computer uses to talk to itself (`127.0.0.1`, `localhost`). Our lab traffic travels here. |
| **Npcap** | The Windows driver that lets programs (Wireshark, scapy) capture packets. |
| **scapy** | A Python library to read, build, capture and write packets. |
| **Docker / container** | Docker runs a program in an isolated box (*container*) built from an *image* downloaded from the internet. We use it to run the HAPI FHIR server without installing Java. |
| **HAPI FHIR** | A popular open-source FHIR server (Java). We use its ready-made Docker image. |
| **Virtual environment (`.venv`)** | A private folder of Python libraries just for this project. |
| **git / commit** | git saves snapshots of the code. A *commit* is one snapshot with a message. |

---

## Phase 0 — Inspect the existing framework

**What:** Look for an existing dissector framework to plug into.
**Result:** The folder was empty (only the plan). So the project is *standalone* and we follow the plan's layout exactly. The public method `FhirDissector.process_tcp(...)` remains the plug-in point for any framework later.
**Commands:**
```powershell
git init
git add FHIR_DISSECTOR_PLAN.md
git commit -m "Phase 0: add plan; repo is standalone"
```
**Problems hit:**
- The plan file disappeared once from the folder (unknown cause, maybe the editor or a sync tool). It came back and we checked it was complete (all 11 sections) before continuing.

---

## Phase 1 — Project setup

**What:** Created the skeleton: `requirements.txt`, `.gitignore`, `.gitattributes`, `docker-compose.yml`, `.vscode/` (settings, launch, tasks, extensions), the `fhir_dissector/` package and the `captures/` folder.

**Why:**
- `requirements.txt` lists libraries so anyone can install the same versions.
- `.gitignore` stops git from saving big/generated files (`.venv`, `.pcap`).
- `docker-compose.yml` describes how to start HAPI FHIR with one command.
- `.vscode/` gives one-click tasks and debug configurations.

**Commands:**
```powershell
py -m venv .venv                           # create the private Python folder
.venv\Scripts\activate                     # "enter" it (prompt shows (.venv))
pip install -r requirements.txt            # install scapy and requests
```

Check that scapy sees Npcap and the loopback adapter:
```powershell
python -c "from scapy.config import conf; print(conf.use_npcap, conf.loopback_name)"
# -> True \Device\NPF_Loopback
```

**Problems hit:**
- `py -3.10 -m venv .venv` → *"No suitable Python runtime found"*. Meaning: the `py` launcher does not know a Python 3.10 (the `python` 3.10 on this PC is not registered with the launcher). Fix: use `py -m venv .venv`, which picks Python 3.13. The plan only needs 3.10 or newer.
- `docker info` → *"failed to connect to the docker API ... dockerDesktopLinuxEngine"*. Meaning: Docker is installed but the Docker Desktop app (the "engine") is not running. Fix: open Docker Desktop and wait for "Engine running".
- git warning *"LF will be replaced by CRLF"*. Meaning: Windows and Linux end text lines differently; git converts automatically. Harmless. We added `.gitattributes` so line endings are handled consistently.

---

## Phase 2 — Lab traffic and capture

**What:** Built the "lab": `lab/mock_fhir_server.py` (tiny FHIR server in pure Python, port 8081), `lab/gen_traffic.py` (19 scripted calls: 17 FHIR + 2 non-FHIR, writes `captures/expected.json`), `lab/run_scenario.py` (capture → traffic → save `captures/lab.pcap`).

**Why:** We have no hospital network. A scripted client against a real FHIR server (HAPI) gives realistic traffic *and* an answer key (`expected.json`) to measure the dissector against. `actual_status` in that file is what the client really got, so it does not depend on the dissector.

**Commands:**
```powershell
docker compose up -d                                   # start HAPI (first time downloads the image)
curl.exe http://localhost:8080/fhir/metadata           # is HAPI ready? (JSON CapabilityStatement)
python lab/run_scenario.py --base http://localhost:8080/fhir --port 8080 --out captures/lab.pcap
# fallback without Docker:
python lab/mock_fhir_server.py --port 8081             # terminal 1
python lab/run_scenario.py --base http://localhost:8081/fhir --out captures/mock_lab.pcap --expected captures/mock_expected.json
```

**Things we learned:**
- On this PC, Npcap is configured with `AdminOnly = 0`, so **capture works without admin rights**.
- `localhost` resolves to the IPv6 address `::1` first, so the lab traffic is IPv6. The mock server listens on IPv4 *and* IPv6 to avoid a slow fallback.
- HAPI (v8.12.0, FHIR R4 4.0.1) answers with `Content-Encoding: gzip` + `Transfer-Encoding: chunked` and an empty reason phrase (`HTTP/1.1 200 `). Good real-world test material.
- The gen script never follows redirects, so 1 call = 1 request/response on the wire.

**Problems hit:**
- *"Unable to guess datalink type (linktype=0)"*: the Npcap loopback adapter uses a 4-byte "NULL/Loopback" header (link type 0). scapy only knows it after importing its layer modules. Fix: import `scapy.layers.l2/inet/inet6` before sniffing.

## Phase 3 — HTTP parser and TCP reassembly

**What:** `fhir_dissector/http_parser.py` (incremental HTTP/1.1 state machine), `fhir_dissector/reassembly.py` (TCP stream reassembly + request/response pairing).

**Key ideas:**
- **Sequence number**: TCP numbers every byte. `offset = seq - ISN` (ISN = initial sequence number from the SYN) tells where a segment's bytes belong in the stream.
- **Out-of-order**: a segment from "the future" waits in a buffer until the missing bytes before it arrive.
- **Retransmission**: a segment we already have is dropped; a partly-new one is trimmed.
- **ACK number**: the receiver says "I have everything up to byte N". If it ACKs bytes *we never saw*, the capture lost them → we skip the hole immediately instead of waiting forever.
- **Pairing**: HTTP/1.1 answers requests in order, so each response is matched with the oldest unanswered request (FIFO queue).
- **Resync**: after garbage or a hole, the parser skips bytes until something that looks like `GET /x HTTP/1.1` or `HTTP/1.1 200`.

**Problems hit (and fixes):**
1. *Resync too strict*: after a hole, the next message begins right after lost body bytes (no newline before it). Fix: search for the start-line pattern anywhere, not only at a line start.
2. *Gap waited forever*: with a lost segment, the reassembler waited for 1000 segments → responses paired with wrong requests. Fix: use the peer's ACK number to detect bytes lost by the capture and skip at once. We added `ack` as an **optional** last argument of `process_tcp(...)` (the plan's signature still works).
3. *Real capture — 4 bytes missing per big packet*: on loopback, TCP segments reach 65,475 data bytes → frames of 65,539 bytes. scapy captures **and reads** with a limit (*snaplen*) of 65,535 bytes, so 4 bytes were cut. Effect: a hole inside the 1.78 MB HTML page, and the next response (`favicon.ico` 404) was paired with `GET /`. Fixes:
   - Dissector: on a hole, emit the *partial* message (marked `truncated`, error `gap`) so pairing stays correct; count each hole once.
   - Capture: raise scapy's snaplen to 262,144 (`fhir_dissector.cli.prepare_scapy_capture`), write the PCAP with `snaplen=262144`, and read with `read_packet(size=262144)`.
   Result: 19/19 exchanges, 0 truncated packets, 0 errors.

## Phase 4 — FHIR logic and public API

**What:** `classifier.py` (URL + method → interaction), `detector.py` (is it FHIR? score 0–1 with named *signals*), `body.py` (metadata-only summary of JSON/XML bodies), `events.py` (event JSON + redaction), `dissector.py` (`FhirDissector` public API), `cli.py` (`pcap` and `live` commands).

**Key ideas:**
- **Classifier** works on path *segments*: it finds the first segment that is a FHIR resource type (`Patient`), `metadata`, `_history` or `$operation`. What comes before is the *base* (`/fhir`). The rest decides the interaction using the table in the plan (§5.4).
- **Detector** adds weights of the clues it finds, e.g. `content-type` (0.6) + `resourceType-body` (0.5) → capped at 1.0. FHIR if ≥ 0.5. The list of signals explains *why* (explainability).
- **Redaction** (privacy): by default we keep search parameter *names* but not their *values* (`family`, not `family=Rossi`), never keep tokens, never copy resource contents.
- **FHIR version**: HAPI only reports it in `/metadata` (CapabilityStatement `fhirVersion`). The dissector remembers it per server and adds it to later events of the same server.

**Commands:**
```powershell
python -m fhir_dissector pcap captures/lab.pcap -o captures/events.jsonl        # FHIR events only
python -m fhir_dissector pcap captures/lab.pcap --all                           # + non-FHIR, printed
python -m fhir_dissector pcap captures/lab.pcap --no-redact                     # keeps search values
```

**Result on the HAPI capture:** 19 HTTP exchanges → 17 FHIR events (all interactions right, confidence 1.0), 2 non-FHIR (score 0.0). Redaction check: `Rossi`, `Mario`, `1980`, `+39`, `diagnostics`, `Bearer` appear **0 times** in default output.

**Problems hit:** one bug caught while writing: in `detector.py`, `request.target or "" if request else ""` is parsed by Python as `request.target or ("" if request else "")` and would crash when there is no request. Fixed with brackets.

## Phase 5 — Evaluation and live mode

**What:** `lab/evaluate.py` (compares dissector output with `expected.json`).

**Key ideas:**
- **Ground truth**: `expected.json` was written by the *client* while generating traffic, so it does not depend on the dissector.
- **Matching**: each expected call is matched to an event with the same `(method, path without query, status)`.
- **Metrics**:
  - *precision* = TP / (TP + FP): of all calls we said were FHIR, how many really were? (FP = false alarm)
  - *recall* = TP / (TP + FN): of all real FHIR calls, how many did we find? (FN = missed)
  - *interaction accuracy*: share of FHIR calls with the right interaction label.
- **Live mode** uses the *same* code path as PCAP mode (`FhirDissector`), only the packet source differs (`sniff` instead of `PcapReader`).

**Commands:**
```powershell
python lab/evaluate.py --pcap captures/lab.pcap --expected captures/expected.json
# live test (two terminals):
python -m fhir_dissector live --bpf "tcp port 8080" --all -o captures/live_events.jsonl   # terminal 1
python lab/gen_traffic.py --base http://localhost:8080/fhir --out captures/live_expected.json   # terminal 2
# then Ctrl+C in terminal 1, and:
python lab/evaluate.py --events captures/live_events.jsonl --expected captures/live_expected.json
```

**Results (HAPI FHIR 8.12.0, FHIR 4.0.1):**

| Run | Calls | TP | FP | FN | TN | Precision | Recall | Interaction acc. |
|---|---|---|---|---|---|---|---|---|
| Offline PCAP (`lab.pcap`) | 19 | 17 | 0 | 0 | 2 | 100% | 100% | 100% |
| Live capture | 19 | 17 | 0 | 0 | 2 | 100% | 100% | 100% |
| Mock server PCAP | 19 | 17 | 0 | 0 | 2 | 100% | 100% | 100% |

Live events were identical to offline events (same method, interaction, type, FHIR flag and status for all 19 calls).

**Notes:**
- A live run needs its *own* expected file (new traffic → new resource ids), so we wrote `captures/live_expected.json`.
- `--timeout N` was added to `live` so a live run can stop by itself (handy for scripts).
- No mismatches had to be fixed in this phase: the evaluator passed on the first run, because the gap/snaplen problems were already solved in Phase 3.

## Phase 6 — Integration and documentation

**What:** Phase 0 found no existing framework, so the "wire into the framework" step is skipped. The integration point is `FhirDissector.process_tcp(...)` / `process_packet(...)`, documented with an example in `README.md`. We wrote `README.md`, `TESTING_GUIDE.md`, `REPORT_SUMMARY.md`, finished these notes, and checked the VS Code configuration.

**Problems hit:**
- *VS Code tasks and paths with spaces*: the project path contains a space (`Packet dissector FHIR`). A `"type": "shell"` task with the Python path inside the command string would be split at the space by PowerShell. Fix: Python tasks use `"type": "process"` (runs the program directly, with the arguments as a list).
- *Invalid `\escape` in JSON*: writing `\` through the shell turned it into a single `\`, which is not valid JSON. Fix: use forward slashes (`${workspaceFolder}/.venv/Scripts/python.exe`), which VS Code accepts on Windows.
- We checked every `"process"` task by running it exactly as VS Code would: `Dissect lab PCAP` → OK, `Evaluate` → PASS.

---

## Final summary — what to remember

1. **FHIR = HTTP + JSON/XML resources.** To see it on the wire you must rebuild TCP streams, then parse HTTP, then interpret URLs and bodies.
2. **TCP reassembly** uses sequence numbers (where bytes go), ACK numbers (what the other side got), and SYN/FIN/RST (start/end).
3. **HTTP framing** decides where one message ends: `Content-Length`, `chunked`, or "until the connection closes". Compression (`gzip`) is undone after de-chunking.
4. **Detection** is a weighted list of clues with a threshold. The signal list makes every decision explainable.
5. **Classification** maps method + URL segments to the FHIR interaction (`GET Patient/1` = read, `POST [base]` with a transaction Bundle = transaction, …).
6. **Privacy by default**: names of search parameters yes, values no. Tokens and resource contents never.
7. **Evaluation** needs ground truth produced independently of the tool (`expected.json` from the client), and the standard metrics precision, recall and accuracy.
8. **Real captures have surprises**: here, 64 KB loopback segments exceeded the default snaplen. Only the real lab run revealed it.

### Full command cheat-sheet (Windows)

```powershell
.venv\Scripts\activate                                   # enter the venv
python lab/live_demo.py all                              # 1 CLICK (= Ctrl+Shift+B): Docker + HAPI + live test + grade
python lab/live_demo.py record                           # save a PCAP (+ answer key + score) in captures/pcaps/
python lab/live_demo.py stop                             # stop HAPI
# --- the same by hand ---
Get-NetTCPConnection -LocalPort 8080 -State Listen       # port busy? then use 8090 everywhere
docker compose up -d                                     # start HAPI on 8080 | docker compose down = stop
$env:HAPI_PORT=8090; docker compose up -d                # ... or on 8090 if 8080 is busy
# live test
python -m fhir_dissector live --bpf "tcp port 8080" --all -o captures/live_events.jsonl        # terminal 1
python lab/gen_traffic.py --base http://localhost:8080/fhir --out captures/live_expected.json   # terminal 2
python lab/evaluate.py --events captures/live_events.jsonl --expected captures/live_expected.json
# as a service (after `pip install .`)
fhir-dissector live --iface "Ethernet" --bpf "tcp port 8080" -o C:\fhir\events.jsonl --quiet
# analyse a recorded capture
python -m fhir_dissector pcap captures/pcaps/fhir_hapi.pcap -o captures/events.jsonl
python lab/evaluate.py --pcap captures/pcaps/fhir_hapi.pcap --expected captures/pcaps/fhir_hapi_expected.json
python lab/mock_fhir_server.py --port 8081               # small FHIR server without Docker
```

---

## Clean-up (after Phase 6)

**What:** made the project smaller and easier to read, without changing behaviour.
- Deleted: `lab/__init__.py`, `captures/.gitkeep`, `.gitattributes`, and generated leftovers (`events_all.jsonl`, `evaluation_lab.json`, `mock_lab.pcap`, `mock_expected.json`).
- Removed dead code: `classifier.query_param_names` (never used), the one-line `events._bundle` helper, the `--json` option of `evaluate.py`.
- Moved the guides into `docs/` so the root only holds the README, the plan and the code folders.
- **Kept** the 8 small dissector modules separate on purpose: one file per pipeline step (TCP → HTTP → detect → classify → body → event) is easier to understand than one big file, and it is the plan's layout.

**Check after clean-up:** `evaluate.py` on the current `captures/lab.pcap` (268 packets, the 13:05 re-capture) → 100% precision, recall, interaction accuracy, PASS.


---

## Deployment hardening (after the clean-up)

**Question asked:** "Is the project 100% ready to be deployed live?" **Honest answer:** ready for plaintext HTTP/1.1 FHIR on one or a few servers; not for HTTPS traffic (encrypted, cannot be read) or very fast core links.

**What we measured first:** speed 25k packets/s for the core but only ~3–6k packets/s through scapy (scapy builds a Python object per packet); 20,000 never-closing connections → 86 MB with no limit; 100,000 random packets → 0 crashes.

**What we changed:**
1. **Memory caps** (`reassembly.py`): max tracked connections (default 10,000; the least recently active one is evicted, its exchanges get the error `evicted`) and max 1,000 unanswered requests per connection (`request-queue-overflow`).
2. **Fast decoder** (`dissector.decode_frame` + `FhirDissector.process_frame`): reads the IP and TCP headers directly from bytes with `struct`. Supports Ethernet (+VLAN), loopback, Linux SLL/SLL2, raw IP, IPv6 extension headers. Classic PCAP files are read without scapy (`cli.iter_pcap_frames`); live capture on libpcap/Npcap keeps frames raw. Result: **~26,500 packets/s, 8× faster, identical events**. PCAPNG files and unusual link types still use scapy.
3. **Service-friendly live mode**: `-o` now **appends**, `--quiet` hides screen output, SIGTERM (sent by `systemctl stop`) flushes and exits cleanly.
4. **Tuning options**: `--max-body`, `--idle-timeout`, `--max-connections` for both `pcap` and `live`.
5. **Packaging**: `pyproject.toml` → `pip install .` gives the command `fhir-dissector`.
6. **Deployment guide** in README §6: where to capture (behind the TLS terminator / mirror port), service setup (systemd, Task Scheduler), log rotation, privacy checklist.
7. `docker-compose.yml`: host port configurable with `HAPI_PORT`.

**Problem hit:** during the live re-test every request got **404**. Meaning: HAPI had been stopped, and an Apache web server (`httpd`, not part of the project) was now listening on port 8080. Found with `Get-NetTCPConnection -LocalPort 8080 -State Listen`. Fix: start HAPI on another port with `HAPI_PORT=8090 docker compose up -d`. Live re-test on 8090: 19/19, precision/recall/interaction accuracy 100%, PASS.


---

## Live-server focus (final change)

**What:** the automated unit tests (`tests/` folder, pytest) were removed, so the project is only about **using the dissector on a live FHIR server**. pytest was also removed from `requirements.txt`, `pyproject.toml` and the VS Code settings/tasks/debug configurations.

**How correctness is shown now:** the lab evaluator on live traffic (`gen_traffic.py` → `live` → `evaluate.py --events`): 19/19 calls, precision, recall and interaction accuracy 100%, RESULT: PASS. The same evaluator also works on a recorded capture (`--pcap`).

**If the tests are ever needed again:** they are kept in git history (commit `fca5799`): `git checkout fca5799 -- tests`.

---

## Two-button live test

**Question asked:** "Does it give multiple PCAPs?" **Answer:** no. Live mode reads the network directly and writes no PCAP. The "multiple results" are lines in one file: one JSON line per request/response (19 per test run) in `captures/live_events.jsonl`. Only the optional recording (`run_scenario.py`) writes one PCAP, replaced on every recording.

**What we built:** `lab/live_demo.py` with three actions, wired to VS Code tasks:
- `start` (*1 Start FHIR server*): checks if a FHIR server is already running; otherwise starts HAPI with Docker on 8080, or on 8090 if 8080 is busy, and waits until `/fhir/metadata` answers.
- `run` (*2 Run live test*, **Ctrl+Shift+B**): finds the server (8080/8090/8081), starts the live dissector in the background, sends the 19 calls, stops the dissector cleanly, prints its summary and the grade, saves `captures/evaluation_live.txt`.
- `stop` (*Stop FHIR server*): `docker compose down`.

**Problem hit (a real bug, now fixed):** stopping the live dissector from the script took 20 s and its summary was lost. Meaning: when no packets arrive, scapy's capture loop waits inside a native `select` call, and Python only runs signal handlers (Ctrl+C, SIGTERM, Ctrl+Break) after that call returns. So a stop request waited until the next packet — Ctrl+C on a quiet network would be slow too. Fix in `cli.py`: the capture runs in a background thread (scapy `AsyncSniffer`); the main thread only waits in short steps, reacts to Ctrl+C / SIGTERM / SIGBREAK at once, and stops the capture thread. `--timeout` is now checked by the main thread. Result: stop in 0.3 s with the summary printed.

**Result:** button 1 picked port 8090 by itself (Apache on 8080); button 2 → 354 packets, 19/19 calls, precision/recall/interaction accuracy 100%, RESULT: PASS.

---

## PCAP set for the supervisor

**Question:** the professor asked "do you have PCAPs?". A PCAP is a recording of network traffic (open it in Wireshark). It serves as evidence of what was tested, makes results reproducible, and is the start of a dataset.

**What we made:** `captures/pcaps/` with `fhir_hapi.pcap` (238 packets, HAPI FHIR R4) and `fhir_mock.pcap` (142 packets, mock server), each with `_expected.json` (ground truth) and `_evaluation.txt` (dissector score: 100% precision, recall, interaction accuracy), plus a README written for the professor. Checked with Wireshark's own tools: `capinfos` reads both files, `tshark` sees 19 HTTP requests in each. These PCAPs are now tracked by git (`!captures/pcaps/*.pcap` in `.gitignore`); `captures/fhir_pcaps.zip` (≈260 KB) is for e-mail.

**New button:** `python lab/live_demo.py record` / task *3 Record PCAP* records a new capture with its ground truth and score.

**Tip:** Wireshark only decodes HTTP on its usual ports. For 8090/8081 use *Analyze → Decode As… → TCP port → HTTP*.

**Privacy:** the PCAPs contain full message contents (only synthetic patients). Redaction applies to the dissector's events, not to raw captures — never share PCAPs of real patient traffic.

---

## Final clean-up and 1-click run

**1 click:** `python lab/live_demo.py all` (VS Code: **Ctrl+Shift+B**, task *Run everything (1 click)*) starts Docker Desktop if needed, starts HAPI (8080, or 8090 if busy), waits until it answers, then runs the live test and prints the grade.

**Deleted (unused / duplicated):** the old recording `captures/lab.pcap` with `captures/expected.json`, `captures/evaluation_lab.txt` and `captures/events.jsonl` (replaced by the documented set in `captures/pcaps/`); the per-run live outputs are no longer kept in git (they are re-created by every live test); `__pycache__` folders; the VS Code debug configurations that were hard-wired to port 8080. Script defaults now point to `captures/pcaps/` and `captures/live_expected.json`.

**Note:** the phase sections above are a diary; commands there that use `captures/lab.pcap` show what we ran at the time. Use the cheat-sheet for today's commands.
