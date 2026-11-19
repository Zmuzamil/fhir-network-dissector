# Testing Guide (Windows) — from zero

Follow the steps in order. Each step shows **what to type**, **what you should see**, and **what it means**.
All commands are for **PowerShell** in the project folder (`C:\Users\muzam\Documents\Packet dissector FHIR`).
In VS Code: *Terminal → New Terminal* opens PowerShell there.

> Numbers that change on every run: patient ids (`1000`, `1005`, …), ports (`[::1]:56105`), timestamps and packet counts (≈ 230–270). Everything else should match.

---

## Step 0 — Open the project and activate the virtual environment

```powershell
cd "C:\Users\muzam\Documents\Packet dissector FHIR"
.venv\Scripts\activate
python --version
```
**You should see:** the prompt starts with `(.venv)` and `Python 3.13.x` (any 3.10+ is fine).
**Meaning:** you are now using the project's private Python with scapy, requests and pytest.

*If `.venv` does not exist yet:* `py -m venv .venv`, then `.venv\Scripts\activate`, then `pip install -r requirements.txt`.

---

## Step 1 — Run the automated tests (no Docker, no network, no admin)

```powershell
pytest -q
```
**You should see:** `139 passed in ~3s`.
**Meaning:** the parser, reassembly, classifier, detector, body summary, redaction and the end-to-end path all work on synthetic packets, including shuffled packets, duplicated packets, IPv6 and missing handshakes.
*If `captures/lab.pcap` does not exist yet, 1 test shows as `skipped`. That is normal.*

---

## Step 2 — Start the FHIR server (HAPI in Docker)

1. Open **Docker Desktop** and wait for *"Engine running"*.
2. Then:
```powershell
docker compose up -d
docker compose ps
```
**You should see:** a container `packetdissectorfhir-hapi-1` with status `Up` and ports `0.0.0.0:8080->8080/tcp`.

3. Wait about 30–90 s, then open **http://localhost:8080/fhir/metadata** in your browser, or run:
```powershell
curl.exe -s http://localhost:8080/fhir/metadata | Select-Object -First 1
```
**You should see:** JSON starting with `{"resourceType": "CapabilityStatement"` that contains `"fhirVersion": "4.0.1"`.
**Meaning:** a real FHIR server is listening on port 8080. `/metadata` is the FHIR "capabilities" endpoint.

---

## Step 3 — Capture lab traffic into a PCAP

```powershell
python lab/run_scenario.py --base http://localhost:8080/fhir --port 8080 --out captures/lab.pcap --expected captures/expected.json
```
**You should see:**
```
Capturing on '\\Device\\NPF_Loopback' with filter 'tcp port 8080'
  1 GET    /fhir/metadata                                          -> 200
  2 POST   /fhir/Patient                                           -> 201
  ...
 16 GET    /fhir/Observation/1007                                  -> 410
 17 GET    /fhir/Patient/does-not-exist-999                        -> 404
 18 GET    /                                                       -> 200
 19 GET    /favicon.ico                                            -> 404
Wrote 19 expected entries to captures\expected.json
Captured 265 packets -> captures\lab.pcap
```
**Meaning:** a sniffer recorded every packet on the loopback adapter (`localhost`) while a script made 19 calls. `expected.json` is the *answer key*: what each call really was.
*If you see "Cannot start capture" or "0 packets", see Problems below (admin rights / Npcap).*

---

## Step 4 — (Optional) Look at the PCAP in Wireshark

1. Open `captures\lab.pcap` in Wireshark.
2. Type `http` in the filter bar and press Enter.
3. Right-click a `GET /fhir/Patient/...` line → *Follow → HTTP Stream*.

**You should see:** requests in red and responses in blue (`HTTP/1.1 200`, `Content-Type: application/fhir+json`, `Content-Encoding: gzip`).
**Meaning:** this is the raw material the dissector reads. Wireshark sees HTTP; our tool also understands the **FHIR** meaning.

---

## Step 5 — Run the dissector on the PCAP

```powershell
python -m fhir_dissector pcap captures/lab.pcap -o captures/events.jsonl
```
**You should see:**
```
wrote 17 events to captures\events.jsonl
packets: 265  tcp: 265  connections: 2  http exchanges: 19  events written: 17  FHIR events: 17
  read                 4
  create               3
  search-type          2
  batch                1
  capabilities         1
  delete               1
  history-instance     1
  operation            1
  transaction          1
  update               1
  vread                1
```
**Meaning:** 19 HTTP exchanges were rebuilt from 265 packets on 2 TCP connections. 17 are FHIR (written), and 2 are not FHIR (the HTML home page and favicon, not written by default).

Look at one event in a readable form:
```powershell
Get-Content captures\events.jsonl -TotalCount 9 | Select-Object -Last 1 | python -m json.tool
```
**You should see:** `"interaction": "search-type"`, `"resource_type": "Patient"`, `"search_params": ["family", "_count"]`, `"path": "/fhir/Patient"`, and a `"bundle"` with `"type": "searchset"`.

---

## Step 6 — Check privacy (redaction)

```powershell
Select-String -Path captures\events.jsonl -Pattern "Rossi","Mario","1980","diagnostics"
```
**You should see:** *nothing* (no output).
**Meaning:** no patient names, birth dates, search values or error texts are stored.

Compare with redaction turned off:
```powershell
python -m fhir_dissector pcap captures/lab.pcap --no-redact 2>$null | Select-String "Rossi"
```
**You should see:** 2 lines containing `family=Rossi` (search values are kept with `--no-redact`). Names inside resources are still never copied.

Also show non-FHIR traffic:
```powershell
python -m fhir_dissector pcap captures/lab.pcap --all -o captures/events_all.jsonl
```
**You should see:** `events written: 19  FHIR events: 17`. The last 2 events have `"is_fhir": false, "confidence": 0.0`.

---

## Step 7 — Evaluate against the answer key

```powershell
python lab/evaluate.py --pcap captures/lab.pcap --expected captures/expected.json
```
**You should see:** 19 rows ending in `OK`, then:
```
expected calls: 19  events: 19  matched: 19  extra events: 0 (FHIR: 0)
detection: TP=17 FP=0 FN=0 TN=2  precision=100.0%  recall=100.0%
interaction accuracy=100.0%  resource type accuracy=100.0%
RESULT: PASS (everything matches)
```
**Meaning:** TP = FHIR calls found, FP = false alarms, FN = missed FHIR calls, TN = non-FHIR correctly ignored. `echo $LASTEXITCODE` prints `0` on PASS.

---

## Step 8 — Live mode (two terminals)

**Terminal 1** (live dissector):
```powershell
python -m fhir_dissector live --bpf "tcp port 8080" --all -o captures/live_events.jsonl
```
**You should see:** `Live capture on '\\Device\\NPF_Loopback' filter='tcp port 8080' (Ctrl+C to stop)`, then it waits.

**Terminal 2** (traffic). Open a second terminal with *+*, then:
```powershell
.venv\Scripts\activate
python lab/gen_traffic.py --base http://localhost:8080/fhir --out captures/live_expected.json
```
**You should see in Terminal 1:** one JSON line appears **for each call, while it happens** (19 lines).
Then press **Ctrl+C** in Terminal 1. **You should see:** the same summary as in Step 5 (`FHIR events: 17`).

Evaluate the live result:
```powershell
python lab/evaluate.py --events captures/live_events.jsonl --expected captures/live_expected.json
```
**You should see:** `RESULT: PASS (everything matches)` with 100% precision, recall and interaction accuracy.
**Meaning:** live mode and PCAP mode give the same results (same code path).

---

## Step 9 — (Optional) The fallback mock server, without Docker

**Terminal 1:**
```powershell
python lab/mock_fhir_server.py --port 8081
```
**Terminal 2:**
```powershell
python lab/run_scenario.py --base http://localhost:8081/fhir --port 8081 --out captures/mock_lab.pcap --expected captures/mock_expected.json
python lab/evaluate.py --pcap captures/mock_lab.pcap --expected captures/mock_expected.json
```
**You should see:** `RESULT: PASS`. Stop the mock server with Ctrl+C.

---

## Step 10 — VS Code buttons

- *Terminal → Run Task…* → `Run tests`, `Start HAPI`, `Run scenario`, `Dissect lab PCAP`, `Evaluate`, `Stop HAPI`.
- *Run and Debug* (Ctrl+Shift+D) → pick e.g. **Dissect lab PCAP** → press F5. Put a breakpoint in `fhir_dissector/classifier.py` → `classify()` to watch each request being classified.
- *Testing* panel (flask icon) → shows all 139 tests. Click ▶ to run.

---

## Step 11 — Stop the server

```powershell
docker compose down
```
**You should see:** `Container packetdissectorfhir-hapi-1 Removed`. (Data in HAPI is lost, which is fine for the lab.)

---

## Common problems and fixes

| Problem | What it means | Fix |
|---|---|---|
| `.venv\Scripts\activate cannot be loaded because running scripts is disabled` | PowerShell blocks scripts by default | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, or use `.venv\Scripts\python.exe` instead of `python` |
| `failed to connect to the docker API ... dockerDesktopLinuxEngine` | Docker Desktop is not running | Start Docker Desktop, wait for "Engine running" |
| `Waiting for FHIR server ... (ConnectionError)` | HAPI is still starting (Java takes time) | Wait; `docker compose logs -f hapi` shows progress ("Started Application") |
| Browser shows an error or 404 at `/fhir/metadata` although `docker compose ps` says `Up` | The container just (re)started; Java/HAPI needs 1–2 min before the FHIR API answers | Wait and reload; `docker compose logs --tail 20 hapi` shows `fhirtest.access` lines once it serves requests |
| Port 8080 already in use | Another program uses 8080 | Stop it, or change `"8080:8080"` to `"8090:8080"` in `docker-compose.yml` and use `--base http://localhost:8090/fhir --port 8090` |
| `Cannot start capture` / `Sniffer did not start` / `0 packets` | No permission to capture, or Npcap without loopback support | Run the terminal **as Administrator**; reinstall Npcap with *"Support loopback traffic"* ticked |
| `WARNING: N packets were cut by the capture snaplen` | A capture tool saved packets shorter than they were | Capture with `run_scenario.py` (raises the limit), or in Wireshark keep the default snaplen (262144) |
| Evaluator shows `MISMATCH` with `-` in "got" | The event was not found: wrong PCAP for this `expected.json` (e.g. ids from another run) | Always use the `expected.json` written in the **same** run as the PCAP |
| `pytest` shows `skipped` | `captures/lab.pcap` is missing | Normal; run Step 3 to create it |
| Live mode prints nothing | Wrong interface or filter, or traffic went to another port | Use `--bpf "tcp port 8080"`; check the server port; default interface is loopback |
| `UnicodeEncodeError` when printing | Old console code page | Use `-o file.jsonl` instead of printing, or `chcp 65001` |
