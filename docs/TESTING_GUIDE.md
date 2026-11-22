# Testing Guide (Windows) — the dissector on a live FHIR server

Follow the steps in order. Each step shows **what to type**, **what you should see**, and **what it means**.
All commands are for **PowerShell** in VS Code (*Terminal → New Terminal*).

**The idea:** a real FHIR server runs on your PC. The dissector listens to the network *live*. A script plays a hospital app and sends 19 calls (17 FHIR + 2 normal web pages) and writes the *answer key*. At the end we compare what the dissector saw with the answer key.

> Numbers that change on every run: patient ids (`1000`, `1015`, …), ports (`[::1]:60668`), timestamps, packet counts. Everything else should match.

---

## Quick way — 2 buttons

Open Docker Desktop (wait for *"Engine running"*), then in VS Code:

| Button | How | What it does |
|---|---|---|
| **1 Start FHIR server** | *Terminal → Run Task… → 1 Start FHIR server* | Starts HAPI in Docker on port 8080 (or 8090 if 8080 is busy) and waits until it answers. Ends with `OK: FHIR server ready at http://localhost:8090/fhir`. Only needed once per session. |
| **2 Run live test** | **Ctrl+Shift+B** (or *Run Task… → 2 Run live test*) | Starts the live dissector, sends the 19 calls, stops the dissector, prints its summary and the grade. Ends with `RESULT: PASS (everything matches)`. Run it as often as you like. |

Same from a terminal: `python lab/live_demo.py start` and `python lab/live_demo.py run`. Stop the server with *Run Task… → Stop FHIR server* (or `python lab/live_demo.py stop`).

**What one run produces (no PCAP files — live mode reads the network directly):**

| File | Content |
|---|---|
| `captures/live_events.jsonl` | the results: **one line per request/response** (19 lines) |
| `captures/live_expected.json` | the answer key written by the traffic generator |
| `captures/evaluation_live.txt` | the grade (precision, recall, interaction accuracy) |

Each run replaces these files with the new run's results.

**Need PCAP files (recorded traffic, e.g. for Wireshark)?** *Run Task… → 3 Record PCAP* (or `python lab/live_demo.py record`). It records the same 19 calls into `captures/pcaps/fhir_<server>_<date>_<time>.pcap`, with its answer key (`_expected.json`) and the dissector's score (`_evaluation.txt`). A ready-made set is already there: `captures/pcaps/fhir_hapi.pcap` and `fhir_mock.pcap` (see `captures/pcaps/README.md`).

The steps below do the same thing by hand, one command at a time, with explanations.

---

## Step 1 — Open the project

```powershell
cd "C:\Users\muzam\Documents\Packet dissector FHIR"
.venv\Scripts\activate
```
**You should see:** the prompt starts with `(.venv)`.
**Meaning:** you are using the project's own Python with scapy and requests.

---

## Step 2 — Choose the port

Another program may already use port 8080 (on this PC an Apache web server sometimes does). Check:
```powershell
Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue
```
- **No output** → port 8080 is free → use **8080** in all steps below.
- **Output shown** → 8080 is busy → use **8090** instead (replace `8080` with `8090` everywhere below).

---

## Step 3 — Start the FHIR server (HAPI in Docker)

1. Open **Docker Desktop** and wait for *"Engine running"*.
2. Start HAPI:
```powershell
docker compose up -d                                   # port 8080
$env:HAPI_PORT=8090; docker compose up -d              # or: port 8090
```
3. Wait 1–2 minutes, then check it is ready:
```powershell
curl.exe -s -o NUL -w "%{http_code}" http://localhost:8080/fhir/metadata
```
**You should see:** `200`. (If not: wait 30 s and try again.)
**Meaning:** a real FHIR R4 server is answering. You can also open http://localhost:8080/fhir/metadata in the browser: a JSON page starting with `"resourceType": "CapabilityStatement"`.

Internet is only needed the very first time (to download the HAPI image). After that everything runs locally.

---

## Step 4 — Start the live dissector (Terminal 1)

```powershell
Remove-Item captures\live_events.jsonl -ErrorAction SilentlyContinue
python -m fhir_dissector live --bpf "tcp port 8080" --all -o captures/live_events.jsonl
```
**You should see:**
```
Live capture on '\\Device\\NPF_Loopback' filter='tcp port 8080' (fast decoding; Ctrl+C to stop)
```
Then it waits. **Leave this terminal open.**
**Meaning:** the dissector listens to the loopback "wire" (the network your PC uses to talk to itself) and only to the FHIR server's port. `--all` also reports non-FHIR web calls, so we can check they are *not* labelled FHIR. The old events file is deleted first because live mode *adds* to the file.

---

## Step 5 — Send traffic (Terminal 2)

Click **+** in the terminal panel to open a second terminal:
```powershell
cd "C:\Users\muzam\Documents\Packet dissector FHIR"
.venv\Scripts\activate
python lab/gen_traffic.py --base http://localhost:8080/fhir --out captures/live_expected.json
```
**You should see in Terminal 2:** 19 lines such as
```
  1 GET    /fhir/metadata                                          -> 200
  2 POST   /fhir/Patient                                           -> 201
  ...
 18 GET    /                                                       -> 200
 19 GET    /favicon.ico                                            -> 404
Wrote 19 expected entries to captures\live_expected.json
```
**You should see in Terminal 1:** one JSON line appears **for each call, while it happens** (19 lines), e.g.
```
{"ts":...,"fhir":{"is_fhir":true,"confidence":1.0,...,"interaction":"read","resource_type":"Patient",...},...}
```
**Meaning:** this is the dissector working live: each request/response becomes one event.

---

## Step 6 — Stop the live dissector

In **Terminal 1** press **Ctrl+C**.
**You should see** a summary:
```
packets: ~300  tcp: ~300  connections: 2  http exchanges: 19  events written: 19  FHIR events: 17
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
**Meaning:** 19 web calls were rebuilt from the packets; 17 were recognised as FHIR, each with its interaction.

---

## Step 7 — Grade the result against the answer key

```powershell
python lab/evaluate.py --events captures/live_events.jsonl --expected captures/live_expected.json
```
**You should see:** 19 rows ending in `OK`, then:
```
expected calls: 19  events: 19  matched: 19  extra events: 0 (FHIR: 0)
detection: TP=17 FP=0 FN=0 TN=2  precision=100.0%  recall=100.0%
interaction accuracy=100.0%  resource type accuracy=100.0%
RESULT: PASS (everything matches)
```
**Meaning:**
- **TP** = FHIR calls found, **FP** = false alarms, **FN** = missed FHIR calls, **TN** = normal web calls correctly ignored.
- **Precision** 100% = every "FHIR" label was right. **Recall** 100% = no FHIR call was missed.
- **Interaction accuracy** 100% = every call got the right label (read, create, …).

---

## Step 8 — Check privacy

```powershell
Select-String -Path captures\live_events.jsonl -Pattern "Rossi","Mario","1980","Bearer"
```
**You should see:** nothing (no output).
**Meaning:** the traffic contained (made-up) patient names and birth dates, but the dissector stored only metadata — no names, no dates, no search values, no tokens.

Look at one event in a readable form:
```powershell
Get-Content captures\live_events.jsonl -TotalCount 4 | Select-Object -Last 1 | python -m json.tool
```
**You should see:** `"interaction": "read"`, `"resource_type": "Patient"`, `"status": 200`, and a `"signals"` list explaining why it was recognised as FHIR.

---

## Step 9 — Stop the server

```powershell
docker compose down
```
**You should see:** `Container packetdissectorfhir-hapi-1 Removed`.

---

## Alternative — without Docker (small built-in server)

If Docker does not work, use the project's own small FHIR server instead of Step 3:

**Terminal 3** (keep it open):
```powershell
python lab/mock_fhir_server.py --port 8081
```
Then do Steps 4–7 with **8081** instead of 8080. You should get the same `RESULT: PASS`. Stop the mock server with Ctrl+C.

---

## VS Code buttons

- *Terminal → Run Task…* → `1 Start FHIR server`, `2 Run live test` (also **Ctrl+Shift+B**), `3 Record PCAP`, `Stop FHIR server`.
- *Run and Debug* (Ctrl+Shift+D) → **Live capture (needs admin)**, **Generate traffic**, **Mock FHIR server** → press F5. Put a breakpoint in `fhir_dissector/classifier.py` → `classify()` to watch each live request being classified.

---

## Common problems and fixes

| Problem | What it means | Fix |
|---|---|---|
| `.venv\Scripts\activate cannot be loaded because running scripts is disabled` | PowerShell blocks scripts by default | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, or use `.venv\Scripts\python.exe` instead of `python` |
| `failed to connect to the docker API ... dockerDesktopLinuxEngine` | Docker Desktop is not running | Start Docker Desktop, wait for "Engine running" |
| Step 3 prints `000` or the browser shows an error | HAPI is still starting (Java takes 1–2 min) | Wait and retry; `docker compose logs --tail 20 hapi` shows `fhirtest.access` lines when ready |
| Every call returns `404`, or HAPI does not start | Another program (e.g. Apache `httpd`) uses port 8080 | Use port 8090 (Step 2) |
| `Cannot find created id (status 404)` in Step 5 | The traffic went to a server that is not HAPI | Check Step 2 and Step 3 (`200` from `/fhir/metadata`) on the same port |
| `error: cannot capture` in Step 4 | No permission to capture | Run the terminal **as Administrator**; reinstall Npcap with *"Support loopback traffic"* |
| Terminal 1 prints nothing during Step 5 | Wrong port in `--bpf`, or wrong interface | `--bpf` port must equal the server port; the default interface is loopback (`localhost`) |
| `RESULT: FAIL` with `extra events` | Old events from an earlier run are still in the file | Delete `captures\live_events.jsonl` before Step 4 (live mode appends) |
| `UnicodeEncodeError` when printing | Old console code page | Use `-o file.jsonl` with `--quiet`, or run `chcp 65001` |
