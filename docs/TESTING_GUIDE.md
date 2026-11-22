# Testing Guide (Windows) — the FHIR network lab

Follow the steps in order. Each step shows **what to type**, **what you should see**, and **what it means**.
All commands are for **PowerShell** in VS Code (*Terminal → New Terminal*), in the project folder.

**The idea:** Docker builds a small hospital network: a FHIR server (HAPI) and several systems
(EHR, laboratory, bedside monitors, clinicians, an intranet), each in its own container with its own
IP and MAC address on one virtual switch, `br-fhir`. A capture container records everything on the
switch into a PCAP file, and every system writes down the requests it made (the *answer key*). Then
the dissector reads the PCAP and an evaluator compares its events with the answer key.

> Numbers that change on every run: resource ids, ports, timestamps, exact counts. The results
> (precision, recall, accuracy, max frame size) should not change.

---

## Quick way

Open **Docker Desktop** (wait for *"Engine running"*), then in VS Code press **Ctrl+Shift+B** and
choose **Network lab: quick run (60 s each)** (about 10 minutes) or **Network lab: all scenarios
(5 min each)** (about 25 minutes). Same in a terminal:

```powershell
.\netlab\lab.ps1 generate -Short       # 60 s per scenario
.\netlab\lab.ps1 generate              # 5 minutes per scenario
```

**You should see at the end** a summary table with one row per scenario, and 100.00 % in the
`prec`, `recall`, `inter` and `type` columns; `maxfr` = 1514 (or less).

The steps below do the same thing slowly, so you can see each part.

---

## Step 1 — Open the project and run the unit tests

```powershell
cd "C:\Users\muzam\Documents\Packet dissector FHIR"
.venv\Scripts\activate
pytest -q
```
**You should see:** `192 passed` (a few seconds; the first run after a change can take longer).
**Meaning:** the dissector, the node configuration and the evaluator work on synthetic packets.
No Docker, no network, no admin rights needed. The last 4 tests re-check the saved network-lab
captures.

---

## Step 2 — Look at a node file

```powershell
python netlab\fhir_node.py --node netlab\scenari\ward\clinician-2.ini --show
```
**You should see:** JSON with `"ip": "10.63.0.26"`, `"mac": "02:63:00:00:00:26"` and one flow with
`"kind": "clinician"`, `"format": "xml"`, `"keep_alive": false`.
**Meaning:** this file *is* the second clinician workstation of the ward: it asks for XML and opens a
new TCP connection for every request. Every system of the lab is described like this
(`netlab\README.md`, "Node file reference").

---

## Step 3 — Run one scenario (icu, 60 seconds)

Docker Desktop must be running.
```powershell
.\netlab\lab.ps1 run -Scenario icu -Duration 60
```
**You should see** (times differ):
```
[labctl 10:00:00] scenario icu: 3 nodes, 60 s
[labctl 10:00:00] starting network + HAPI (first start of HAPI takes 1-2 minutes)
[labctl 10:01:05] HAPI ready at http://10.63.0.10:8080/fhir
[labctl 10:01:08] capture on br-fhir -> captures/netlab/icu.pcap
[labctl 10:01:10] clients up: ehr (10.63.0.21), monitor-1 (10.63.0.23), monitor-2 (10.63.0.24)
[labctl 10:02:13] all clients finished
[labctl 10:02:19] answer key: captures/netlab/icu_expected.jsonl
[labctl 10:02:19] lab down
=== icu ===
capture: ~5500 frames, 60 s, 1.1 MB, max frame 1514 bytes (0 frames > 1514), 5 TCP connections
...
detection: TP=~330 FP=0 FN=0 TN=0  precision=100.00%  recall=100.00%
interaction accuracy=100.00%  resource type accuracy=100.00%
RESULT: PASS (everything matches)
```
**Meaning:** the order is the same as in hl7-sim: network + server first, **then** the capture, then
the clients. `max frame 1514` proves that TCP offload is off: large FHIR responses travel in many
normal-size segments, as on a real cable.

---

## Step 4 — Open the capture in Wireshark (optional)

1. Open `captures\netlab\icu.pcap` in Wireshark.
2. Filter `http` (port 8080 is decoded as HTTP automatically).
3. *Statistics → Conversations → IPv4*: you see the three clients (10.63.0.21, .23, .24) talking to
   HAPI (10.63.0.10).
4. *Statistics → Packet Lengths*: nothing above 1514 bytes.

**Meaning:** a real multi-host capture: separate IP and MAC per system, ARP, TCP handshakes, and
messages split into segments.

---

## Step 5 — Run the dissector on the capture

```powershell
python -m fhir_dissector pcap captures\netlab\icu.pcap -o captures\events.jsonl
```
**You should see:** `FHIR events: ~330` and a list by interaction, mostly `create` (vital signs).

Look at one event:
```powershell
Get-Content captures\events.jsonl -TotalCount 1 | python -m json.tool
```
**You should see:** `"flow": {"client": "10.63.0.2x:...", "server": "10.63.0.10:8080"}` and the FHIR
interaction and resource type. No patient names, no values.

---

## Step 6 — Evaluate one capture by hand

```powershell
python lab\evaluate.py --pcap captures\netlab\icu.pcap --expected captures\netlab\icu_expected.jsonl
```
**You should see** the same block as at the end of Step 3, ending with `RESULT: PASS`.
**Meaning:** every request in the answer key was matched, *for the same client IP*, to a dissector
event with the same method, path and status, within 2 seconds. TP/FP/FN/TN, precision and recall
are computed on that matching. Encrypted calls (only in `general`) are listed separately as
"expected not visible".

---

## Step 7 — Watch a scenario while it runs

```powershell
.\netlab\lab.ps1 up -Scenario ward -Duration 300
docker compose -p fhir-netlab ps                    # the containers and their state
docker compose -p fhir-netlab logs -f clinician-2   # one line per request; Ctrl+C to stop watching
.\netlab\lab.ps1 down                               # stop, merge the answer key
python lab\evaluate.py --pcap captures\netlab\ward.pcap --expected captures\netlab\ward_expected.jsonl
```
**You should see in the logs:** lines like `[ward-round] GET /fhir/Patient -> 200`.
**Meaning:** `up` leaves the lab running so you can look inside; `down` always cleans up, even after
an interrupted start.

---

## Step 8 — All scenarios and the summary

```powershell
.\netlab\lab.ps1 generate
Get-Content captures\netlab\summary.txt
```
**You should see:** four rows (`general`, `ward`, `laboratory`, `icu`) and a TOTAL row, all at
100.00 %; in `general` the `TLS` column shows the encrypted calls of the secure clinician.

---

## Common problems and fixes

| Problem | What it means | Fix |
|---|---|---|
| `Docker is not running` | Docker Desktop is closed | Start Docker Desktop, wait for "Engine running" |
| `HAPI did not become ready` | HAPI needs more memory or time | Docker Desktop → Settings → Resources: give it at least 4 GB; run again |
| `Pool overlaps with other one on this network` | another Docker network uses 10.63.0.0/24 | `.\netlab\lab.ps1 down`; if it persists, remove the other network (`docker network ls`) |
| `a previous lab is still up: stopping it first` | the last run was interrupted | nothing to do: it cleans up by itself |
| `capture: 0 frames` | the capture container could not open `br-fhir` | check `docker compose -p fhir-netlab logs capture`; Docker Desktop must use the WSL2 engine |
| `max frame` above 1514 | offload is still on for some container | check that the node containers have `NET_ADMIN` (see `netlab/docker-compose.yml`) |
| `RESULT: FAIL` | a mismatch: dissector bug, or the answer key of another run | the report lists each mismatch; use the `_expected.jsonl` of the same run |
| `.venv\Scripts\activate cannot be loaded` | PowerShell blocks scripts | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, or use `.venv\Scripts\python.exe` |

**Live mode:** `python -m fhir_dissector live` works on real interfaces, but it cannot listen on
`br-fhir` from Windows: the bridge exists only inside Docker Desktop's Linux VM. The network lab is
therefore analysed from its captures (which is how the hl7-sim captures are used too).
