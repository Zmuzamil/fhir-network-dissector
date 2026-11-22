# Testing Guide (Windows)

How to test the FHIR dissector yourself, from zero. Each step: **type** → **you should see** → **what it means**.
Use **PowerShell** in VS Code (*Terminal → New Terminal*).

---

## Before you start (once)

```powershell
cd "C:\Users\muzam\Documents\Packet dissector FHIR"
.venv\Scripts\activate
```
**You should see:** the prompt starts with `(.venv)`.
If `activate` is blocked: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, then try again.

Open **Docker Desktop** and wait for *"Engine running"* (needed from Test 2 on).

---

## Test 1 — Unit tests (1 minute, no Docker)

```powershell
pytest -q
```
**You should see:** `192 passed`.
**Meaning:** every part of the dissector works on made-up packets: shuffled, duplicated and lost
packets, gzip, chunked bodies, IPv6, FHIR classification, privacy, and the evaluator itself.

---

## Test 2 — The hospital network, quick (about 10 minutes)

```powershell
.\netlab\lab.ps1 generate -Short
```
**You should see:** for each of the 4 scenarios (general, ward, laboratory, icu) lines like
```
[labctl] HAPI ready at http://10.63.0.10:8080/fhir
[labctl] capture on br-fhir -> captures/netlab/icu.pcap
[labctl] clients up: ehr (10.63.0.21), monitor-1 (10.63.0.23), monitor-2 (10.63.0.24)
[labctl] all clients finished
```
and at the end a table with **100.00 %** in `prec`, `recall`, `inter`, `type`, and `1514` in `maxfr`.

**Meaning:** Docker built a small hospital network (a FHIR server + EHR, laboratory, monitors,
clinicians, an intranet), each system with its own IP address. Everything on the network was
recorded into a PCAP file, each system wrote down what it sent (the *answer key*), and the
dissector's results were compared with that answer key.

In VS Code the same: **Ctrl+Shift+B** → *Network lab: quick run (60 s each)*.

---

## Test 3 — Read the results

```powershell
Get-Content captures\netlab\summary.txt
```
**You should see:** one row per scenario and a TOTAL row, all at 100.00 %.

| Column | Meaning |
|---|---|
| `calls` | requests in the answer key |
| `TLS` | encrypted (HTTPS) requests: the dissector cannot read them, so they are counted apart |
| `TP` | FHIR requests the dissector found |
| `FP` | false alarms (should be 0) |
| `FN` | FHIR requests it missed (should be 0) |
| `TN` | normal web requests it correctly ignored |
| `prec` / `recall` | no false alarms / nothing missed |
| `inter` / `type` | right FHIR action (read, create, …) / right resource (Patient, …) |
| `maxfr` | biggest packet: 1514 bytes = normal network packets |

---

## Test 4 — One scenario, and look inside the result

```powershell
.\netlab\lab.ps1 run -Scenario icu -Duration 60
python -m fhir_dissector pcap captures\netlab\icu.pcap -o captures\events.jsonl
Get-Content captures\events.jsonl -TotalCount 1 | python -m json.tool
```
**You should see:** `RESULT: PASS` after the run; then `FHIR events: ...`; then one event with
`"interaction"`, `"resource_type"` and `"client": "10.63.0.2x:..."`, and **no** patient names or values.
**Meaning:** this is what the dissector produces: one short, private line per request.

---

## Test 5 — Watch the systems while they work

```powershell
.\netlab\lab.ps1 up -Scenario ward -Duration 300
docker compose -p fhir-netlab ps
docker compose -p fhir-netlab logs -f clinician-2
```
**You should see:** the containers `Up`, then log lines like `[ward-round] GET /fhir/Patient -> 200`.
Press **Ctrl+C** to stop watching, then:
```powershell
.\netlab\lab.ps1 down
python lab\evaluate.py --pcap captures\netlab\ward.pcap --expected captures\netlab\ward_expected.jsonl
```
**You should see:** `lab down`, then the evaluation ending with `RESULT: PASS`.

---

## Test 6 — Full captures for the report (about 28 minutes)

```powershell
.\netlab\lab.ps1 generate
```
**You should see:** the same as Test 2, with about 3,700 calls in total (5 minutes per scenario).
These are the numbers in the report sentence.

---

## Optional — Look at a capture in Wireshark

Open `captures\netlab\general.pcap`, filter `http`, then *Statistics → Conversations → IPv4*:
you see each hospital system (10.63.0.2x) talking to the FHIR server (10.63.0.10).

---

## If something goes wrong

| You see | Fix |
|---|---|
| `Docker is not running` | start Docker Desktop, wait for "Engine running" |
| `HAPI did not become ready` | Docker Desktop → Settings → Resources: at least 4 GB memory; run again |
| `a previous lab is still up` | nothing to do: it cleans up by itself |
| you stopped a run halfway | `.\netlab\lab.ps1 down` |
| `RESULT: FAIL` | read the `MISMATCHES` lines; use the answer key of the same run |
| `running scripts is disabled` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
