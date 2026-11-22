# Testing Guide (Windows)

How to test the FHIR dissector yourself. Each step: **type** → **you should see** → **what it means**.
Use **PowerShell** in VS Code (*Terminal → New Terminal*).

---

## Test everything in one go

```powershell
cd "C:\Users\muzam\Documents\Packet dissector FHIR"
.venv\Scripts\activate
.\netlab\lab.ps1 -Short
```
Or in VS Code just press **Ctrl+Shift+B** (task *Test EVERYTHING (1 click, quick)*).

It does all of this by itself (about 12 minutes):

1. starts **Docker Desktop** if it is not running;
2. runs the **192 unit tests**;
3. builds the **hospital network** and runs the 4 scenarios (general, ward, laboratory, icu),
   60 seconds of traffic each, recording everything;
4. **evaluates** the dissector on each recording and prints one verdict.

**You should see at the end:**
```
========================================================================
unit tests : PASS  (192 passed in ...)
general    : PASS  (... calls, precision 100%, recall 100%, interaction 100%, max frame 1514)
ward       : PASS  (...)
laboratory : PASS  (...)
icu        : PASS  (...)
========================================================================
EVERYTHING PASSED   in 12 minutes
```

**What it means:** the dissector's parts work (unit tests), and on a realistic hospital network
— a FHIR server plus EHR, laboratory, monitors, clinicians and an intranet, each with its own IP
address — it found every FHIR request, labelled each one correctly, and raised no false alarm.

**Full version** (5 minutes per scenario, about 30 minutes; these are the report numbers):
```powershell
.\netlab\lab.ps1
```
Quick runs are saved in `captures\netlab\quick\`; full runs in `captures\netlab\` (the quick test
never overwrites the full captures).

If `activate` is blocked: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, then try again.

---

## Read the results

```powershell
Get-Content captures\netlab\quick\summary.txt      # after the quick run
Get-Content captures\netlab\summary.txt            # after the full run
```

| Column | Meaning |
|---|---|
| `calls` | requests in the answer key (what the systems really sent) |
| `TLS` | encrypted (HTTPS) requests: the dissector cannot read them, so they are counted apart |
| `TP` | FHIR requests the dissector found |
| `FP` | false alarms (should be 0) |
| `FN` | FHIR requests it missed (should be 0) |
| `TN` | normal web requests it correctly ignored |
| `prec` / `recall` | no false alarms / nothing missed |
| `inter` / `type` | right FHIR action (read, create, …) / right resource (Patient, …) |
| `maxfr` | biggest packet: 1514 bytes = normal network packets |

---

## Look deeper (optional)

**One scenario, then one event:**
```powershell
.\netlab\lab.ps1 run -Scenario icu -Duration 60
python -m fhir_dissector pcap captures\netlab\quick\icu.pcap -o captures\events.jsonl
Get-Content captures\events.jsonl -TotalCount 1 | python -m json.tool
```
**You should see:** `RESULT: PASS`, then `FHIR events: ...`, then one event with `"interaction"`,
`"resource_type"` and `"client": "10.63.0.2x:..."` — and **no** patient names or values.

**Watch the systems while they work:**
```powershell
.\netlab\lab.ps1 up -Scenario ward
docker compose -p fhir-netlab logs -f clinician-2      # Ctrl+C to stop watching
.\netlab\lab.ps1 down
```
**You should see:** log lines like `[ward-round] GET /fhir/Patient -> 200`, then `lab down`.

**Only the unit tests** (seconds, no Docker): `pytest -q` → `192 passed`.

**Wireshark:** open `captures\netlab\general.pcap`, filter `http`, then *Statistics →
Conversations → IPv4*: each hospital system (10.63.0.2x) talks to the FHIR server (10.63.0.10).

---

## If something goes wrong

| You see | Fix |
|---|---|
| `Docker is not running` | Docker Desktop did not start by itself: open it, wait for "Engine running", run again |
| `HAPI did not become ready` | Docker Desktop → Settings → Resources: at least 4 GB memory; run again |
| `unit tests : FAIL` | the lines above the verdict show which test failed |
| `SOMETHING FAILED` for a scenario | open its `_evaluation.txt`: the `MISMATCHES` lines show each problem |
| you stopped a run halfway | `.\netlab\lab.ps1 down` |
| `running scripts is disabled` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
