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
| **pytest** | The tool that runs our automated tests. |
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

**What:** Created the skeleton: `requirements.txt`, `.gitignore`, `.gitattributes`, `docker-compose.yml`, `pytest.ini`, `.vscode/` (settings, launch, tasks, extensions), the `fhir_dissector/` package, `tests/` with a smoke test, and the `captures/` folder.

**Why:**
- `requirements.txt` lists libraries so anyone can install the same versions.
- `.gitignore` stops git from saving big/generated files (`.venv`, `.pcap`).
- `docker-compose.yml` describes how to start HAPI FHIR with one command.
- `.vscode/` gives one-click tasks and debug configurations.

**Commands:**
```powershell
py -m venv .venv                           # create the private Python folder
.venv\Scripts\activate                     # "enter" it (prompt shows (.venv))
pip install -r requirements.txt            # install scapy, requests, pytest
pytest                                     # run tests -> "1 passed"
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
