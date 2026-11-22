# netlab: an emulated FHIR hospital network

A small hospital network in Docker, in the style of hl7-sim: several systems exchange HL7 FHIR
messages (and some ordinary web traffic) with a real FHIR server, each system in its own container
with its own IP and MAC address on one shared bridge. Everything on the bridge is captured to a PCAP
file, and every client writes an answer key of the requests it made, so the FHIR dissector can be
evaluated automatically on realistic, multi-system traffic.

All data is synthetic and deterministic per seed: Italian-style names chosen from short lists,
invented identifiers (`MRN…`), telephone numbers in a non-assignable range (`06 0…`), random
vital signs and lab values. No real person is represented.

## Contents

```
fhir_node.py            the generic node: FHIR client workflows, or a plain web server
scenari/                one folder per network: general/, ward/, laboratory/, icu/ (one .ini per node)
docker-compose.yml      base services: networks, HAPI FHIR, readiness/offload helpers, capture
labctl.py               up / down / run / generate / evaluate (used by the scripts below)
lab-up.ps1   lab-up.sh             start a scenario with the capture on
lab-down.ps1 lab-down.sh           stop it, merge the answer keys (works after an interrupted start)
generate-captures.ps1 / .sh        every scenario in turn, then evaluate them all
Dockerfile, node-entrypoint.sh     the node image: Python + requests + ethtool + tcpdump
```

Results go to `captures/netlab/` (see the README there).

## How it works

### The node

`fhir_node.py` reads an `.ini` file and becomes the system described there. A node has an
identity (`ip`, `mac`, `seed`), a default FHIR server, and one or more **flows**. A flow repeats a
workflow (a *round*) every `interval` seconds (±20 %), until the run time is over:

| `kind` | System | One round |
|---|---|---|
| `ehr` | EHR / admissions | admit a patient (Patient + Encounter, 40 % as one **transaction** Bundle); search patients by family name; read one; 50 %: update it, then sometimes `_history` and **vread**; 10 %: create, **delete** and re-read an Encounter (**410**); 10 %: read an unknown patient (**404**) |
| `lab` | laboratory information system | results for orders that are due (2–4 Observation + DiagnosticReport, 3–8 s after the order); new ServiceRequest; worklist search; 25 %: **batch** Bundle with three GETs |
| `monitor` | bedside monitor gateway | heart rate, SpO2 and blood pressure for each of 3 beds; 20 %: all of them as one **batch** Bundle (store-and-forward) |
| `clinician` | clinician workstation | multi-parameter Patient search; **XML** read; vital-sign search with `_sort`; 50 %: compartment search; 30 %: **$everything**; 40 %: **POST _search**; 30 %: open encounters |
| `web` | staff PC | 2–4 intranet pages: HTML, JS, CSS, a JSON API, a 404 (**not FHIR**) |

Options per flow: `format` (`json` or `xml` for reads/searches), `gzip` (yes/no), `connection`
(`keep-alive`, or `per-request` = a new TCP connection for every request), `server` (to send a
flow somewhere else, e.g. through the HTTPS proxy). A node with `[server:web]` is a plain web
server instead (the intranet). Each flow has its own random generator seeded with `seed/flow`, so
every run sends the same kinds of requests in the same order (server-assigned ids differ).

Every client request is written to the node's answer key (`captures/netlab/run/SCENARIO/NODE.jsonl`)
*before* the dissector is involved: time, client IP, method, path (no host, no query), query yes/no,
expected interaction, expected resource type, FHIR yes/no, encrypted yes/no, and the HTTP status
the client really received.

### The network

```
             br-fhir 10.63.0.0/24  (MTU 1500, no internet; everything here is captured)
   ┌──────────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────────┐
  hapi      intranet    ehr        lis     monitor-1/2 clinician(-2) browser  secure-clin.  tlsproxy
 .10:8080   .20:80      .21        .22     .23 / .24   .25 / .26     .28      .29 ──HTTPS──▶ .30:443
   │                                                                                          │
   └──────────────────────── br-fhir-back 10.63.1.0/24 (NOT captured) ────────────────────────┘
                                   .10                                        .30
```

- `labctl.py up` creates the Docker networks: the Linux bridges `br-fhir` and `br-fhir-back` (the
  bridge names are fixed with `com.docker.network.bridge.name`). Each node file becomes one
  container with the IP and MAC from the file.
- **Capture**: a `tcpdump` container with `network_mode: host` lives in the network namespace where
  Docker creates the bridges (on Docker Desktop: its Linux VM) and captures on `br-fhir`. It sees
  every frame between the containers, including ARP and TCP handshakes. Verified on Docker Desktop
  for Windows (WSL2 backend).
- **Offload off**: every node container turns TSO/GSO/GRO off on its interfaces at start
  (`node-entrypoint.sh`, needs `NET_ADMIN`). The HAPI and Caddy images have no shell, so a small
  helper container that shares their network stack (`network_mode: service:hapi`) does it for them.
  The capture therefore shows normal frames of at most 1514 bytes, and large FHIR responses are
  split into many TCP segments, as on a physical network.
- **HAPI** (hapiproject/hapi, FHIR R4) has no shell either, so its health is checked from outside:
  the `wait-hapi` container polls `/fhir/metadata` until it answers.
- **TLS**: in `general`, the secure clinician reaches HAPI through **Caddy** (HTTPS, self-signed
  certificate from Caddy's internal CA). The proxy forwards to HAPI over `br-fhir-back`, which is
  not captured, as with a capture point in front of a TLS terminator. On `br-fhir` these calls are
  encrypted: the answer key marks them `encrypted`, and the evaluation reports them separately
  (expected: not visible), never as misses.

Start order (as in hl7-sim's `lab-up.sh`): networks + HAPI → wait until HAPI answers → **start the
capture** → servers (intranet, proxy) → clients. So the capture contains the clients' connection
set-up but not the start-up polls. `down` stops the clients first, then the capture, then
everything else, and merges the answer keys into `captures/netlab/SCENARIO_expected.jsonl`.

## Networks provided

| Scenario | Nodes | Traffic |
|---|---|---|
| `general` | ehr, lis, monitor-1, clinician, browser + intranet, secure-clinician + tlsproxy | every node type together, including non-FHIR and encrypted traffic |
| `ward` | ehr, clinician (JSON, keep-alive), clinician-2 (XML, one connection per request), browser + intranet | a hospital ward: admissions, two workstations, intranet browsing |
| `laboratory` | ehr, lis | order → results → report workflow; the LIS opens a new connection for every request and does not use gzip |
| `icu` | ehr, monitor-1, monitor-2 | intensive care: high message rate (vital signs of 6 beds every ~3 s) |

## Captures provided

See [captures/netlab/README.md](../captures/netlab/README.md) for the table (size, duration,
exchanges, message mix) and the evaluation results.

## Requirements

- Docker Desktop (Windows/macOS) or Docker Engine (Linux), with Compose v2.24 or newer.
- Internet once, to build the node image and pull `hapiproject/hapi` and `caddy:2-alpine`.
- The project's Python (`.venv`) to run `labctl.py` and the evaluation. No admin rights are needed
  on Windows: everything privileged happens inside containers (`NET_ADMIN`, `NET_RAW`).
- About 2 GB of free memory for HAPI.

## Usage

```powershell
.\netlab\generate-captures.ps1                 # every scenario, 5 min each, then evaluate (~25 min)
.\netlab\generate-captures.ps1 -Short          # 60 s each (~10 min)
.\netlab\generate-captures.ps1 -Scenarios icu,ward -Duration 120

.\netlab\lab-up.ps1 -Scenario ward -Duration 300   # start one scenario and leave it running
.\netlab\lab-down.ps1                              # stop it and merge its answer key
python netlab\labctl.py evaluate                   # (re)evaluate everything in captures/netlab/
```

Linux/macOS: `./netlab/generate-captures.sh`, `DURATION=60 ./netlab/generate-captures.sh icu`,
`./netlab/lab-up.sh ward 300`, `./netlab/lab-down.sh`. In VS Code: **Ctrl+Shift+B** →
*Network lab: all scenarios* or *Network lab: quick run*.

Only one network lab can run at a time. While a scenario is up, the logs are visible with
`docker compose -p fhir-netlab logs -f ehr`. Check a node file without Docker:
`python netlab/fhir_node.py --node netlab/scenari/ward/ehr.ini --show`.

## Node file reference

For `ip`, `mac`, `seed` and `server` the values are examples; for the other keys the value shown
is the default.

```ini
[node]
ip       = 10.63.0.21              # address and MAC of the container on br-fhir
mac      = 02:63:00:00:00:21       # locally administered (02:...), belongs to no vendor
seed     = ehr                     # random seed (default: file name)
server   = http://10.63.0.10:8080/fhir   # default FHIR base URL of the flows
duration = 300                     # seconds; labctl overrides it with --duration

[flow:NAME]                        # one section per workflow
kind        = ehr                  # ehr | lab | monitor | clinician | web
interval    = 10                   # seconds between rounds, +-20 %
start_delay = 1                    # seconds before the first round (+ 0-1 s)
format      = json                 # json | xml: Accept of reads and searches
gzip        = yes                  # Accept-Encoding gzip, deflate | identity
connection  = keep-alive           # keep-alive | per-request (Connection: close)
server      =                      # this flow's base URL (https://... = encrypted)

[server:web]                       # instead of flows: a plain (non-FHIR) web server
port = 80

[proxy:tls]                        # read by labctl only: an HTTPS reverse proxy (Caddy)
upstream = 10.63.1.10:8080         # HAPI on the back network
```

A new network is a new folder in `scenari/` with distinct addresses in 10.63.0.0/24.

## Limits

- One FHIR server implementation (HAPI FHIR, R4) and HTTP/1.1. HAPI does not support compartment
  search by default and answers it with `400` + OperationOutcome; the call is kept, because real
  clients do get such errors.
- The virtual network has no loss, no reordering and almost no latency: the captures contain no
  retransmissions (those cases are covered by the unit tests in `tests/`).
- Workflow timings are compressed (results arrive seconds after an order); message rates are those
  of the node files, not measured from a real hospital.
- Request bodies are JSON; XML is used for responses (`format = xml`).
- The time stamps of the answer key (client clock) and of the capture (kernel) come from the same
  Docker VM, so they agree to within milliseconds; the evaluation allows 2 s.
- Encrypted traffic is generated only in `general` and only to show that it is invisible to the
  dissector; nothing is decrypted.
