# FHIR lab captures (PCAP)

Packet captures of HL7 FHIR traffic recorded in a controlled lab, used to develop and evaluate the FHIR dissector. Each capture comes with its ground truth and the dissector's score on it.

| File | Content |
|---|---|
| `fhir_hapi.pcap` | 19 HTTP exchanges with a **HAPI FHIR server** (v8.12.0, FHIR R4 4.0.1, Docker), 238 packets |
| `fhir_hapi_expected.json` | ground truth: method, path, status and FHIR interaction of every call |
| `fhir_hapi_evaluation.txt` | dissector result on this capture (per-call table + metrics) |
| `fhir_mock.pcap` | the same 19 exchanges with a small Python mock FHIR server (no gzip/chunking), 142 packets |
| `fhir_mock_expected.json` | ground truth for the mock capture |
| `fhir_mock_evaluation.txt` | dissector result on the mock capture |

## What is inside

One scripted client session (keep-alive) plus a separate non-FHIR session, in this order:

| # | Request | FHIR interaction |
|---|---|---|
| 1 | `GET /fhir/metadata` | capabilities |
| 2–3 | `POST /fhir/Patient` (×2) | create |
| 4 | `GET /fhir/Patient/{id}` (JSON) | read |
| 5 | `GET /fhir/Patient/{id}` with `Accept: application/fhir+xml` | read (XML) |
| 6 | `PUT /fhir/Patient/{id}` | update |
| 7 | `GET /fhir/Patient/{id}/_history` | history-instance |
| 8 | `GET /fhir/Patient/{id}/_history/1` | vread |
| 9 | `GET /fhir/Patient?family=Rossi&_count=5` | search-type |
| 10 | `POST /fhir/Patient/_search` (form body) | search-type |
| 11 | `POST /fhir/Observation` | create |
| 12 | `POST /fhir` (transaction Bundle: Patient + Observation) | transaction |
| 13 | `POST /fhir` (batch Bundle: 2 GETs) | batch |
| 14 | `GET /fhir/Patient/{id}/$everything` | operation |
| 15 | `DELETE /fhir/Observation/{id}` | delete |
| 16 | `GET /fhir/Observation/{id}` → 410 Gone | read |
| 17 | `GET /fhir/Patient/does-not-exist-999` → 404 | read |
| 18–19 | `GET /` (HTML page), `GET /favicon.ico` | not FHIR |

17 FHIR calls covering 11 interaction types, plus 2 non-FHIR calls on the same server.

## Capture set-up

- Windows 11, Npcap loopback adapter, scapy; link type NULL/loopback; IPv6 (`::1`); snaplen 262,144 bytes (full packets).
- HAPI responses use `Content-Encoding: gzip` and `Transfer-Encoding: chunked`; the mock server uses plain `Content-Length` bodies.
- Server port: **8090** (HAPI) and **8081** (mock).
- **All patient data is synthetic** (made-up names such as "Mario Rossi"); no real or personal data.

## Dissector result on these captures

| Capture | Calls | TP | FP | FN | TN | Precision | Recall | Interaction accuracy |
|---|---|---|---|---|---|---|---|---|
| `fhir_hapi.pcap` | 19 | 17 | 0 | 0 | 2 | 100% | 100% | 100% |
| `fhir_mock.pcap` | 19 | 17 | 0 | 0 | 2 | 100% | 100% | 100% |

## How to open / use

**Wireshark:** open the file, then *Analyze → Decode As… → TCP port 8090 (or 8081) → HTTP* (these are not standard HTTP ports, so Wireshark shows plain TCP until told). Then filter `http` and use *Follow → HTTP Stream*.

**Dissector:**
```
python -m fhir_dissector pcap captures/pcaps/fhir_hapi.pcap -o events.jsonl
python lab/evaluate.py --pcap captures/pcaps/fhir_hapi.pcap --expected captures/pcaps/fhir_hapi_expected.json
```

**Record a new capture:** start a FHIR server (`python lab/live_demo.py start`), then `python lab/live_demo.py record` (writes `fhir_<server>_<date>_<time>.pcap` with its ground truth and score here).
