# Detecting HL7 FHIR Exchanges in Network Traffic — Summary

## Aim

To build a modular protocol dissector module that **detects HL7 FHIR exchanges** in live traffic and in packet capture (PCAP) files, and that emits one **structured, privacy-preserving event** per HTTP request/response pair. FHIR is not a binary wire protocol but a RESTful convention over HTTP with JSON/XML resources. Detection therefore needs transport reassembly, HTTP parsing, and FHIR-specific semantic analysis.

## Method

**Dissector design.** Python 3, standard library plus scapy (packet capture only; the core is independent of scapy). Packets are decoded by a fast raw-frame decoder (IPv4/IPv6, Ethernet/VLAN, loopback, Linux cooked capture) and pass through six stages:
1. **TCP reassembly:** connection tracking, client identification, sequence-number unwrapping, out-of-order buffering, retransmission and overlap trimming, and gap recovery using the peer's acknowledgement numbers. FIFO request/response pairing on keep-alive connections.
2. **Incremental HTTP/1.1 parsing:** Content-Length, chunked transfer, gzip/deflate, HEAD/1xx/204/304/101 semantics, pipelining, resynchronisation after corrupt input.
3. **Body summary:** metadata only from JSON/XML bodies (resource type, id, version, Bundle type and entry counts, OperationOutcome severity/code), never resource contents.
4. **Classification:** segment-based URL analysis against the full R4+R5 resource list, mapping method + path to 20+ FHIR interactions, with base, resource type, id, version and operation.
5. **FHIR detection:** a weighted, explainable score from eight signals (FHIR media types, `Accept`, top-level `resourceType`, FHIR XML namespace, `_format`, resource-type path segments, `/metadata`, `/fhir` base). Threshold 0.5.
6. **Event building with redaction by default:** search parameter names only, no query strings, no tokens, no resource contents, no diagnostic text.

**Evaluation network.** No clinical network was available, so an emulated hospital network was built in Docker, following the design of an existing HL7 v2 network emulator from our lab (hl7-sim). One generic node program, configured by an `.ini` file per system, plays an EHR/admissions system, a laboratory information system, bedside-monitor gateways, clinician workstations, and an intranet web server with a browsing client. Each system runs in its own container with its own IP and MAC address on one Linux bridge (MTU 1500), with TCP segmentation/receive offload disabled so that every frame is at most 1514 bytes, as on a physical network. The FHIR server is HAPI FHIR 8.12.0 (R4). The workflows follow clinical patterns: admissions with transaction Bundles, updates, history and version reads, deletions followed by reads of the deleted resource (410), stale links (404), laboratory orders followed by results and reports, vital signs every few seconds with occasional batch Bundles, multi-parameter and XML searches, `$everything`. Clients differ in JSON/XML, gzip use and connection reuse (keep-alive or one connection per request). One clinician reaches the server through an HTTPS reverse proxy, whose backend link is not captured. All data are synthetic and deterministic per seed.

A capture container records the bridge for five minutes per scenario. Each client writes its own ground truth for every request (time, client IP, method, path, expected interaction and resource type, FHIR or not, encrypted or not, HTTP status received). An evaluator matches each ground-truth call to a dissector event of the same client IP, method, path and status, closest in time (within 2 s), and computes detection and classification metrics; encrypted calls are reported separately. Four scenarios were run: a general network with every system type, a ward, a laboratory, and an intensive-care unit with a high message rate.

The parser and reassembly are also covered by 192 unit tests on synthetic packets (shuffled, duplicated and lost segments, missing handshakes, IPv6, sequence wrap-around, every byte-boundary split of chunked bodies).

## Results

> Evaluated on **3,627 exchanges** from **6 concurrent systems** on an emulated hospital network (separate hosts, 1500-byte MTU), over **4 scenarios of 5 minutes each**, with automatic ground truth: **precision 100 %, recall 100 %, interaction accuracy 100 %**.

| Scenario | Client systems | Calls | of which encrypted | TP | FP | FN | TN | Precision | Recall | Interaction accuracy |
|---|---|---|---|---|---|---|---|---|---|---|
| General | 6 | 1,080 | 135 | 796 | 0 | 0 | 149 | 100 % | 100 % | 100 % |
| Ward | 4 | 683 | 0 | 504 | 0 | 0 | 179 | 100 % | 100 % | 100 % |
| Laboratory | 2 | 437 | 0 | 437 | 0 | 0 | 0 | 100 % | 100 % | 100 % |
| Intensive care | 3 | 1,562 | 0 | 1,562 | 0 | 0 | 0 | 100 % | 100 % | 100 % |
| **Total** | | **3,762** | **135** | **3,299** | **0** | **0** | **328** | **100 %** | **100 %** | **100 %** |

The 3,627 plaintext exchanges (3,299 FHIR, 328 non-FHIR) come from up to six concurrent client systems per scenario (eight distinct systems over the four scenarios), plus the server, the intranet server and the TLS proxy. They cover eleven FHIR interaction types, statuses 200/201/400/404/410, JSON and XML, compressed and uncompressed bodies, and 17 to 299 TCP connections per capture. Resource-type accuracy was also 100 %. Every frame was at most 1514 bytes; large messages were split into up to 356 TCP segments. The 135 calls sent over HTTPS were, as expected, invisible to the dissector (no event) and are not counted as misses. The dissector processed the captures at 1,500–4,400 events (35,000–89,000 packets) per second on one CPU core, and 100,000 random TCP segments caused no failure.

The emulated network did not reveal new defects in the dissector. An earlier loopback test had revealed one capture artefact: loopback TCP segments of up to 65,475 bytes exceeded the default 65,535-byte capture/read limit of the capture library and silently lost 4 bytes per frame; the dissector's ACK-based gap recovery kept request/response pairing correct, and the tools now use a 262,144-byte limit.

## Limitations

Plaintext HTTP/1.1 only (no TLS decryption, no HTTP/2, no WebSocket subscriptions). The evaluation uses one server implementation (HAPI, R4) and designed workflows on an emulated network without loss, reordering or latency; it shows correctness on the covered interactions, not accuracy on real clinical traffic or performance at scale. Detection is heuristic: non-FHIR APIs that imitate FHIR paths and payloads would be counted as FHIR. XML support is limited to metadata. There is no profile validation.

## Future work

TLS visibility (key-log files or proxy integration); HTTP/2 and WebSocket subscriptions; HL7 v2/MLLP as a sibling module; SMART-on-FHIR/OAuth flow detection; network impairments in the lab (loss, delay, reordering); other servers (Firely, Microsoft FHIR) and anonymised real-world captures; analysis on top of the events (baselines of normal FHIR usage, detection of unusual access).
