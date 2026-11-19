# Detecting HL7 FHIR Exchanges in Network Traffic — Summary

## Aim

To build a modular protocol dissector module that **detects HL7 FHIR exchanges** in live traffic and in packet capture (PCAP) files, and that emits one **structured, privacy-preserving event** per HTTP request/response pair. FHIR is not a binary wire protocol but a RESTful convention over HTTP with JSON/XML resources. Detection therefore needs transport reassembly, HTTP parsing, and FHIR-specific semantic analysis.

## Method

**Lab setup.** No clinical network was available, so traffic was generated in a controlled lab: a HAPI FHIR server (v8.12.0, FHIR R4 4.0.1) in Docker, and a scripted client issuing 19 calls per run. These were 17 FHIR interactions (capabilities, create, read in JSON and XML, update, history, vread, search via GET and POST `_search`, transaction and batch Bundles, the `$everything` operation, delete, and reads that return 410 and 404) and 2 non-FHIR requests on the same server. The client records a *ground-truth* file with the real method, path, status and expected interaction of every call, independently of the dissector. Packets were captured on the loopback interface with scapy/Npcap. A standard-library mock FHIR server served as a fallback and a second test target.

**Dissector design.** Python 3, standard library plus scapy (packet I/O only; the core is independent of scapy). The pipeline has five stages:
1. **TCP reassembly:** connection tracking, client identification, sequence-number unwrapping, out-of-order buffering, retransmission and overlap trimming, and gap recovery using the peer's acknowledgement numbers.
2. **Incremental HTTP/1.1 parsing:** Content-Length, chunked transfer, gzip/deflate, HEAD/1xx/204/304/101 semantics, pipelining, resynchronisation after corrupt input. FIFO request/response pairing on keep-alive connections.
3. **FHIR detection:** a weighted, explainable score from eight signals (FHIR media types, `Accept`, top-level `resourceType`, FHIR XML namespace, `_format`, resource-type path segments, `/metadata`, `/fhir` base). Threshold 0.5.
4. **Classification:** segment-based URL analysis against the full R4+R5 resource list, mapping method + path to 20+ FHIR interactions, with base, resource type, id, version and operation.
5. **Event building with redaction by default:** search parameter names only, no query strings, no tokens, no resource contents, no diagnostic text.

Offline and live modes share the same code path.

**Verification.** 156 automated tests run without Docker, network or privileges. They use synthetic TCP conversations with shuffled and duplicated segments, missing handshakes, IPv6, sequence wrap-around and lost segments. The real captures are scored by an evaluator that matches events to ground truth on (method, path, status).

## Results

| Run | Calls | TP | FP | FN | TN | Precision | Recall | Interaction accuracy |
|---|---|---|---|---|---|---|---|---|
| Offline PCAP (HAPI, 268 packets) | 19 | 17 | 0 | 0 | 2 | 100% | 100% | 100% |
| Live capture (HAPI, 260 packets) | 19 | 17 | 0 | 0 | 2 | 100% | 100% | 100% |
| Offline PCAP (mock server) | 19 | 17 | 0 | 0 | 2 | 100% | 100% | 100% |

Resource-type accuracy was also 100%, and live events were identical to the offline events. Robustness and cost: 100,000 random TCP segments caused no failure; a raw-frame decoder processes about 26,500 packets/s on one CPU core (8 times faster than generic scapy decoding, with identical output); memory is bounded by caps on tracked connections, queued requests, buffered out-of-order data and stored body size. The default output contained none of the synthetic patient data (names, birth dates, telephone numbers, search values, server diagnostics). The real HAPI traffic was IPv6 loopback with gzip-compressed, chunked responses.

The lab surfaced one capture artefact worth reporting. Loopback TCP segments reached 65,475 data bytes (65,539-byte frames), which exceeded the default 65,535-byte capture/read limit of the capture library and silently cut 4 bytes from large frames. The dissector's ACK-based gap recovery kept request/response pairing correct in that case. The lab tools now capture, write and read with a 262,144-byte limit.

## Limitations

Plaintext HTTP/1.1 only (no TLS, no HTTP/2, no WebSocket subscriptions). The evaluation is a small, controlled loopback lab against one server implementation (HAPI, R4). It shows correctness on the covered interactions, not accuracy on real clinical traffic or performance at scale. Detection is heuristic: non-FHIR APIs that imitate FHIR paths and payloads would be counted as FHIR. XML support is limited to metadata. There is no profile validation.

## Future work

TLS visibility (key-log files or proxy integration); HTTP/2 and WebSocket subscriptions; HL7 v2/MLLP as a sibling module; SMART-on-FHIR/OAuth flow detection; evaluation on larger and more varied traffic (other servers such as Firely or Microsoft FHIR, PATCH and conditional operations, paging, error cases) and on anonymised real-world captures; throughput benchmarking and optimisation.
