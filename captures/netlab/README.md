# Network-lab captures

One capture per scenario of the emulated FHIR hospital network (`netlab/`), recorded on the bridge
`br-fhir` for five minutes with `.\netlab\lab.ps1 generate`, from the start of the clients to their
end. HAPI FHIR R4 (v8.12.0) at 10.63.0.10:8080; MTU 1500 with TCP offload off; all data synthetic.

For each scenario:

- `NAME.pcap`: the capture (Ethernet, every frame at most 1514 bytes);
- `NAME_expected.jsonl`: the answer key, merged from all client nodes (one line per request: time,
  client IP, method, path, query yes/no, expected interaction and resource type, FHIR yes/no,
  encrypted yes/no, HTTP status received);
- `NAME_evaluation.txt`: the dissector evaluated against the answer key.

`summary.txt` has the table of all scenarios.

| File | Size | Duration | Frames | Client systems | Exchanges | Message mix |
|---|---|---|---|---|---|---|
| `general.pcap` | 4.4 MB | 304 s | 24,678 | 6: ehr, lis, monitor-1, clinician, browser, secure-clinician (+ intranet, TLS proxy) | 1,080 = 796 FHIR + 149 non-FHIR + 135 encrypted | create 502, search-type 135, read 72, batch 17, update 17, transaction 15, search-compartment 11, operation 10, history-instance 6, vread 6, delete 5 |
| `ward.pcap` | 1.7 MB | 304 s | 5,398 | 4: ehr, clinician, clinician-2 (XML, new connection per request), browser (+ intranet) | 683 = 504 FHIR + 179 non-FHIR | search-type 224, read 119, create 53, search-compartment 34, operation 25, update 17, transaction 15, history-instance 6, vread 6, delete 5 |
| `laboratory.pcap` | 3.4 MB | 300 s | 26,295 | 2: ehr, lis (new connection per request, no gzip) | 437 FHIR | create 278, search-type 80, read 34, transaction 14, update 12, batch 5, history-instance 5, vread 5, delete 4 |
| `icu.pcap` | 5.2 MB | 300 s | 24,899 | 3: ehr, monitor-1, monitor-2 | 1,562 FHIR | create 1,433 (vital signs), batch 41, read 29, search-type 25, transaction 11, update 9, history-instance 5, vread 5, delete 4 |

HTTP statuses in the traffic: 200 and 201 for most calls; 410 after deletions; 404 for stale links
and intranet misses; 400 from HAPI for compartment searches (not enabled by default in HAPI).

## Dissector results

| Scenario | Calls | Encrypted | TP | FP | FN | TN | Precision | Recall | Interaction acc. | Resource-type acc. | Max frame | TCP conns |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| general | 1,080 | 135 | 796 | 0 | 0 | 149 | 100 % | 100 % | 100 % | 100 % | 1514 | 173 |
| ward | 683 | 0 | 504 | 0 | 0 | 179 | 100 % | 100 % | 100 % | 100 % | 1514 | 185 |
| laboratory | 437 | 0 | 437 | 0 | 0 | 0 | 100 % | 100 % | 100 % | 100 % | 1514 | 299 |
| icu | 1,562 | 0 | 1,562 | 0 | 0 | 0 | 100 % | 100 % | 100 % | 100 % | 1514 | 17 |
| **total** | **3,762** | **135** | **3,299** | **0** | **0** | **328** | **100 %** | **100 %** | **100 %** | **100 %** | | |

The 135 encrypted calls (HTTPS through the TLS proxy) are not visible to the dissector, as expected:
0 events were produced for that client, and they are not counted as misses. Large messages are split
into many TCP segments (up to 356 for one uncompressed search Bundle in `laboratory`), so TCP
reassembly is exercised on every capture.

Re-evaluate: `.\netlab\lab.ps1 evaluate`, or one file:
`python lab\evaluate.py --pcap captures\netlab\icu.pcap --expected captures\netlab\icu_expected.jsonl`.
