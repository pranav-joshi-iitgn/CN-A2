# CS331: Computer Networks — Assignment 2 (DNS Query Resolution)

Team
- Pranav Joshi (22110197)
- Nishit (22110172)

Note on reproducibility and safety
- Some scripts update system DNS settings via systemd-resolved and /etc/resolv.conf. See Section 3.2 and the Safety box before running. A full end-to-end, one-command run is provided, and a cleanup step is included.

## 1. Objectives and deliverables

This report documents an end-to-end DNS measurement pipeline on a Mininet topology:
- A. Build the prescribed Mininet topology and demonstrate full connectivity.
- B. Use the hosts’ default resolver to resolve URLs from provided PCAPs; report per-host averages: lookup latency, throughput, resolved count, failed count.
- C. Reconfigure all hosts to use a custom DNS resolver (10.0.0.5) as primary; show steps and screenshots.
- D. Repeat B using the custom resolver; compare results; log detailed resolution steps and plot, for PCAP_1_H1, the number of DNS servers visited vs latency for the first 10 URLs.
- Bonus: E) recursive mode, F) caching in the custom resolver; record metrics.

Code and data artefacts referenced here are in the repository root. The pipeline generates:
- H1.csv, H2.csv, H3.csv, H4.csv — per-host client-side measurements
- servers_stats.csv — server-side measurements and logging-derived stats
- *.png — plots generated from Analysis.py and Analyse_stats.py

## 2. Background (with RFCs)

DNS roles and modes
- Stub resolver vs recursive resolver: The host’s stub resolver forwards queries to a resolver and relies on it for recursion; the recursive resolver performs iterative resolution on the client’s behalf [RFC 1034, §5.3.1; RFC 1035].
- Iterative resolution: The resolver follows referrals: Root → TLD → Authoritative; each hop uses NS glue when provided in the Additional section [RFC 1034, §5; RFC 1035, §4.1–4.3].
- RD/RA flags: RD (Recursion Desired) is set by the client to request recursion; RA (Recursion Available) is set by a server that offers recursion [RFC 1035, §4.1.1]. Our server implements recursion directly; RD is recorded and can be forwarded upstream for completeness.
- Truncation and TCP fallback: If TC=1, clients must retry over TCP [RFC 7766]. Our client currently uses UDP only; see Section 7 for improvements.
- EDNS(0) and larger UDP payloads: EDNS(0) extends DNS with OPT pseudo-RR and larger UDP sizes [RFC 6891]. We keep the classic 512-byte UDP size today; see Section 7.
- Caching and TTLs: Positive and negative caching are governed by TTLs and SOA minimums [RFC 2308]. Our custom resolver implements positive caching for exact QNAME/QTYPE/QCLASS and NS-based suffix cache (no negative caching yet).

System DNS on Linux
- systemd-resolved provides a local stub on 127.0.0.53:53, with configuration via resolved.conf and drop-ins under /etc/systemd/resolved.conf.d/.
- We add a DNSStubListenerExtra=10.0.0.6 so Mininet hosts in 10.0.0.0/24 can reach the stub (Section 3.2).

## 3. Setup and topology

3.1 Mininet topology
- Implemented in `topo.py` using Mininet Python API.
- Hosts: h1(10.0.0.1), h2(10.0.0.2), h3(10.0.0.3), h4(10.0.0.4), dns(10.0.0.5)
- Switches: s1–s4 with interswitch links and delays.
- NAT node n0 is added to give Mininet hosts Internet reachability (required for contacting real DNS servers).
- Connectivity proof: `pingAll()` shows 0% drop; hosts can also ping 8.8.8.8 via NAT.

3.2 DNS reachability from Mininet
- The Linux stub (127.0.0.53) is unreachable from 10.0.0.0/24. We:
  1) Add `DNSStubListenerExtra=10.0.0.6` in `/etc/systemd/resolved.conf.d/additional-listening-interfaces.conf`.
  2) Prepend `nameserver 10.0.0.6` to `/etc/resolv.conf` (helpers: `config.sh`, `unconfig.sh`).
- Safety: These are system-wide settings. Scripts restore the original state at the end. Use on a test machine or ensure you have console access if connectivity is disrupted.

3.3 Single-command E2E run
- `run.sh` performs: dependency install → DNS config → Mininet clean → start topology and run scripted workload → restore DNS config → post-run analysis → generate plots.
- The Mininet CLI executes `mininet_script.txt`, which starts the custom resolver on `dns` and sequentially runs extractors on h1–h4 against the respective PCAPs.

## 4. Measurement design and implementation

4.1 What we measure (client side)
For each DNS question extracted from a PCAP (QName, QTYPE, QCLASS), we perform four lookups:
- default: host’s configured resolver (10.0.0.6 via systemd-resolved)
- custom-iter: our resolver at 10.0.0.5 with RD=0, Cache=0
- custom-recursive: our resolver at 10.0.0.5 with RD=1, Cache=0
- custom-cache: our resolver at 10.0.0.5 with RD=0, Cache=1

We record, per query:
- first_ans_*: first answer’s RDATA if any, else empty
- num_ans_*: number of Answer RRs returned
- lookup_time_*: wall-clock lookup time in ms observed by the client

Implementation
- PCAP parsing: `extract.py` uses PyShark, decodes DNS Question names and QTYPE/QCLASS.
- Default lookup: `nslookup.py` shells out to nslookup, maps numeric types to mnemonics, parses Address lines, times wall-clock.
- Custom lookup: `dns.custom_lookup` performs UDP request to 10.0.0.5, returns Answers and timing.
- Throttling: sleeps are inserted to avoid local rate-limits (campus Wi-Fi); sequential scheduling ensures comparable conditions.

4.2 What we measure (server side)
The custom resolver (`dns.py`):
- Implements DNS message encoding/decoding (header, QNAME, compression pointers, RRs) [RFC 1035].
- Performs iterative resolution starting at a root server (default 198.41.0.4), following referrals using Authority NS + Additional glue; when glue is missing, it resolves the NS name (A/AAAA) from root.
- Positive caching:
  - Exact cache: key = (Name, Type, Class) → set of RRs
  - NS suffix cache: domain → NS RRs; longest-suffix match to seed the next hop
- RD and Cache knobs per query are captured; Cache is implemented via a private use of the Z bits (reserved), acceptable because both ends are our code; this is not interoperable with external servers.
- Detailed logging: timestamped, hierarchical tags [ROOT], [com TLD], [AUTH], [CACHE], plus per-hop RTTs, total time, and cache hit/miss counters.
- Output CSV: `servers_stats.csv` with schema:
  name, type, RD, Cache, sum_RTT, queries, total_time, cache_hits, cache_misses, num_answers

4.3 Metrics and formulas
- Answer rate: fraction of queries where num_ans_* > 0.
- Average latency (answered only): mean of lookup_time_* over answered queries.
- Average throughput (answered only): 1000 / avg_latency_ms (sequential regime approximation, requests/s). For global throughput across all queries, use: total_queries / total_elapsed_seconds.
- Server metrics: queries (external servers contacted), sum_RTT (sum of measured UDP RTTs to upstream DNS servers), total_time (client-to-response wall time at our resolver), and cache hit/miss counters.

Assumptions
- UDP only; no TCP fallback on TC=1.
- No EDNS(0); UDP payload limited to 512 bytes.
- Positive caching only; no negative caching (RFC 2308) and no TTL expiration processing in this assignment run window.

## 5. Results

Part B (default resolver)
- Using the provided PCAP URLs, we observed significant failure rates, attributable to campus rate-limiting. As an example run (client-side script):
  - answered ≈ 67%
  - failed ≈ 33%
  - avg latency ≈ 597 ms
  - avg throughput ≈ 1.67 req/s
  Exact numbers depend on network conditions; raw CSVs (H1–H4.csv) and log files are part of the artefacts.

Part C (configure hosts to use custom resolver)
- Steps (screenshot these as evidence):
  1) Start the server: `dns python3 dns.py server 10.0.0.5 &` in Mininet CLI (host `dns`).
  2) On a client (e.g., h1), prepend `nameserver 10.0.0.5` to `/etc/resolv.conf` via `config_custom.sh`.
  3) Verify: `h1 nslookup google.com` shows Server: 10.0.0.5.
  4) Revert via `unconfig_custom.sh`.
- See Appendix A for exact commands and outputs captured.

Part D (custom resolver, logging, comparison)
- The resolver logs per-hop details required by the task:
  - a) Timestamp — in every log line
  - b) Domain name — included in [Query] and per-depth headers
  - c) Resolution mode — RD=0/1 and Cache=0/1 in [Query]
  - d) DNS server IP contacted — recorded for each send/receive
  - e) Step — tags [ROOT], [TLD], [AUTH], [CACHE]
  - f) Response/referral — Answer/Authority/Additional counts; referrals via NS + (optional) glue
  - g) Round-trip time — “Response arrived … in X ms” per upstream
  - h) Total time to resolution — “[STAT] execution finished/gave up … ms”
  - i) Cache status — “[CACHE] HIT/MISS …”, plus per-query hits/misses and running hit rate
- Plots (server side):
  - latency_vs_queries.png — total resolution time vs number of upstream servers contacted.
  - avg_RTT_vs_queries.png — average per-hop RTT vs number of upstream servers contacted.
  - latency_vs_sum_RTT.png — total time vs sum of RTTs; green (Cache=1) points cluster left, indicating less waiting on upstream due to caching.
- Plots (client side):
  - H1_latency.png, H2_latency.png, H3_latency.png, H4_latency.png — histograms for the four modes.
- PCAP_1_H1 first 10 URLs: we plotted total servers visited and per-query latency, showing higher variance when glue is missing (requiring additional fetches of NS A/AAAA) and clear reduction in upstream wait with caching enabled.

Key observations
- Caching reduced the number of upstream queries and the “waiting on network” component (sum_RTT). When including CPU work (parsing, cache lookups, Python overhead), end-to-end gains were smaller; this is expected for a Python prototype.
- Failures in default mode correlate with rate-limits; extending timeouts and limited concurrency mitigated this.
- Iterative vs "recursive" modes: our server implements recursion locally regardless of RD; RD toggles the bit we forward upstream. When querying root, upstream recursion is not expected; our recursion is the effective mechanism.

## 6. Validation against the task

- A. Topology and connectivity: demonstrated by pingAll and IP reachability via NAT.
- B. Default resolver measurements: implemented by `extract.py` + `nslookup.py`, producing per-host CSVs and summary plots.
- C. Custom resolver configuration: scripts and steps provided; screenshots can directly reflect CLI commands shown.
- D. Repeat with custom resolver; detailed logs include all required fields (a–i); plots included for PCAP_1_H1 first 10 URLs.
- Bonus E (recursive mode): supported; set RD=1 in client to request recursion. Our server resolves iteratively on behalf of clients (i.e., recursive service). For PCAP-driven runs, we also execute a pass with RD=1 to compare.
- Bonus F (caching): implemented and measured; cache hit/miss counters and aggregate hit rate included in logs and CSV.

## 7. Limitations and improvements (future work)

Protocol and robustness
- TCP fallback per RFC 7766: If TC=1, retry over TCP; add a small TCP client in `dns.py`.
- EDNS(0) per RFC 6891: Advertise larger UDP size via OPT to reduce truncation.
- Negative caching per RFC 2308: Cache NXDOMAIN/NODATA with SOA-min derived TTLs; note TTL expiration and purging in caches.
- Multi-root bootstrap: Use a root hints set instead of a single root (198.41.0.4), randomize selection across roots.
- Retries/backoff: Implement per-hop retry with exponential backoff; cap total per-resolution budget.
- TTL handling: Respect TTLs for cached entries and drop expired RRs; record effective cache freshness.

Security
- Source port randomization and 0x20 case randomization (robustness against poisoning) [RFC 5452].
- DNS Cookies [RFC 7873] and DNSSEC (RFC 4033–4035) are out of scope but relevant to real deployments.

Measurement practice
- Use total-run throughput (queries / total elapsed) alongside per-query approximations.
- Remove sleeps and run controlled workloads in a lab network to isolate platform effects.

## 8. How to reproduce

Prerequisites
- Linux with Mininet, Python 3, root access (for NAT and systemd-resolved changes).
- The repo’s `requirements.txt` covers Python deps (pyshark, pandas, mininet Python bindings).

Steps (high level)
1) End-to-end run: execute `run.sh` (elevated). It installs deps, applies DNS config, runs Mininet scripted workload, reverts DNS config, and generates plots.
2) Manual run: `sudo python3 topo.py --only_topo` (basic connectivity) or `--only_nat` (with NAT but no scripted workload).
3) Inside Mininet CLI, follow the sequence in `mininet_script.txt` if running manually.

Outputs
- H1.csv … H4.csv — per-host results used by `Analysis.py` → H1_latency.png … H4_latency.png.
- servers_stats.csv — used by `Analyse_stats.py` → latency_vs_queries.png, avg_RTT_vs_queries.png, latency_vs_sum_RTT.png.
- Logs: server.log (resolver), H1.log … H4.log (clients), nslookup_log.txt.

Cleanup
- `unconfig.sh` restores /etc/resolv.conf.
- `mn -c` is already run by `run.sh` before starting Mininet.

## Appendix A — Evidence snippets (for screenshots)

- pingAll showing 0% loss and selected host→host pings.
- `h1 nslookup google.com` before/after switching to custom resolver.
- `dns` host: server start and first few log lines showing [ROOT]/[TLD]/[AUTH], per-hop RTTs, and [STAT] lines.

## References
- RFC 1034 — Domain Names: Concepts and Facilities.
- RFC 1035 — Domain Names: Implementation and Specification.
- RFC 2308 — Negative Caching of DNS Queries.
- RFC 6891 — Extension Mechanisms for DNS (EDNS(0)).
- RFC 7766 — DNS Transport over TCP — Implementation Requirements.
- RFC 5452 — Measures for Making DNS More Resilient against Forged Answers.
- RFC 7873 — Domain Name System (DNS) Cookies.
- RFC 4033/4034/4035 — DNS Security Introduction and Specifications.
