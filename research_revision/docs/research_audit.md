# Complete Repository & Implementation Audit

**Document:** `research_revision/docs/research_audit.md`  
**Auditor:** Senior IEEE Research Supervisor, Technical Auditor, and Systems Engineer  
**Date:** October 31, 2026  
**System:** DeepPacket Analyzer (C++17 Engine + Node.js Telemetry Service)

---

## 1. Executive Summary

A comprehensive, line-by-line technical audit of the DeepPacket Analyzer repository was performed, covering the C++17 engine source code (`src/`, `include/`), CMake build configuration, unit/integration test suites (`tests/`), synthetic and live benchmark scripts (`scripts/`), captured PCAP datasets (`dataset_capture_1..4.pcap`), ground truth labels (`ground_truth_1..4.csv`), and the submitted IEEE research manuscript.

The core C++17 processing pipeline (packet parsing, fast-path filtering, TLS SNI extraction, HTTP host parsing, DNS parsing, and bounded ring-buffer telemetry) is well-structured and performs efficiently. However, the audit uncovered **critical scientific discrepancies, methodological flaws, and data-pipeline artifacts** between the empirical codebase and the claims made in the manuscript. This audit documents all verified features, unverified assertions, software bugs, and necessary corrective actions.

---

## 2. Verified Implementation Features

The following architectural components and features were verified directly in the C++ source code and confirmed functional via automated tests:

1. **Protocol Stack Parsers (`src/packet_parser.cpp`)**:
   - Ethernet II (`DLT_EN10MB`, 14-byte frame header, EtherType validation).
   - IPv4 header parsing with IHL validation, total length checks, protocol dispatch (TCP/UDP), and IP fragmentation detection.
   - IPv6 base header parsing with Next Header chaining for common extension headers (Hop-by-Hop, Routing, Fragment).
   - TCP header parsing with data offset validation, flag extraction (SYN, ACK, PSH, RST, FIN), sequence/acknowledgment numbers, and payload pointer calculation.
   - UDP header parsing with length validation and payload pointer calculation.
2. **Bounds-Checked Protocol Parsers**:
   - **TLS SNI Extractor (`src/sni_extractor.cpp`)**: Verified robust parsing of TLS Client Hello (handshake type 0x01, record 0x16 0x03). Iterates extensions safely, locates Server Name extension (0x0000), extracts hostname with strict bounds checking against buffer length.
   - **DNS Parser (`src/dns_parser.cpp`)**: Parses DNS queries (UDP/53) and answers. Supports label decompression pointers (0xC0 offset), extracts A records, parses TTL, and handles multi-answer resource records.
   - **HTTP Host Parser (`src/http_parser.cpp`)**: Extracts `Host:` header from plaintext HTTP/1.0 and HTTP/1.1 requests on port 80.
3. **FastPath Gatekeeper (`src/fast_path.cpp`)**:
   - Pre-filters packets before DPI inspection. Dispatches only ports 80, 443, and 53 with valid payload lengths.
4. **Weighted Multi-Domain DNS Cache (`src/probabilistic_dns_cache.cpp`)**:
   - Maps IPv4 address (`uint32_t`) to `std::vector<DnsRecord>`.
   - Thread safety enforced via `std::shared_mutex` (reader/writer locks).
   - Bounded vector per IP (capped at 5 domains).
   - Sorts candidates descending by observation weight (`weight`), breaking ties by expiration timestamp.
   - TTL-based expiration and lazy/active cleanup (`cleanupExpired()`).
   - Tracks collision/ambiguity count via `getOverwriteCount()`.
5. **TCP Stream Reassembler (`src/tcp_reassembler.cpp`)**:
   - Tracks 4-tuple connections for segmented TLS Client Hellos on port 443.
   - Buffers payload up to 2,048 bytes per flow.
   - Reassembles in-order sequence continuity (`seq == flow.next_seq`).
   - Invokes SNI extraction on accumulated stream; evicts buffer immediately upon successful extraction.
   - Idle flow timeout eviction (5 seconds).
6. **Bounded Telemetry Engine (`src/stats_collector.cpp`, `src/traffic_analytics.cpp`)**:
   - Caps packet ring to 300 records, flow ring to 100/500 records, timeline to 300 seconds, and endpoint/port hash maps to 4,096 keys.
   - Serializes consistent JSON snapshots (`output.json`) periodically (500 ms in live mode, 1,000 packets in offline mode).
7. **Thread Management & Queuing (`src/packet_queue.cpp`)**:
   - Mutex-protected bounded producer-consumer queue (10,000 packets capacity) with condition variables and shutdown signaling.
8. **Dynamic WFP Enforcement Architecture (`src/wfp_enforcement.cpp`)**:
   - Dynamic session management (`FWPM_SESSION_FLAG_DYNAMIC`), auto-clearing kernel filters on crash or exit.
   - Installs ALE connect layer v4 (`FWPM_LAYER_ALE_AUTH_CONNECT_V4`) filters for blocked IPs and ports.

---

## 3. Unverified Implementation Features

The following features are described in the manuscript or comments but are **NOT VERIFIED** or lack empirical execution proof:

1. **Active WFP Kernel Enforcement in Non-Elevated Environments**:
   - WFP filter installation requires Windows Administrator privileges. In non-elevated CI/test environments, WFP initialization fails gracefully and reverts to `MONITOR ONLY`. Actual packet dropping at the NDIS/WFP kernel layer was **NOT VERIFIED** in the test suite.
2. **QUIC SNI Extraction**:
   - The engine detects QUIC v1 Initial packets (UDP/443 with long header 0xC0 and version 0x00000001), but explicitly does NOT decrypt or extract QUIC SNI. The manuscript properly notes this limitation in Section I, but references to QUIC must avoid implying classification capability.
3. **IPv6 Firewall Enforcement**:
   - WFP rules are only implemented for IPv4 (`FWPM_LAYER_ALE_AUTH_CONNECT_V4`). IPv6 enforcement is entirely unimplemented.

---

## 4. Missing Functionality

1. **PCAPNG File Support**: Only legacy libpcap (`0xa1b2c3d4` / `0xd4c3b2a1`) format is supported. Modern Wireshark `.pcapng` files fail on open.
2. **VLAN Tag Handling (IEEE 802.1Q / 802.1ad)**: Frames containing EtherType `0x8100` are treated as non-IP and skipped.
3. **TCP Out-of-Order Segment Buffering**: `TcpReassembler` only handles strictly contiguous segments (`seq == flow.next_seq`). If segment 2 arrives before segment 1, it is dropped rather than held in a reorder buffer.
4. **Automated End-to-End C++ Unit Test Runner**: Unit tests are executed via Node.js (`node --test tests/*.test.js`) rather than native C++ testing frameworks (e.g., GTest, Catch2).

---

## 5. Critical Technical Inconsistencies & Scientific Flaws Discovered

During this audit, five critical scientific integrity and data pipeline flaws were discovered:

### A. The 500-Flow Buffer Truncation Artifact
- **Root Cause**: `ConnectionTracker::recent_flows_` is a `std::vector` ring buffer capped at 500 elements (`src/connection_tracker.cpp:352`).
- **Mechanism**: The 1,400-flow dataset generator (`scale_dataset.py`) produces 4 captures with 350 ground-truth target flows each. However, generating each positive flow also emits a DNS request/response pair on port 53. Thus, each PCAP contains **600 unique flows** (250 DNS flows + 250 HTTPS flows + 100 negative HTTPS flows).
- **Impact**: Because 600 flows are pushed into a 500-element FIFO buffer, the first 100 flows (50 DNS + 50 HTTPS) are evicted. When the engine dumps `output.json`, only 500 flows remain (200 DNS + 200 HTTPS positive + 100 negative).
- **Result**: The evaluation script searched for all 250 positive flows in `output.json`. The first 50 were missing, forcing exactly 50 False Negatives and bounding maximum recall to exactly $200/250 = 80.00\%$. The reported 80.00% recall was an artifact of buffer capacity, not engine classification failure.

### B. Mathematical Inconsistency in Table II
- **Discrepancy**: The manuscript reports for `SNI + single-domain DNS`:
  $$\text{Precision} = 0.951, \quad \text{Recall} = 0.673, \quad F_1 = 0.694$$
- **Mathematical Impossibility**:
  $$F_1 = 2 \times \frac{0.951 \times 0.673}{0.951 + 0.673} = \frac{1.280046}{1.624} = 0.7882 \neq 0.694$$
- **Origin**: In `baseline_comparison.csv`, SNI-only had $\text{Precision}=1.0$, $\text{Recall}=0.532$, which yields $F_1 = \frac{2 \times 1.0 \times 0.532}{1.532} = 0.6945$. The value `0.694` was accidentally copied from SNI-only into the single-domain DNS row while arbitrarily inserting precision 0.951 and recall 0.673.

### C. Flawed Baseline Simulation in `evaluate_baselines.py`
- In `scripts/evaluate_baselines.py`, method `(c) SNI + DNS-single` was implemented by filtering engine results for `method in ["TLS SNI", "HTTP Host", "DNS Query"]`.
- Because all evaluated flows in `ground_truth.csv` are on port 443, no target flow ever has `method == "DNS Query"` (which only occurs on port 53).
- Consequently, `SNI + DNS-single` filtered out all `"DNS Correlation"` labels, making its predictions 100% identical to `SNI-only` (133 TP, recall = 0.532). The baseline script never actually executed single-domain DNS correlation on port 443 flows.

### D. Degenerate Paired Statistics & Hardcoded P-Values
- In `scale_dataset.py`, the synthetic generator used static domain-to-IP mappings and identical random seeds across all 4 capture sessions.
- As a result, the performance metrics across Captures 1, 2, 3, and 4 were mathematically identical ($\Delta = 0$, $\sigma = 0$).
- When calculating paired t-tests in `scripts/statistical_analysis.py`, the author encountered a division-by-zero error ($\sigma_{\text{diff}} = 0$) and added an `if std_diff == 0.0:` branch that hardcoded `p_val = 0.0001` and `cohens_d = 9.99`.
- Furthermore, claiming an exact two-sided Wilcoxon signed-rank test $p < 0.0001$ with $N = 4$ paired session observations is mathematically impossible, as the minimum achievable $p$-value for $N = 4$ is $2 \times (1/2)^4 = 0.125$.

### E. Fabricated Error Analysis Table (Table IV)
- In the original manuscript, Table IV reported 10 domain misclassifications (e.g. `gitlab.com -> github.com`, `x.com -> twitter.com`) and claimed that 1.7% of flows suffered from CDN collisions.
- However, audit of `ground_truth_1..4.csv` revealed that `scale_dataset.py` assigned 150 unique, non-overlapping IP addresses to the 50 domains and 100 negative controls.
- There were **zero shared IPs and zero false positives** in the actual dataset (`FP = 0`). The entire misclassification table in the original paper was fabricated/hypothetical.

### F. Fabricated TCP Reassembly Contribution Claim
- The paper claimed: *"TCP stream reassembly contributes approximately 8 percentage points of the recall gain"*.
- In `scale_dataset.py`, line 344 generates TLS Client Hellos as single contiguous TCP packets with `flags = PSH | ACK`. Not a single packet in any of the 4 PCAPs was split across TCP segments.
- `TcpReassembler` was never exercised by the dataset; the 8 percentage point gain was fabricated in prose.

---

## 6. Implementation-to-Paper Traceability Matrix

| Manuscript Claim / Topic | Paper Section | Source File(s) | Function / Class | Test / Script | Experimental Evidence | Verification Status |
|---|---|---|---|---|---|---|
| **Pipeline Architecture** | Sec. III-A | `src/main.cpp` | `main()` | `tests/offline.test.js` | `output.json` | **VERIFIED** |
| **Ethernet/IP/TCP/UDP Parsing** | Sec. III-D | `src/packet_parser.cpp` | `PacketParser::parse` | `tests/offline.test.js` | Valid 5-tuples | **VERIFIED** |
| **TLS SNI Extraction** | Sec. III-A, Alg. 2 | `src/sni_extractor.cpp` | `SNIExtractor::extract` | `tests/offline.test.js` | 133/200 SNI labels | **VERIFIED** |
| **HTTP Host Extraction** | Sec. III-A | `src/http_parser.cpp` | `HttpParser::parse` | `tests/offline.test.js` | Host matches | **VERIFIED** |
| **FastPath Gatekeeper** | Sec. III-A, RQ3 | `src/fast_path.cpp` | `FastPath::needsInspection` | `tests/offline.test.js` | Port filter (80,443,53) | **VERIFIED** |
| **Probabilistic DNS Cache** | Sec. III-F | `src/probabilistic_dns_cache.cpp` | `ProbabilisticDnsCache` | `tests/offline.test.js` | Weighted multi-domain | **VERIFIED** |
| **DNS TTL Expiration** | Sec. III-F | `src/probabilistic_dns_cache.cpp` | `cleanupExpired()` | Code inspection | Expiry timestamp check | **VERIFIED** |
| **TCP Stream Reassembly** | Sec. III-B | `src/tcp_reassembler.cpp` | `TcpReassembler::inspectSegment` | `npm test` | Capped at 2,048 B | **VERIFIED (Code only; inactive in dataset)** |
| **Bounded Telemetry Rings** | Sec. III-I | `src/stats_collector.cpp` | `StatsCollector::update` | `tests/analytics.test.js` | Ring caps (300/100/4096) | **VERIFIED** |
| **Dynamic WFP Sessions** | Sec. III-H | `src/wfp_enforcement.cpp` | `WfpEnforcement::initialize` | `tests/server.test.js` | Dynamic session flag | **VERIFIED (Windows Admin required)** |
| **1,400-Flow Dataset** | Sec. V | `dataset_capture_1..4.pcap` | N/A | `scripts/scale_dataset.py` | 4 PCAPs (90 KB each) | **VERIFIED** |
| **Baseline Metrics (Table II)** | Sec. V-C | `scripts/evaluate_baselines.py` | `compute_metrics()` | `evaluate_baselines.py` | `baseline_comparison.csv` | **AUDITED & CORRECTED (Math error in draft)** |
| **Wilcoxon p < 0.0001** | Sec. V-D | `scripts/statistical_analysis.py` | `paired_hypothesis_test()` | `statistical_analysis.py` | Script hardcoded 0.0001 | **DEBUNKED (Math invalid for N=4)** |
| **Reassembly Recall Gain (+8 pp)** | Sec. VI-A | N/A | N/A | None | PCAP has no fragmented TLS | **FABRICATED IN DRAFT** |
| **Top Misclassifications (Table IV)**| Sec. V-G | N/A | N/A | None | FP = 0 in dataset | **FABRICATED IN DRAFT** |
| **Offline Throughput (Table V)** | Sec. V-H | `scripts/benchmark-mixed.js` | N/A | `benchmark-mixed.js` | 46,510 pkts/s (100k) | **VERIFIED (Startup overhead explained)** |

---

## 7. Recommended Modifications for IEEE Submission

1. **Fix Manuscript Table II**: Recompute all metrics strictly from verifiable data. Ensure precision, recall, and F1 satisfy the exact harmonic mean formula.
2. **Correct Statistical Testing**:
   - Disclose that across the 4 synthetic runs, metrics are deterministic.
   - For statistical significance, evaluate at the **domain level ($N = 50$)** across categories using paired t-tests / Wilcoxon tests on domain-level recall, or utilize clustered bootstrap resampling ($B = 1,000$) over individual flows.
3. **Conduct a Genuine Ablation Study**:
   - Construct a genuine PCAP with segmented TLS Client Hellos to evaluate `TcpReassembler`.
   - Construct a genuine PCAP with CDN IP collisions to evaluate `ProbabilisticDnsCache` against a single-domain cache.
4. **Remove Fabricated Misclassification Narrative**:
   - Replace the fabricated Table IV with genuine error diagnostics (explaining the 50 buffer-truncated false negatives and negative noise handling).
5. **Clarify Startup Overhead in Benchmarks**:
   - Explicitly document that process initialization accounts for ~500 ms of execution time, which explains the apparent throughput scaling from 1,718 pps (1k packets) to 46,510 pps (100k packets).

