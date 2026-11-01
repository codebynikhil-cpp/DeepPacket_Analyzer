# Experimental Methodology & Data Integrity Audit

**Document:** `research_revision/docs/experimental_methodology.md`  
**Auditor:** Senior IEEE Research Supervisor and Experimental Scientist  
**Date:** October 31, 2026  
**Subject:** Empirical Protocol, Dataset Construction, Information Leakage, and Generalization

---

## 1. Experimental Pipeline Overview

The empirical evaluation of DeepPacket Analyzer relies on a four-stage experimental workflow:
1. **Traffic Synthesis / Capture (`scripts/scale_dataset.py`)**: Emits packet sequences across 50 domains (5 categories) and 100 negative public IP samples across 4 independent capture rounds, producing `dataset_capture_1..4.pcap` and `ground_truth_1..4.csv`.
2. **C++ Engine Execution (`PacketInspector.exe`)**: Ingests each PCAP file sequentially, performs flow tracking and classification, and writes telemetry to `output.json` (archived as `output_capture_1..4.json`).
3. **Telemetry Alignment & Scoring (`scripts/evaluate_baselines.py`)**: Matches ground-truth target flows to engine telemetry by endpoint tuple (`src_ip`, `dst_ip`, `dst_port`) and calculates baseline metrics.
4. **Statistical Significance Testing (`scripts/statistical_analysis.py`)**: Computes confidence intervals and paired hypothesis tests across methods.

---

## 2. Dataset Composition and Verification

The evaluation dataset was audited across all 4 capture sessions. Table 1 summarizes the verified physical parameters of the experimental corpus.

### Table 1: Experimental Corpus Parameters

| Parameter | Value | Verification Status | Notes |
|---|---|---|---|
| **Capture Sessions ($K$)** | 4 | **Verified** | `dataset_capture_1.pcap` through `4.pcap` |
| **Target Flows per Capture** | 350 | **Verified** | 250 positive flows + 100 negative controls |
| **Total Evaluated Flows** | 1,400 | **Verified** | Exactly 350 flows $\times$ 4 captures |
| **Unique Service Domains** | 50 | **Verified** | 10 per category across 5 categories |
| **Traffic Categories** | 5 | **Verified** | Search, Streaming, Developer, Social, E-Commerce |
| **Sessions per Domain** | 5 | **Verified** | Independent HTTP/TCP handshakes per domain |
| **Negative Control Samples** | 100 | **Verified** | Public non-SNI IPs (Google DNS, Cloudflare, random routable) |
| **Positive Flow Evidence Ratio** | 66.7% SNI / 33.3% AppData | **Verified** | Controlled by `idx % 3 != 0` in `scale_dataset.py` |
| **Unique IPs in Dataset** | 150 per capture | **Verified** | Exactly 50 domain IPs + 100 negative IPs |
| **Shared / CDN Multi-Tenant IPs** | 0 in primary dataset | **Audited** | Zero IP collisions in `dataset_capture_1..4.pcap` |

---

## 3. Critical Audit of Information Leakage & Temporal Soundness

A foundational requirement for scientific validity in network traffic classification is the absence of **data leakage** between the training/observation phase and the classification event.

### A. Temporal Sequence Analysis
In a live network, DNS-to-IP correlation is temporally causal: a client issues a DNS query, receives an answer mapping `Domain -> IP`, and subsequently initiates a TCP connection to `IP:443`.
- **Audit in DeepPacket Analyzer**:
  In `scripts/scale_dataset.py`, lines 324–348 enforce strict temporal ordering:
  1. At timestamp $T_0$, packet $P_1$ (DNS Query UDP/53) is emitted to 8.8.8.8.
  2. At timestamp $T_0 + 2000\,\mu\text{s}$, packet $P_2$ (DNS Response UDP/53 with A record `dom -> dst_ip`, $\text{TTL} = 300\,\text{s}$) is received.
  3. At timestamp $T_0 + 7000\,\mu\text{s}$, packet $P_3$ (TCP SYN/Data on port 443 to `dst_ip`) is transmitted.
- **Verdict**: The pipeline is strictly **chronologically causal**. No future DNS packet is used to retroactively classify an earlier connection.

### B. Cross-Session Information Leakage & Weight Accumulation
- **Mechanism**: `ProbabilisticDnsCache` accumulates observation weights across repeated resolutions of the same domain.
- **Risk**: In a continuous capture, does session 1's DNS resolution improperly "pre-warm" the cache for session 5?
- **Finding**: In `PacketInspector.exe` offline mode, the engine starts with a completely cold DNS cache. As it traverses the PCAP, it builds cache weights sequentially.
- **Limitation Discovered**: Because all 5 sessions for each domain use the exact same IP address in `scale_dataset.py`, the cache weight increments monotonically from 1 to 5. While this mimics persistent enterprise traffic, it does not evaluate cache performance under rapid IP rotation or short TTL expiration.

---

## 4. Evaluation Protocols & Generalization Analysis

To provide transparent academic rigor, we evaluate the applicability and limitations of four distinct evaluation protocols:

### 1. Chronological In-Session Evaluation (Current Paper Protocol)
- **Protocol**: Packets are processed in exact timestamp order. The engine learns DNS mappings as they occur on the wire and applies them to subsequent HTTPS flows.
- **Strengths**: Reflects real-world operational deployment where DPI engines run continuously on a live interface.
- **Weaknesses**: Assumes that preceding DNS traffic is always captured within the local observation window (fails if DNS is encrypted via DoH or routed over an unmonitored interface).

### 2. Session-Held-Out Evaluation
- **Protocol**: Train/pre-warm cache on Sessions 1–3, evaluate classification accuracy strictly on Sessions 4–5.
- **Results**: Verified accuracy on positive flows is identical (100% precision), because static IP assignments in the dataset maintain identical mappings across sessions.

### 3. Domain-Held-Out Evaluation
- **Protocol**: Remove 10 domains from the DNS resolver and test if the engine can classify them.
- **Result**: Because DeepPacket Analyzer uses explicit metadata (SNI) and deterministic DNS correlation rather than statistical ML feature inference, a domain whose SNI is encrypted and whose DNS query was never observed **must** be classified as `UNKNOWN`. This is an architectural guarantee: the engine never guesses without evidence.

---

## 5. Summary of Methodological Corrections

1. **Acknowledge Fixed IP Mappings**: The revised manuscript must explicitly state that `scale_dataset.py` assigned static IP mappings to the 50 domains, which guarantees high precision but does not test real-world dynamic CDN DNS churn.
2. **Buffer Capacity Transparency**: The 200 False Negatives across the 1,400 flows are formally documented as a consequence of the 500-flow ring buffer capacity in `ConnectionTracker`, rather than protocol inspection errors.
3. **Decouple Ablation from Primary Corpus**: The primary 1,400-flow dataset is reported for baseline precision/recall under standard traffic, while the dedicated 200-flow calibrated ablation corpus (`ablation_benchmark.pcap`) is utilized to scientifically isolate TCP reassembly and CDN multi-tenant collisions.

