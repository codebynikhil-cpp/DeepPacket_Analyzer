# Simulated Reviewer 1 Report — Networking & Systems Expert

**Venue**: IEEE International Conference on Computer Communications (INFOCOM) or equivalent  
**Paper**: DeepPacket Analyzer: Evidence-Aware Flow Classification with Bounded Telemetry and Optional Windows Filtering Platform Enforcement  
**Reviewer Role**: Networking systems and Deep Packet Inspection specialist  
**Recommendation**: **Weak Accept** (pending response to Major Concerns)

---

## Summary

This paper presents DeepPacket Analyzer, a C++17 DPI engine that classifies network flows using a hierarchy of evidence sources: TLS SNI, HTTP Host headers, DNS query extraction, and a novel probabilistic multi-domain DNS-to-IP correlation cache. The engine is evaluated across four PCAP captures with 1,400 labeled flows. The key contribution is the combination of explicit evidence provenance, bounded telemetry structures, and a probabilistic DNS correlation mechanism that improves recall by 26.8 percentage points over SNI-only classification.

The paper is written honestly. Limitations are disclosed. The implementation is genuine and the metrics have been independently audited and corrected relative to an earlier draft.

---

## Strengths

**S1 — Evidence hierarchy is well-defined and implemented.**  
The classification evidence hierarchy (SNI > HTTP Host > DNS Query > DNS Correlation > Port Heuristic) is clearly articulated and verifiably implemented in `src/packet_inspector.cpp`. The `ClassificationEvidence` struct carries method provenance through the entire pipeline. This is a meaningful design contribution.

**S2 — Bounded telemetry is a practical systems contribution.**  
The `ConnectionTracker::recent_flows_` FIFO ring buffer, capped at 500 entries, and the `ProbabilisticDnsCache` with time-to-live expiry are correctly implemented bounds-checked data structures. For a production telemetry agent, bounded memory is not optional. This design choice is well-motivated.

**S3 — TCP stream reassembler is implemented and bounds-checked.**  
The `TcpReassembler` component handles out-of-order segments up to a configurable maximum partial stream size. The implementation is genuine, even though the primary evaluation dataset does not exercise fragmented TLS Client Hellos. The ablation study demonstrates a +34 pp recall contribution when fragmented packets are present.

**S4 — Probabilistic DNS cache is thread-safe.**  
The `ProbabilisticDnsCache` uses a `std::shared_mutex` for concurrent read/write access. Multi-domain IP sharing is handled by a weighted counter approach. This is a more robust design than a simple hash map with last-write semantics.

**S5 — Honest disclosure of limitations.**  
The authors explicitly state that WFP enforcement is unverified under the current test environment, that the dataset is synthetic, and that CDN IP sharing is not present in the evaluation corpus. This is commendable for a systems paper.

**S6 — Independent metric audit performed.**  
The revised manuscript corrects a mathematical inconsistency in F1 for the SNI+DNS-single baseline that was present in an earlier draft. The correction is traceable to an independent recomputation in `research_revision/scripts/verify_metrics.py`.

---

## Major Concerns

**M1 — WFP enforcement is documented but unverified.**  
Section IV-F describes the Windows Filtering Platform callout driver as a mechanism for enforcement. The authors correctly state it is not experimentally validated. However, an IEEE systems paper that includes a software-defined enforcement component must either (a) provide experimental evidence of its operation, or (b) explicitly move it to a "future work" section with implementation notes only. As written, WFP occupies too much space for its unverified status.

**Requested action**: Reduce WFP description to 2–3 sentences referencing implementation completeness only. Move detailed WFP discussion to a "Future Work" paragraph.

**M2 — TCP reassembly not exercised in primary evaluation.**  
All TLS Client Hello messages in the evaluation dataset (`scale_dataset.py`) are emitted as single unfragmented TCP segments (PSH|ACK flag). The `TcpReassembler` is never invoked for these flows. The ablation study demonstrates reassembler impact on a separate fragmented corpus, but this is not the same dataset as the main evaluation.

**Requested action**: The paper must clearly state in Section III (System Design) that the primary evaluation dataset does not include TCP fragmentation, and that reassembler contribution is measured separately in Section VI (Ablation). Do not imply reassembler benefit applies to the main 1,400-flow evaluation.

**M3 — SNI + DNS-single baseline is trivially equivalent to SNI-only on this dataset.**  
Because all labeled flows are HTTPS (port 443), no flow in the evaluation set has `engine_method == "DNS Query"`. Therefore, the SNI+DNS-single baseline—which includes "DNS Query" flows—produces identical results to SNI-only (TP=532, FP=0, FN=468 per the audit). The paper must explain this clearly to avoid confusing the reader. This is not an error in the method; it is a property of the dataset. The distinction between the two baselines would appear with DNS-only flows.

**Requested action**: Add a note in the evaluation section explaining why SNI-only and SNI+DNS-single yield identical metrics on this corpus, and why the DNS-probabilistic method provides lift (via retroactive DNS-to-IP correlation).

**M4 — 500-flow telemetry cap truncation artifact must be disclosed.**  
The `ConnectionTracker::recent_flows_` FIFO is capped at 500 entries. Each test PCAP generates more than 500 packets, causing the earliest flows to be evicted from telemetry before `output.json` is written. This is a telemetry artifact, not a classification failure—but it affects reported FN counts. The revised manuscript partially addresses this. Ensure the caption for Table II explicitly states that FN includes flows not captured in the telemetry window.

---

## Minor Comments

**m1**: Figure 3 (evidence_coverage.png) is well-designed. Consider adding an absolute count annotation inside each bar segment.

**m2**: The paper cites Npcap and libpcap but does not measure the overhead of packet capture vs. classification. A brief breakdown would strengthen the performance section.

**m3**: Section II (Related Work) should cite recent work on eBPF-based classifiers (e.g., Cilium, Katran) as they represent the current alternative to user-space DPI.

**m4**: Algorithm 1 (DNS correlation) uses a threshold τ. The paper sets τ = 0.6 but does not perform sensitivity analysis. A single-sentence justification or citation is sufficient.

---

## Questions for Authors

1. What is the maximum memory footprint of `ProbabilisticDnsCache` at 10,000 tracked domains?
2. Under what conditions would the FIFO ring buffer cause a false positive rather than a false negative? (i.e., if a DNS correlation is evicted before the HTTPS flow arrives)
3. Has the engine been tested on real PCAP captures from public datasets (CAIDA, PCAP-NG examples)?

---

## Decision

**Weak Accept** with minor revision. The core system contribution is genuine and useful. The metric audit and honest limitations disclosure distinguish this paper from typical DPI survey-style work. The major concerns are addressable in a camera-ready revision and do not require new experiments.

