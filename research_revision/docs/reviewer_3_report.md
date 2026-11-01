# Simulated Reviewer 3 Report — IEEE Publication Standards & Novelty

**Venue**: IEEE International Conference on Computer Communications (INFOCOM) or equivalent  
**Paper**: DeepPacket Analyzer: Evidence-Aware Flow Classification with Bounded Telemetry and Optional Windows Filtering Platform Enforcement  
**Reviewer Role**: IEEE publication standards, novelty assessment, and related-work coverage  
**Recommendation**: **Weak Reject → Borderline** (conditional on novelty reframing)

---

## Summary

DeepPacket Analyzer describes a practical DPI system with a carefully implemented evidence hierarchy and a probabilistic DNS-to-IP correlation mechanism. The implementation is genuine and the evaluation is honest. However, from an IEEE publication novelty standpoint, the individual components (TLS SNI extraction, DNS correlation, flow tracking, TCP reassembly) are well-established. The paper's contribution depends on the combination and the probabilistic cache design, but the current manuscript does not clearly differentiate the probabilistic cache from existing solutions in a technically rigorous way.

---

## Strengths

**S1 — Honest limitation disclosure is above average for systems papers.**  
The paper explicitly states that WFP enforcement is unverified, the dataset is synthetic, and CDN IP sharing is not modeled. Many systems papers overstate their contributions. This paper understates them, which is more acceptable but requires stronger novelty justification.

**S2 — Evidence provenance is a practical contribution.**  
Carrying classification evidence through the entire pipeline (from packet parsing to telemetry export) is not universally implemented in open-source DPI engines. The `ClassificationEvidence` struct in `packet_inspector.h` is a concrete design artifact that enables auditability.

**S3 — The metric audit and manuscript self-correction.**  
The revised manuscript corrects an F1 mathematical inconsistency (SNI+DNS-single F1 was copied from the SNI-only row) and removes a fabricated error analysis table. This level of self-auditing is unusual and commendable.

**S4 — Complete software artifact.**  
The authors provide a complete, compilable C++17 codebase with CMake build, Node.js telemetry service, browser dashboard, and a full evaluation pipeline. The artifact quality is high.

---

## Major Concerns

**M1 — Novelty of the probabilistic DNS cache is not clearly established.**  
The probabilistic multi-domain DNS cache assigns confidence weights to IP-domain associations based on co-occurrence counts. This mechanism is described informally but is not compared to existing approaches:

- Zeek's `dns.log` correlates DNS A-records to connection logs by timestamp and IP. This is functionally equivalent to DNS-single correlation.
- ntopng uses DNS-to-flow correlation with TTL-aware expiry, which overlaps with the proposed cache.
- The paper does not cite or compare against either system.

**The critical question**: What does the *probabilistic* aspect add that a deterministic TTL-aware DNS cache does not provide? The answer (CDN disambiguation) is never empirically demonstrated on this dataset.

**Requested action**: Add a comparison table (Table I or a new table) listing DeepPacket Analyzer, Zeek, and ntopng across: DNS correlation (yes/no), TTL-aware expiry (yes/no), multi-domain disambiguation (yes/no), evidence provenance export (yes/no), bounded memory (yes/no). This would directly establish the novelty.

**M2 — No comparison with nDPI on the same PCAP captures.**  
nDPI is the most widely used open-source DPI library and represents the state of the art for PCAP-based classification. The paper makes no comparison against it. Without this comparison, it is impossible to assess whether DeepPacket Analyzer provides any improvement over the baseline state of the art.

**Requested action**: Run nDPI (or ndpiReader) on the four evaluation PCAPs and report its precision, recall, and F1 alongside the DeepPacket Analyzer results. If the evaluation PCAPs are synthetic, nDPI may perform differently (it does not rely on statistical learning but on protocol dissection), making the comparison informative rather than damning.

**Note from audit**: The previous supervisor report correctly flags that nDPI comparison was requested but not performed. The authors must either (a) include nDPI results, or (b) provide a documented technical reason why comparison is inappropriate (e.g., nDPI requires different input format or processes packets differently).

**M3 — Encrypted Client Hello (ECH) impact is not discussed.**  
TLS 1.3 with ECH encrypts the SNI field. If ECH is deployed, the SNI-only and DNS-correlation baselines become the primary classification paths, not fallbacks. The paper does not mention ECH, despite this being an active IETF deployment (RFC 8744, draft-ietf-tls-esni). For an IEEE 2024+ networking paper, omission of ECH is a significant gap.

**Requested action**: Add a 2–3 sentence discussion of ECH impact in Section II (Background) or Section VII (Conclusion/Future Work). State explicitly that as ECH adoption increases, DNS-based correlation becomes the primary classification mechanism, which strengthens the paper's long-term motivation.

**M4 — The paper title references "Bounded Telemetry" as a key contribution but this is underexplored.**  
The 500-flow FIFO ring buffer and bounded DNS cache are described but not benchmarked as a design contribution. How does bounded telemetry compare to unbounded alternatives? What is the memory footprint? Does the bound cause meaningful information loss in real traffic? The title implies this is a major contribution, but it receives less analysis than the DNS correlation mechanism.

**Requested action**: Either add a brief bounded-telemetry evaluation (memory usage vs. flow rate, information loss rate at different buffer sizes), or remove "Bounded Telemetry" from the title and relegate it to an implementation detail.

---

## Minor Comments

**m1**: The paper uses the term "evidence-aware" in the title and abstract but does not define it formally. A one-sentence definition in Section I (Introduction) would help.

**m2**: References [1]–[5] in the related work section need DOIs or full bibliographic details. IEEE submissions require complete citations.

**m3**: The paper is 8 pages (IEEE double-column). If targeting INFOCOM, the page limit is strictly enforced. Check that the WFP section reduction (per Reviewer 1's request) does not create awkward whitespace in the layout.

**m4**: Figure 2 (evidence_coverage.png) shows "Port Heuristic" as a detection method. The evaluation correctly shows that port-only classification achieves 0% precision in this dataset because all port-443 flows are labeled by domain, not by port. The figure caption should clarify that "Port Heuristic" is included as a coverage metric for the engine method distribution, not as a classification baseline that achieves precision.

**m5**: The ablation study (Section VI) references "Appendix A" for fragmented TLS details. No appendix is present in the manuscript. Change to a self-contained description or an inline note.

---

## Questions for Authors

1. How does DeepPacket Analyzer handle TLS 1.3 session resumption tickets? Does the engine re-classify resumed sessions?
2. What is the false positive rate when the DNS cache TTL expires and a new domain maps to a previously-classified IP?
3. Can the evidence hierarchy be configured at runtime, or is it compile-time only?

---

## Decision

**Weak Reject → Borderline.** The paper describes a genuine and well-implemented system. The primary weaknesses are novelty differentiation (no nDPI comparison, no CDN disambiguation experiment) and missing ECH discussion. These are not insurmountable. A revised submission with a comparison table against Zeek/ntopng/nDPI and an ECH discussion paragraph would be borderline acceptable. The honest evaluation methodology and complete software artifact are significant strengths.

