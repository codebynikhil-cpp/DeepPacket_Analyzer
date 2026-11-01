# Simulated Reviewer 2 Report — Experimental Research & Evaluation

**Venue**: IEEE International Conference on Computer Communications (INFOCOM) or equivalent  
**Paper**: DeepPacket Analyzer: Evidence-Aware Flow Classification with Bounded Telemetry and Optional Windows Filtering Platform Enforcement  
**Reviewer Role**: Experimental methodology and evaluation specialist  
**Recommendation**: **Borderline** — Major Revision Required

---

## Summary

The paper presents a DPI classification engine and evaluates four classification baselines across 1,400 labeled flows. The evaluation methodology is honest, well-described, and reproducible. However, from an experimental research standpoint, the dataset has fundamental constraints that limit the generalizability of the results: it is fully synthetic, contains no CDN IP sharing, and produces degenerate statistical properties (identical measurements across all four captures). These constraints are partially disclosed but not sufficiently addressed.

---

## Strengths

**S1 — Reproducible evaluation pipeline.**  
The authors provide `evaluate_baselines.py`, `statistical_analysis.py`, `run_evaluation.ps1`, and `run_evaluation.sh` as a complete reproducible pipeline. Random seeds are documented (`seed=42` in `scale_dataset.py`). This is significantly above the reproducibility standard for most DPI papers.

**S2 — No data leakage.**  
Strict temporal causality is maintained: DNS records are processed before flow classification in each session. Ground truth is derived from `scale_dataset.py` labels, not from `output.json`. This is methodologically sound.

**S3 — Honest limitations statement.**  
The authors state that the dataset is synthetic and that CDN IP sharing is not modeled. They do not claim the results generalize to arbitrary real-world traffic. This intellectual honesty is appreciated.

**S4 — Ablation study is well-structured.**  
The five-configuration ablation study (A through E) systematically isolates the contribution of each pipeline component. The ablation corpus is distinct from the primary evaluation dataset.

---

## Major Concerns

**M1 — The dataset does not stress the probabilistic DNS cache's primary use case.**  
The probabilistic multi-domain DNS cache is explicitly designed to handle the case where a single IP address is shared by multiple CDN-hosted domains (e.g., Akamai, Fastly, Cloudflare). This is the scenario where probabilistic weighting provides value over last-write semantics. However, the evaluation dataset (`scale_dataset.py`) assigns one unique IP per domain, guaranteeing zero CDN collision. The probabilistic cache therefore behaves identically to a simple last-write hash map in this evaluation.

**Consequence**: The reported +26.8 pp recall improvement (SNI-only → probabilistic DNS) is due entirely to retroactive DNS-to-IP lookup for flows that missed TLS SNI, not from the probabilistic disambiguation. The probabilistic component is never tested under its motivating conditions.

**Requested action**: The authors must either (a) add a CDN-collision sub-experiment using artificially shared IPs, or (b) clearly state in the abstract and conclusions that the probabilistic improvement is measured under non-colliding conditions and that CDN disambiguation is a design property not yet empirically validated.

**M2 — Statistical analysis is limited by N=4 independent captures.**  
With N=4 paired observations (one per capture), the minimum achievable Wilcoxon signed-rank p-value is 0.125. This means no capture-level statistical test can achieve conventional significance (α=0.05). The authors redesigned their statistical test to use N=50 domain-level paired comparisons, which achieves p<10⁻²⁴. While this is statistically valid, the reviewer notes that domain-level comparisons within a single corpus are not truly independent — the same IP allocation scheme applies across all domains.

**Requested action**: Report the domain-level test results with an explicit caveat: "Domain-level comparisons assume independence of domains within the synthetic corpus. Real-world validation with independent traffic captures is required for population-level inference."

**M3 — Bootstrap confidence intervals are degenerate.**  
Because the dataset is fully deterministic (synthetic, seeded), bootstrap resampling of flow-level results across four captures produces zero variance CIs. The paper must either (a) acknowledge this explicitly and use normal-approximation CIs instead, or (b) use domain-level bootstrap which has non-trivial variance. The current `statistical_analysis.py` produces CIs that will be questioned by any statistics-aware reviewer.

**Requested action**: Replace capture-level bootstrap CIs with domain-level bootstrap CIs (resample domains with replacement, N=50, B=1,000). Report the resulting intervals. For the flow-level Wilson CIs, state clearly that variance reflects dataset composition, not measurement uncertainty.

**M4 — Per-session metrics are identical across all four captures.**  
The audit reveals that per-session metrics are constant: each capture produces TP=133, FP=0, FN=117, TN=100. This is an artifact of the deterministic dataset construction. A reader of the paper may interpret "four independent captures" as implying natural variability in traffic, which this dataset does not provide.

**Requested action**: Add a footnote or note in the experimental setup stating: "The four capture sessions are independent by construction but share identical statistical properties due to the deterministic dataset generation with a fixed random seed. This confirms implementation determinism; real-world variability would require live traffic captures."

---

## Minor Comments

**m1**: Table III (per-domain breakdown) shows all domains achieving identical metrics (100% precision and either 100% or 0% recall based on whether DNS correlation resolved them). Consider grouping domains into "resolved by SNI," "resolved by DNS correlation only," and "unresolved" for clarity.

**m2**: The paper does not report inference latency per flow. Even a rough estimate (microseconds per classification decision) would strengthen the systems contribution.

**m3**: "NEGATIVE" in the ground truth represents flows to unclassified IPs. This terminology may confuse readers expecting binary positive/negative labels. Consider renaming to "background" or "unclassified" for clarity.

**m4**: The coverage metric `(TP + FP) / Total` is non-standard. Most DPI papers report recall as the coverage analog. If both TP and FP contribute to coverage, the metric mixes precision-recall space. Consider reporting labeling rate as a separate metric.

---

## Questions for Authors

1. What happens to the probabilistic DNS cache when two domains share an IP (CDN scenario)? Does it correctly abstain from labeling, or does it pick the plurality domain? Please provide a brief example or unit test result.
2. Have the authors tested on any real PCAP captures, even a single 5-minute trace from a home or office network?
3. What is the effect of the TTL threshold on probabilistic cache accuracy? Is there a τ sensitivity analysis?

---

## Decision

**Borderline — Major Revision Required.** The implementation is solid and the evaluation methodology is honest. However, the central claim—that probabilistic DNS correlation provides meaningful improvement—is not validated under the conditions that motivate the probabilistic design (CDN IP sharing). A targeted CDN-collision experiment, or an explicit scope limitation in the abstract, is required for acceptance.

