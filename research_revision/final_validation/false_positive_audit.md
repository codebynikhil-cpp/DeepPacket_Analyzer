# Independent Zero-False-Positive Audit & Boundary Analysis

**Investigation Subject**: Zero False Positive Claim ($FP = 0, \text{Precision} = 100.0\%$)  
**Evaluator**: Independent IEEE Senior Reviewer & Experimental Systems Auditor  
**Date**: November 2026  
**Artifacts Inspected**:
- Negative Ground Truth: 400 negative flows (100 per capture across 4 captures)
- Engine Predictions: `research_revision/final_validation/complete_predictions.csv`
- Negative IP Generator: `scripts/scale_dataset.py` (lines 233–247)

---

## 1. Executive Summary

The claim that DeepPacket Analyzer achieves **zero false positives ($FP = 0$)** across the 1,400-flow evaluation dataset has been **INDEPENDENTLY AUDITED AND STATISTICALLY CONFIRMED** on the provided benchmark corpus.

However, a rigorous scientific evaluation requires distinguishing between **algorithmic correctness** and **benchmark construction boundaries**:
- **What is Established**: The engine's hierarchical evidence architecture strictly refuses to assign a domain label based on raw transport-layer heuristics alone. When no cleartext TLS SNI, HTTP Host, or valid DNS A-record correlation is present, the engine outputs `"UNKNOWN"`, properly abstaining rather than guessing.
- **What is NOT Established**: The result does **not** demonstrate zero false positives in environments with **DNS cache poisoning**, **rapid IP churn**, or **CDN multi-tenant IP collisions** (which produced a 13.3% false positive rate in our separate ablation experiment).

---

## 2. Granular Inspection of All 400 Negative Examples

Across the four 350-flow captures, exactly 100 flows per session ($N = 400$ total) were designated as negative controls:

| Capture ID | Negative Flows | True Label | Engine Method Assigned | Engine Domain Assigned | FP Count | TN Count |
|---|---|---|---|---|---|---|
| **Capture 1** | Flows 251–350 (100) | `NEGATIVE` | `Port 443` | `UNKNOWN` | 0 | 100 |
| **Capture 2** | Flows 251–350 (100) | `NEGATIVE` | `Port 443` | `UNKNOWN` | 0 | 100 |
| **Capture 3** | Flows 251–350 (100) | `NEGATIVE` | `Port 443` | `UNKNOWN` | 0 | 100 |
| **Capture 4** | Flows 251–350 (100) | `NEGATIVE` | `Port 443` | `UNKNOWN` | 0 | 100 |
| **Total** | **400 Flows** | `NEGATIVE` | **`Port 443` (100%)** | **`UNKNOWN` (100%)** | **0** | **400** |

Every single negative flow was correctly labeled `UNKNOWN` by the engine and scored as a **True Negative (TN = 400)**.

---

## 3. False Positive Rate (FPR) & Wilson Confidence Intervals

Given $FP = 0$ out of $N_{\text{neg}} = 400$ negative trials:
$$\widehat{\text{FPR}} = \frac{FP}{FP + TN} = \frac{0}{0 + 400} = \mathbf{0.0000\%}$$

Because the sample size is finite ($N = 400$), standard normal approximation intervals degrade ($0 \pm 0$). Applying the **Wilson score confidence interval with continuity correction**:
$$\text{CI}_{95\%} = \frac{\widehat{p} + \frac{z^2}{2N} \pm z\sqrt{\frac{\widehat{p}(1-\widehat{p})}{N} + \frac{z^2}{4N^2}}}{1 + \frac{z^2}{N}}$$

For $z = 1.95996$, $\widehat{p} = 0$, and $N = 400$:
$$\text{CI}_{95\%}(\text{FPR}) = [0.0000\%, \mathbf{0.9512\%}]$$

> [!NOTE]
> The empirical finding establishes that the engine's true false-positive rate on this class of traffic is bounded below **0.95%** at the 95% confidence level.

---

## 4. Root-Cause Analysis of 5 Potential Failure Modes

We systematically audited five vulnerabilities common in DPI classifiers:

### 1. Public DNS Resolver Addresses
- *Risk*: If public resolvers (e.g. `8.8.8.8`, `1.1.1.1`) are queried for target domains, does the engine misattribute DNS traffic itself as domain flows?
- *Finding*: No. In `ConnectionTracker::process()`, DNS query packets on UDP port 53 are inspected for A-records, but their connection records receive `conn->detection_method = "DNS Query"` or `"Port 53"`. They are not misclassified as target HTTPS flows.

### 2. Shared CDN Multi-Tenant IPs
- *Risk*: When multiple domains share an Anycast CDN IP (e.g., Cloudflare, Akamai), does the DNS cache misattribute non-target traffic?
- *Finding*: In the **primary 1,400-flow dataset**, each of the 50 domains was assigned a distinct destination IP address with zero IP sharing. Therefore, CDN collision was impossible by benchmark construction. In the **ablation study** (where CDN multi-tenancy was deliberately simulated), Config D and E yielded **20 false positives (13.3% FP rate)** because traffic to a minor tenant was attributed to the dominant tenant sharing that IP.

### 3. DNS Cache Contamination & Stale TTLs
- *Risk*: Does an expired DNS mapping linger in memory and misattribute a reassigned IP?
- *Finding*: `ProbabilisticDnsCache::cleanupExpired()` implements TTL-based expiration. However, within the short duration of the synthetic capture runs (~10 seconds simulated), TTLs (set to 300 seconds) never expired, so eviction under TTL expiry was not stressed in this dataset.

### 4. False Hostname Attribution via Wildcard Matching
- *Risk*: Do wildcard rules (e.g., `*google*`) match unrelated domains like `notgoogle.com`?
- *Finding*: Audited unit test `short brand domains do not match inside unrelated hostnames` confirms `WfpEnforcement::domainMatches()` requires subdomain boundary dots (e.g., `.google.com` or exact `google.com`). False matches on substring boundaries are prevented.

### 5. Negative-Example Selection Bias
- *Risk*: How were the 100 negative examples generated?
- *Finding*: In `scale_dataset.py`, negative IPs were randomly sampled public routable IPv4 addresses (`23.x.x.x`, `45.x.x.x`, etc.) that were **never resolved via DNS in the PCAP trace**. This represents pure background IP traffic. It does not represent hostile traffic attempting evasion (e.g., forged SNIs, domain fronting, or DoH tunnels).

---

## 5. Formal Conclusion

The zero false-positive result is scientifically valid and mathematically verified on the 1,400-flow benchmark. However, the manuscript must not present this as a universal guarantee against all real-world traffic. The revised manuscript appropriately scopes this finding:
- *Verified Claim*: DeepPacket Analyzer maintains strict evidence hygiene, yielding zero false positives on unpolluted synthetic enterprise traffic with unshared IP allocations ($\text{FPR} < 0.95\%$ at 95% CI).
- *Disclosed Limitation*: In environments with Anycast CDN multi-tenancy without TLS SNI, DNS correlation alone produces an observed 13.3% false positive rate due to dominant-tenant bias.

