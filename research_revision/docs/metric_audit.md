# Mathematical and Metric Audit

**Document:** `research_revision/docs/metric_audit.md`  
**Auditor:** Senior IEEE Research Supervisor and Statistical Analyst  
**Date:** October 31, 2026  
**Subject:** Audit of Mathematical Integrity, Metric Definitions, and Experimental Tables

---

## 1. Executive Summary

This audit rigorously evaluates every mathematical statement, formula, reported metric, and experimental conclusion presented in the DeepPacket Analyzer research manuscript. Every reported number was independently verified against the raw ground-truth CSV records (`ground_truth_1..4.csv`) and the raw C++ DPI engine telemetry output files (`output_capture_1..4.json`).

The audit confirms a major **mathematical violation in Table II** of the original manuscript where the reported Precision, Recall, and F1-score fail to satisfy the harmonic mean formula. Furthermore, discrepancies were uncovered where original empirical outputs were artificially perturbed in the draft manuscript (e.g. reporting 0.951/0.973/0.996 precision instead of the true empirical values of 1.000, and reporting fabricated 0.673 recall for single-domain DNS). All metrics have been recomputed from first principles and are presented below with complete mathematical proofs and corrected values.

---

## 2. Mathematical Definition of Metrics

To avoid ambiguity, all evaluation metrics are strictly defined below. A total of $N = 1{,}400$ flows ($1{,}000$ positive flows across 50 domains, and $400$ negative public IP controls) are evaluated across 4 independent capture sessions.

### A. Classification Event Definitions
Let $\mathcal{Y}$ be the true domain label and $\hat{\mathcal{Y}}$ be the engine-predicted domain label.
- **True Positive (TP)**: The flow is a positive ground-truth domain ($y \in \text{Domains}$) and the engine correctly predicts $\hat{y} = y$.
- **False Positive (FP)**: The engine predicts $\hat{y} \in \text{Domains} \cup \{\text{Protocol}\}$ such that $\hat{y} \neq y$. This includes misattributing negative traffic or predicting domain $A$ when the true domain is $B$.
- **False Negative (FN)**: The flow is a positive ground-truth domain ($y \in \text{Domains}$), but the engine abstains or outputs `UNKNOWN` ($\hat{y} \in \{\emptyset, \text{UNKNOWN}\}$).
- **True Negative (TN)**: The flow is a negative control ($y = \text{NEGATIVE}$), and the engine correctly abstains ($\hat{y} \in \{\emptyset, \text{UNKNOWN}\}$).

### B. Core Metric Formulas
1. **Precision (Positive Predictive Value)**:
   $$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}$$
2. **Recall (True Positive Rate / Sensitivity)**:
   $$\text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}}$$
3. **F$_1$-Score (Harmonic Mean of Precision and Recall)**:
   $$F_1 = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}} = \frac{2\text{TP}}{2\text{TP} + \text{FP} + \text{FN}}$$
4. **Specificity (True Negative Rate)**:
   $$\text{Specificity} = \frac{\text{TN}}{\text{TN} + \text{FP}}$$
5. **Accuracy (Overall Correctness)**:
   $$\text{Accuracy} = \frac{\text{TP} + \text{TN}}{\text{TP} + \text{FP} + \text{FN} + \text{TN}} = \frac{\text{TP} + \text{TN}}{N_{\text{total}}}$$
6. **Classification Coverage (Labelled Fraction)**:
   $$\text{Coverage} = \frac{\text{TP} + \text{FP}}{N_{\text{total}}}$$
   *(Note: Coverage measures the fraction of flows for which the engine assigned a non-abstaining domain label).*

---

## 3. Discrepancy Analysis: The Table II F1 Contradiction

### The Manuscript's Claim:
In Section V-C, Table II, the draft manuscript reports:
- **SNI + single-domain DNS**:
  $$\text{Precision} = 0.951, \quad \text{Recall} = 0.673, \quad F_1 = 0.694$$

### The Mathematical Proof of Inconsistency:
By definition, the $F_1$-score is the harmonic mean of precision and recall. Substituting the manuscript's reported values into the definition:
$$F_1 = 2 \times \frac{0.951 \times 0.673}{0.951 + 0.673} = \frac{2 \times 0.640023}{1.624} = \frac{1.280046}{1.624} = \mathbf{0.788206} \approx \mathbf{0.788}$$

The reported $F_1 = 0.694$ represents an absolute error of $-0.094$ ($-9.4$ percentage points) relative to the mathematical definition!

### Root Cause Audit:
Where did $0.694$ come from?
In the empirical benchmark output (`baseline_comparison.csv`), the SNI-only baseline achieved:
$$\text{Precision} = 1.000, \quad \text{Recall} = 0.5320, \quad F_1 = 2 \times \frac{1.0 \times 0.532}{1.532} = \mathbf{0.6945}$$
The author copied the $F_1$ value from the SNI-only baseline ($0.694$) into the single-domain DNS row, while manually writing perturbed Precision ($0.951$) and Recall ($0.673$) values without verifying that they satisfy the harmonic mean formula.

---

## 4. Side-by-Side Audit: Original Manuscript vs. Verified Data

Table 1 presents the full side-by-side audit comparing the numbers printed in the draft manuscript against the independently verified values computed directly from the raw telemetry and ground-truth files.

### Table 1: Comprehensive Baseline Audit (1,400 Flows across 4 Captures)

| Baseline Method | Metric | Manuscript Draft | Verified Ground Truth | Discrepancy ($\Delta$) | Audit Conclusion / Cause |
|---|---|---|---|---|---|
| **Port-only** | Precision | 0.000 | **0.000** | 0.000 | Verified (Ports do not identify domains) |
| | Recall | 0.000 | **0.000** | 0.000 | Verified |
| | F1-Score | 0.000 | **0.000** | 0.000 | Verified |
| | Coverage | 1.000 | **1.000** | 0.000 | Verified (All 1,400 flows assigned port label) |
| **SNI-only** | Precision | 0.973 | **1.000** | $+0.027$ | Draft artificially deflated empirical 100% precision |
| | Recall | 0.532 | **0.532** | 0.000 | Verified (532/1,000 positive flows resolved) |
| | F1-Score | 0.688 | **0.695** | $+0.007$ | Draft altered F1 ($2 \times 1.0 \times 0.532 / 1.532 = 0.6945$) |
| | Coverage | 0.532 | **0.380** | $-0.152$ | Draft conflated recall with total coverage ($532/1400 = 0.380$) |
| **SNI + DNS-single** | Precision | 0.951 | **1.000** | $+0.049$ | Draft invented 0.951 precision |
| | Recall | 0.673 | **0.532** | $-0.141$ | Draft invented 0.673 recall; script did not correlate DNS |
| | F1-Score | 0.694 | **0.695** | $+0.001$ | Draft F1 was mathematically invalid for reported P & R |
| | Coverage | 0.673 | **0.380** | $-0.293$ | Draft invented coverage value |
| **SNI + DNS-prob.** | Precision | 0.996 | **1.000** | $+0.004$ | Draft artificially deflated empirical 100% precision |
| | Recall | 0.800 | **0.800** | 0.000 | Verified (800/1,000 positive flows resolved) |
| | F1-Score | 0.889 | **0.889** | 0.000 | Verified ($2 \times 1.0 \times 0.8 / 1.8 = 0.8889$) |
| | Coverage | 0.804 | **0.571** | $-0.233$ | Draft conflated recall with total coverage ($800/1400 = 0.5714$) |

---

## 5. Verified Raw Confusion Matrix (1,400 Evaluated Flows)

The exact flow confusion counts across all 4 capture sessions (350 flows each $\times 4 = 1{,}400$ total flows) are presented in Table 2.

### Table 2: Verified Flow Classification Breakdown

| Metric / Category | Port-only | SNI-only | SNI + DNS-single (Legacy Script) | SNI + DNS-probabilistic (Ours) |
|---|---|---|---|---|
| **True Positives (TP)** | 0 | 532 | 532 | **800** |
| **False Positives (FP)** | 1,400 | 0 | 0 | **0** |
| **False Negatives (FN)** | 0 | 468 | 468 | **200** |
| **True Negatives (TN)** | 0 | 400 | 400 | **400** |
| **Total Flows** | 1,400 | 1,400 | 1,400 | **1,400** |
| **Precision** | 0.00% | 100.00% | 100.00% | **100.00%** |
| **Recall** | 0.00% | 53.20% | 53.20% | **80.00%** |
| **F$_1$-Score** | 0.00% | 69.45% | 69.45% | **88.89%** |
| **Specificity** | 0.00% | 100.00% | 100.00% | **100.00%** |
| **Overall Accuracy** | 0.00% | 66.57% | 66.57% | **85.71%** |
| **Coverage** | 100.00% | 38.00% | 38.00% | **57.14%** |
| **False Positive Rate** | 100.00% | 0.00% | 0.00% | **0.00%** |
| **False Negative Rate** | 0.00% | 46.80% | 46.80% | **20.00%** |

### Key Observations:
1. **Zero False Positives Across All DNS Methods**:
   In the synthetic dataset, negative samples are directed to raw public IPs without SNI or preceding DNS queries. The engine correctly abstains on all 400 negative flows ($\text{TN} = 400, \text{FP} = 0$). Specificity is strictly $100.0\%$.
2. **Recall Gain**:
   Adding probabilistic DNS correlation increases the true positive count from 532 to 800 (+268 flows), boosting recall from $53.20\%$ to $80.00\%$ (+26.80 percentage points).
3. **The 200 False Negatives**:
   The 200 false negatives across 4 captures (50 per capture) occur exclusively because `ConnectionTracker`'s ring buffer was capped at 500 entries, evicting the first 50 positive flows before telemetry export.

---

## 6. Textual Corrections Required in Manuscript

The following numerical claims in the manuscript draft must be updated to align with the audited, verified results:

1. **Abstract**:
   - *Original*: *"improves recall from 0.532 to 0.800 (+26.8 pp) and F1-score from 0.694 (single-domain DNS) to 0.889 (probabilistic DNS)..."*
   - *Correction*: Clarify that the baseline comparison is against direct SNI-only extraction (F1 = 0.695) and single-domain DNS cache under CDN collisions, where recall improves by +26.8 pp and F1 improves from 0.695 to 0.889 (+19.4 pp).
2. **Table II (Baseline Comparison)**:
   - Replace Table II with the mathematically consistent Verified Metrics from Table 1.
   - Fix Precision (1.000 instead of 0.973 / 0.951 / 0.996).
   - Fix Coverage (0.380 for SNI-only, 0.571 for Probabilistic, instead of 0.532 and 0.804).
3. **Table IV (Error Analysis)**:
   - Remove the fabricated 10-row misclassification table.
   - Replace with an authentic breakdown explaining that in the controlled evaluation dataset, FP = 0 and FN = 200 (50 per capture), attributing the false negatives to the 500-flow telemetry buffer window.

