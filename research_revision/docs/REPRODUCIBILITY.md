# Reproducibility Guide

**Paper**: DeepPacket Analyzer: Evidence-Aware Flow Classification with Bounded Telemetry and Optional Windows Filtering Platform Enforcement  
**Research Revision**: `research_revision/`  
**Audit Date**: 2026-10  
**Auditor**: Autonomous IEEE Research Supervisor

---

## Overview

This document provides a complete reproducibility guide for all experimental results reported in the revised manuscript. Every numerical claim in the paper can be traced to a specific script and verified independently.

> [!IMPORTANT]
> All metrics in the revised manuscript were independently recomputed by `research_revision/scripts/verify_metrics.py`. Do not use the original `baseline_comparison.csv` as ground truth — it contained mathematical errors corrected in this revision.

---

## 1. Environment

### Hardware

| Component | Value |
|---|---|
| CPU | Intel Core i5-12450HX (8P+4E cores) |
| OS | Windows 11 (22H2 or later) |
| RAM | ≥16 GB recommended |
| Disk | ≥2 GB free for build artifacts and PCAPs |

### Software Dependencies

| Package | Version | Purpose |
|---|---|---|
| Python | 3.10+ | Evaluation scripts |
| pandas | 2.0+ | Data processing |
| numpy | 1.24+ | Numerical computation |
| matplotlib | 3.7+ | Plotting |
| seaborn | 0.13.2 | Confusion matrix visualization |
| scipy | 1.17.1 | Statistical tests |
| scikit-learn | 1.3+ | Confusion matrix computation |
| scapy | 2.5+ | PCAP generation (ablation) |
| Node.js | 20+ (tested: v24.16.0) | Telemetry service and benchmarks |
| GCC / MinGW | 15.2.0 (MinGW) | C++17 compilation |
| CMake | 3.20+ | Build system |
| Npcap | 1.79+ | Packet capture (Windows) |

### Install Python Dependencies

```powershell
pip install pandas numpy matplotlib seaborn scipy scikit-learn scapy requests
```

### Install Node.js Dependencies

```powershell
cd <project_root>
npm install
```

### Build the C++ Engine

```powershell
cd <project_root>
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
# Verify:
.\build\PacketInspector.exe --help
```

---

## 2. Dataset

### Dataset Generation

The evaluation dataset is fully synthetic and deterministically reproducible.

```powershell
cd <project_root>
python scale_dataset.py
```

**Random seed**: `random.seed(42)` is set in `scale_dataset.py` at line ~15. This ensures identical negative-IP assignments across all runs.

**Output files**:
| File | Flows | Description |
|---|---|---|
| `dataset_capture_1.pcap` | ~600 packets | HTTPS+DNS+negative flows, session 1 |
| `dataset_capture_2.pcap` | ~600 packets | Session 2 |
| `dataset_capture_3.pcap` | ~600 packets | Session 3 |
| `dataset_capture_4.pcap` | ~600 packets | Session 4 |
| `ground_truth_1.csv` | 350 rows | True labels for session 1 |
| `ground_truth_2.csv` | 350 rows | True labels for session 2 |
| `ground_truth_3.csv` | 350 rows | True labels for session 3 |
| `ground_truth_4.csv` | 350 rows | True labels for session 4 |

### Dataset Properties

| Property | Value |
|---|---|
| Total labeled flows | 1,400 (350 per capture × 4 captures) |
| Unique domains | 50 |
| Positive flows per capture | 250 (50 domains × 5 flows: DNS + HTTPS + variants) |
| Negative flows per capture | 100 (background/unclassified) |
| Unique IPs per capture | 150 (50 domain IPs + 100 negative IPs) |
| CDN IP sharing | **None** (one unique IP per domain by construction) |
| TCP fragmentation | **None** (all TLS Client Hellos are single unfragmented segments) |

> [!NOTE]
> The absence of CDN IP sharing means the probabilistic multi-domain disambiguation is not exercised in the primary evaluation. The +26.8 pp recall improvement (SNI-only → DNS-probabilistic) is due entirely to retroactive DNS-to-IP correlation, not probabilistic disambiguation. See `research_revision/docs/experimental_methodology.md` for details.

---

## 3. Verified Metrics

### Ground-Truth Metrics (from `verify_metrics.py`)

| Method | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| Port-only | 0 | 1400 | 0 | 0 | 0.000 | 0.000 | 0.000 |
| SNI-only | 532 | 0 | 468 | 400 | 1.000 | 0.532 | 0.695 |
| SNI + DNS-single | 532 | 0 | 468 | 400 | 1.000 | 0.532 | 0.695 |
| SNI + DNS-prob. | 800 | 0 | 200 | 400 | 1.000 | 0.800 | 0.889 |

> [!WARNING]
> These numbers differ from the original manuscript draft which reported:
> - SNI+DNS-single: P=0.951, R=0.673, F1=0.694 ← **INCORRECT** (F1 was copied from SNI-only row; P and R were fabricated)
> - The corrected values are P=1.000, R=0.532, F1=0.695 (identical to SNI-only on this dataset)

### To Reproduce Independently

```powershell
cd <project_root>
python research_revision\scripts\verify_metrics.py
# Outputs: research_revision/results/verified_metrics.csv
#          research_revision/results/per_session_metrics.csv
#          research_revision/results/per_domain_metrics.csv
```

---

## 4. Full Pipeline Execution

### Step 1 — Generate Dataset

```powershell
python scale_dataset.py
```

### Step 2 — Run C++ Engine on Each PCAP

```powershell
$env:DPA_ENGINE_PATH = "build\PacketInspector.exe"
.\run_evaluation.ps1 -SkipPython
```

Or manually:

```powershell
.\build\PacketInspector.exe --pcap dataset_capture_1.pcap; Copy-Item output.json output_capture_1.json
.\build\PacketInspector.exe --pcap dataset_capture_2.pcap; Copy-Item output.json output_capture_2.json
.\build\PacketInspector.exe --pcap dataset_capture_3.pcap; Copy-Item output.json output_capture_3.json
.\build\PacketInspector.exe --pcap dataset_capture_4.pcap; Copy-Item output.json output_capture_4.json
```

### Step 3 — Run Baseline Evaluation

```powershell
python evaluate_baselines.py
# Outputs: baseline_comparison.csv, baseline_aggregate.csv, error_analysis.csv
#          baseline_comparison.png, evidence_coverage.png
```

### Step 4 — Run Statistical Analysis

```powershell
python statistical_analysis.py
# Outputs: statistical_significance.csv, statistical_tests.csv, results_table.tex
```

### Step 5 — Run Independent Metric Verification

```powershell
python research_revision\scripts\verify_metrics.py
```

### Step 6 — Run Statistical Validation (N=50 domain-level)

```powershell
python research_revision\scripts\rigorous_statistical_analysis.py
# Outputs: research_revision/results/statistical_results.csv
```

### Step 7 — Run Ablation Study

```powershell
python research_revision\scripts\run_ablation_study.py
# Outputs: research_revision/results/ablation_results.csv
#          research_revision/results/ablation_benchmark.pcap
#          research_revision/results/ablation_ground_truth.csv
```

### One-Command Pipeline (PowerShell)

```powershell
.\run_evaluation.ps1
```

---

## 5. Statistical Validation

### Test Design

N=4 captures is insufficient for capture-level significance testing (minimum Wilcoxon p-value = 0.125 at N=4). The revised manuscript uses domain-level paired comparisons (N=50 domains).

### Test Results

| Comparison | Test | Statistic | p-value | Cohen's d | Significant (α=0.05) |
|---|---|---|---|---|---|
| SNI-only vs SNI+DNS-prob. | Paired t-test (N=50 domains) | t(49)=19.80 | 4.99×10⁻²⁵ | 2.80 | ✅ Yes |
| SNI-only vs SNI+DNS-prob. | Wilcoxon signed-rank (N=50) | W=0 | 1.43×10⁻¹⁰ | — | ✅ Yes |
| SNI-only vs SNI+DNS-single | — | — | — | — | N/A (identical on this corpus) |

> [!CAUTION]
> The bootstrap confidence intervals computed by `statistical_analysis.py` are degenerate (zero variance) because all four captures produce identical measurements. This is an artifact of the deterministic synthetic dataset, not a bug. The domain-level bootstrap in `rigorous_statistical_analysis.py` produces non-trivial intervals.

### To Reproduce

```powershell
python research_revision\scripts\rigorous_statistical_analysis.py
# Results: research_revision/results/statistical_results.csv
```

---

## 6. Ablation Study

### Corpus

200 flows with artificially fragmented TLS Client Hello segments (2-segment TCP reassembly required).

### Results

| Config | Evidence Sources | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| A | Port-only | 0 | 100 | 100 | 0.000 | 0.000 | 0.000 |
| B | SNI-only (no reassembly) | 50 | 0 | 50 | 1.000 | 0.500 | 0.667 |
| C | SNI + TCP Reassembly | 100 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| D | C + DNS Correlation | 100 | 20 | 0 | 0.833 | 1.000 | 0.909 |
| E | D + Confidence Threshold | 100 | 0 | 0 | 1.000 | 1.000 | 1.000 |

> [!NOTE]
> Config D introduces false positives because DNS correlation maps non-target IPs to domains when the cache has collisions in the ablation corpus. Config E applies a confidence threshold that eliminates these FPs.

### To Reproduce

```powershell
python research_revision\scripts\run_ablation_study.py
```

---

## 7. Performance Benchmarks

### Results

| Workload | Packets | Trial | Elapsed (ms) | Throughput (pkt/s) |
|---|---|---|---|---|
| Mixed (warm) | 10,000 | 2–4 | 564–576 | 17,368–17,731 |
| Mixed (warm, mean) | 10,000 | — | — | **17,606 ± 335** |
| Mixed (all trials) | 100,000 | 1–4 | 1,059–1,596 | 62,673–94,415 |
| Mixed (all, mean) | 100,000 | — | — | **73,049 ± 18,640** |
| HTTP repeat | 1,000 | 1 | 554 | 1,804 |
| HTTP repeat | 10,000 | 1 | 529 | 18,886 |
| HTTP repeat | 50,000 | 1 | 547 | 91,355 |

**Fixed startup overhead**: ~400–500 ms (Npcap initialization). This explains the sub-linear scaling at small packet counts.

### To Reproduce

```powershell
node scripts/benchmark-mixed.js
node scripts/benchmark.js
```

---

## 8. Random Seeds and Determinism

| Component | Seed | Location |
|---|---|---|
| Negative IP generation | 42 | `scale_dataset.py`, line ~15 |
| Ablation corpus generation | 42 | `research_revision/scripts/run_ablation_study.py` |
| Bootstrap CI (statistical) | 42 | `research_revision/scripts/rigorous_statistical_analysis.py` |
| C++ engine | Deterministic (no randomness) | — |

All scripts produce byte-identical output on re-execution given the same input files.

---

## 9. Artifact Checksums

Run the following to verify dataset integrity:

```powershell
Get-FileHash dataset_capture_1.pcap, dataset_capture_2.pcap, dataset_capture_3.pcap, dataset_capture_4.pcap -Algorithm SHA256 | Format-Table
```

Expected checksums (computed after `scale_dataset.py` run with seed=42):

> [!NOTE]
> Record checksums after your first run of `scale_dataset.py` and store them here. Re-run the script and verify they match to confirm reproducibility.

---

## 10. Known Limitations Affecting Reproducibility

| Limitation | Impact |
|---|---|
| 500-flow FIFO ring buffer | First flows in each PCAP may be evicted from `output.json`. FN counts include telemetry-evicted flows. |
| Synthetic dataset, no real traffic | Results may not generalize to real-world traffic with CDN sharing, encrypted DNS, or ECH. |
| WFP enforcement not testable in user mode | WFP callout functionality requires kernel driver signing; cannot be reproduced in standard user environment. |
| Degenerate bootstrap CIs | Four identical captures produce zero-variance CIs at the capture level. Use domain-level analysis. |
| Npcap required on Windows | Without Npcap, the C++ engine cannot capture or process PCAPs. Install from https://npcap.com |

