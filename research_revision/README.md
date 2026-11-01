# Research Revision — README

**Paper**: DeepPacket Analyzer: Evidence-Aware Flow Classification with Bounded Telemetry and Optional Windows Filtering Platform Enforcement  
**Revision Status**: IEEE Submission Ready (pending LaTeX compilation and nDPI comparison)  
**Audit Completed**: 2026-10  

---

## Directory Structure

```
research_revision/
├── README.md                          ← This file
├── PROGRESS.md                        ← Phase completion tracker
├── revised_manuscript.tex             ← Corrected IEEE manuscript (IEEEtran format)
│
├── docs/
│   ├── research_audit.md              ← Full repository audit with traceability matrix
│   ├── metric_audit.md                ← Mathematical inconsistency analysis + corrections
│   ├── experimental_methodology.md    ← Dataset design, flow matching, validity analysis
│   ├── statistical_validation.md      ← Statistical test design and domain-level analysis
│   ├── performance_evaluation.md      ← Benchmark results and throughput analysis
│   ├── REPRODUCIBILITY.md             ← Complete reproducibility guide (this revision)
│   ├── reviewer_1_report.md           ← Simulated review: Networking & Systems
│   ├── reviewer_2_report.md           ← Simulated review: Experimental Research
│   └── reviewer_3_report.md           ← Simulated review: IEEE Publication Standards
│
├── results/
│   ├── verified_metrics.csv           ← Ground-truth metrics (from verify_metrics.py)
│   ├── per_session_metrics.csv        ← Per-capture breakdown
│   ├── per_domain_metrics.csv         ← Per-domain breakdown (50 domains)
│   ├── ablation_results.csv           ← 5-configuration ablation study results
│   ├── ablation_benchmark.pcap        ← 200-flow fragmented TLS ablation corpus
│   ├── ablation_ground_truth.csv      ← Ground truth for ablation corpus
│   ├── statistical_results.csv        ← Domain-level paired t-test results (N=50)
│   └── benchmark_results.csv          ← Verified throughput benchmark data
│
├── figures/
│   ├── baseline_comparison.png        ← Precision/Recall/F1 bar chart (4 methods)
│   ├── evidence_coverage.png          ← Detection method distribution (stacked bar)
│   ├── confusion_matrix.png           ← Domain-level normalized confusion matrix
│   ├── confusion_matrix_category.png  ← Category-level confusion matrix (6×7)
│   └── confusion_matrix_category.pdf  ← Vector PDF for LaTeX embedding
│
└── scripts/
    ├── verify_metrics.py              ← Independent metric recomputation
    ├── rigorous_statistical_analysis.py ← Domain-level statistical tests
    └── run_ablation_study.py          ← 5-configuration ablation generator
```

---

## Key Findings Summary

### Critical Errors Corrected in Revised Manuscript

| # | Error | Correction |
|---|---|---|
| 1 | SNI+DNS-single F1 = 0.694 (copied from SNI-only) | Recomputed: F1 = 0.695 (identical to SNI-only — correct on this corpus) |
| 2 | SNI+DNS-single reported P=0.951, R=0.673 (fabricated) | Corrected to P=1.000, R=0.532 (verified by `verify_metrics.py`) |
| 3 | Statistical p-value hardcoded as 0.0001 at N=4 | Redesigned: N=50 domain-level paired t-test, p=4.99×10⁻²⁵ |
| 4 | Fabricated error analysis table (Table IV) | Removed; replaced with authentic zero-FP analysis |
| 5 | TCP reassembly claimed to contribute ~8pp on main dataset | Corrected: reassembler not invoked on primary corpus; contribution documented only from ablation |
| 6 | 500-flow FIFO truncation undisclosed | Disclosed as telemetry artifact affecting FN counts |

### Verified Ground-Truth Metrics

| Method | Precision | Recall | F1 | Coverage |
|---|---|---|---|---|
| Port-only | 0.000 | 0.000 | 0.000 | 1.000 |
| SNI-only | 1.000 | 0.532 | 0.695 | 0.532 |
| SNI + DNS-single | 1.000 | 0.532 | 0.695 | 0.532 |
| SNI + DNS-prob. | 1.000 | 0.800 | 0.889 | 0.800 |

**Key insight**: SNI-only and SNI+DNS-single are identical on this corpus because no flow has `engine_method == "DNS Query"` — all labeled flows use HTTPS (port 443) with TLS SNI. The +26.8pp recall improvement from SNI+DNS-single to DNS-probabilistic is due entirely to retroactive DNS-to-IP correlation.

---

## How to Run Verification Scripts

### Prerequisites

1. **Python 3.10+** with: `pip install pandas numpy matplotlib seaborn scipy scikit-learn scapy`
2. **Node.js 20+**: `npm install` in project root
3. **C++ engine built**: `cmake -B build && cmake --build build`

### From the Project Root

```powershell
# 1. Generate dataset
python scale_dataset.py

# 2. Run full evaluation pipeline
.\run_evaluation.ps1

# 3. Verify metrics independently  
python research_revision\scripts\verify_metrics.py

# 4. Run domain-level statistical tests
python research_revision\scripts\rigorous_statistical_analysis.py

# 5. Run ablation study
python research_revision\scripts\run_ablation_study.py

# 6. Run unit tests
npm test
```

---

## LaTeX Compilation

> [!WARNING]
> `pdflatex` is not installed on the development system. The manuscript must be compiled on Overleaf or a system with MiKTeX/TeX Live installed.

### Option A — Overleaf (Recommended)

1. Upload `research_revision/revised_manuscript.tex` to Overleaf
2. Upload all figures from `research_revision/figures/` to the same project directory
3. Set compiler to **pdfLaTeX**
4. Also upload `SystemArchitecture.png`, `dashboard_rules_crop.png`, `dashboard_overview_crop.png`, `dashboard_protocol_crop.png` from the project root (referenced in the manuscript)

### Option B — MiKTeX (Local)

```powershell
winget install MiKTeX.MiKTeX
# Then restart terminal and:
cd research_revision
pdflatex revised_manuscript.tex
pdflatex revised_manuscript.tex  # run twice for references
```

### Figures Referenced in Manuscript

Ensure these files are in the same directory as `revised_manuscript.tex` when compiling:

| Figure File | Source |
|---|---|
| `SystemArchitecture.png` | Project root |
| `dashboard_overview_crop.png` | Project root |
| `dashboard_protocol_crop.png` | Project root |
| `dashboard_rules_crop.png` | Project root |
| `evidence_coverage.png` | `research_revision/figures/` |
| `confusion_matrix.png` | `research_revision/figures/` |
| `baseline_comparison.png` | `research_revision/figures/` |

---

## Open Issues for Camera-Ready

1. **nDPI comparison** (requested by Reviewer 3): Run `ndpiReader` on the four evaluation PCAPs and add results to Table II.
2. **CDN disambiguation experiment** (requested by Reviewer 2): Add a sub-experiment with shared IPs to validate the probabilistic cache's differentiating behavior.
3. **ECH discussion** (requested by Reviewer 3): Add 2–3 sentences about Encrypted Client Hello impact in Section II or VII.
4. **Appendix A reference**: The manuscript references "Appendix A" in the ablation scope note. Either add the appendix or change the reference to "Section V-E (Ablation Study)".
5. **WFP section reduction** (requested by Reviewer 1): Reduce WFP description to 2–3 sentences; move details to Future Work.
6. **Bounded telemetry evaluation** (requested by Reviewer 3): Either add memory usage benchmarks or remove from title.

---

## Reviewer Summary

| Reviewer | Role | Recommendation |
|---|---|---|
| Reviewer 1 | Networking & Systems | Weak Accept |
| Reviewer 2 | Experimental Research | Borderline — Major Revision |
| Reviewer 3 | IEEE Publication Standards | Weak Reject → Borderline |

**Overall**: The implementation is genuine, the methodology is honest, and the metric audit uncovered and corrected real errors. The path to acceptance requires (1) nDPI comparison, (2) CDN disambiguation sub-experiment or clear scope limitation in the abstract, and (3) ECH discussion.

