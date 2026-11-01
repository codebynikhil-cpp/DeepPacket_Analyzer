# DeepPacket Analyzer — Research Evaluation Pipeline

A production-grade Deep Packet Inspection (DPI) engine with a full end-to-end research evaluation suite.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Building the C++ Engine](#building-the-c-engine)
4. [Setting `DPA_ENGINE_PATH`](#setting-dpa_engine_path)
5. [Running the Full Pipeline](#running-the-full-pipeline)
6. [Step-by-Step Manual Execution](#step-by-step-manual-execution)
7. [Output Files Reference](#output-files-reference)
8. [Dataset Generation Details](#dataset-generation-details)
9. [Evaluation Methodology](#evaluation-methodology)
10. [C++ Engine Modules](#c-engine-modules)
11. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```
                    ┌──────────────────────────────────────────────────┐
                    │              C++ DPI Engine (PacketInspector.exe) │
                    │                                                    │
  PCAP File ──────► │  ProbabilisticDnsCache ──► ConnectionTracker      │──► output.json
                    │  TcpReassembler        ──► DPIEngine              │
                    │  WFP Integration       ──► Telemetry              │
                    └──────────────────────────────────────────────────┘
                                          │
                    ┌─────────────────────▼────────────────────────────┐
                    │              Python Evaluation Suite              │
                    │                                                    │
  ground_truth.csv ►│  evaluate_baselines.py  (4 classification methods)│──► baseline_comparison.csv
                    │  statistical_analysis.py (Wilson CIs, bootstrap)  │──► results_table.tex
                    │  evaluate_dpi.py         (single-capture eval)    │──► confusion_matrix.png
                    └──────────────────────────────────────────────────┘
```

---

## Prerequisites

### System

| Requirement | Minimum Version | Notes |
|-------------|----------------|-------|
| Windows     | 10 / 11        | Primary target platform |
| Npcap       | 1.70+          | Required for live PCAP capture; install with WinPcap API compatibility |
| CMake       | 3.16+          | Build system |
| C++ Compiler| MinGW-w64 (GCC 11+) or MSVC 2022 | C++17 required |
| Python      | 3.10+          | Evaluation scripts |
| Node.js     | 18+            | Unit test runner (`npm test`) |

### Python Dependencies

```powershell
pip install requests urllib3 scapy pandas numpy matplotlib scikit-learn scipy
```

Full list with verified versions:

```
requests>=2.31.0
urllib3>=2.0.0
scapy>=2.5.0
pandas>=2.0.0
numpy>=1.24.0
matplotlib>=3.7.0
scikit-learn>=1.3.0
scipy>=1.11.0
```

### Node.js Dependencies

```powershell
npm install
```

---

## Building the C++ Engine

```powershell
# From the project root
cmake -B build -G "MinGW Makefiles"
cmake --build build
```

For MSVC (Visual Studio):

```powershell
cmake -B build
cmake --build build --config Release
```

Verify the build succeeded:

```powershell
.\build\PacketInspector.exe --help
# Or just run it — it will print usage on no args
```

Run unit tests (14 tests, all must pass):

```powershell
npm test
```

> [!IMPORTANT]
> The flow cap in `src/connection_tracker.cpp` is set to **500** (`recent_flows_.size() > 500`).
> Do **not** raise this above ~500 without re-running `npm test` — the analytics test enforces
> `JSON.stringify(data).length < 400000` on a 5,000-packet fixture.

---

## Setting `DPA_ENGINE_PATH`

The orchestration scripts auto-discover the engine at `.\build\PacketInspector.exe`.
Override this with the `DPA_ENGINE_PATH` environment variable:

**PowerShell (session-scoped):**
```powershell
$env:DPA_ENGINE_PATH = ".\build\PacketInspector.exe"
```

**PowerShell (permanent, current user):**
```powershell
[System.Environment]::SetEnvironmentVariable("DPA_ENGINE_PATH", ".\build\PacketInspector.exe", "User")
```

**Bash / WSL:**
```bash
export DPA_ENGINE_PATH=./build/PacketInspector
```

---

## Running the Full Pipeline

### Windows (PowerShell) — Recommended

```powershell
powershell -ExecutionPolicy Bypass -File .\run_evaluation.ps1
```

**Flags:**

| Flag | Effect |
|------|--------|
| *(none)* | Full pipeline: generate dataset → run engine → evaluate → statistics |
| `-SkipEngineRun` | Reuse existing `output_capture_N.json` files; skip engine invocations |
| `-EnginePath <path>` | Override engine binary path |

**Example — reuse existing engine outputs:**
```powershell
powershell -ExecutionPolicy Bypass -File .\run_evaluation.ps1 -SkipEngineRun
```

### Linux / macOS / WSL (Bash)

```bash
bash run_evaluation.sh
```

**Environment variables:**
```bash
export DPA_ENGINE_PATH=./build/PacketInspector
bash run_evaluation.sh
```

---

## Step-by-Step Manual Execution

If you prefer to run each stage individually:

### 1. Generate Synthetic Dataset (1,400 flows across 4 captures)

```powershell
python scripts/scale_dataset.py `
    --synthetic `
    --captures 4 `
    --sessions-per-domain 5 `
    --negative-samples 100 `
    --session-delay 0 `
    --capture-gap 0
```

For live capture (requires Npcap and network access):

```powershell
# List interfaces
python scripts/scale_dataset.py --list-interfaces

# Capture on interface 6 with 30-second session delays
python scripts/scale_dataset.py --interface 6 --session-delay 30
```

### 2. Run the C++ Engine on Each Capture

```powershell
for ($i = 1; $i -le 4; $i++) {
    .\build\PacketInspector.exe "dataset_capture_$i.pcap"
    Copy-Item output.json "output_capture_$i.json" -Force
}
```

### 3. Run Baseline Evaluation

```powershell
python scripts/evaluate_baselines.py --skip-engine
```

### 4. Run Statistical Analysis

```powershell
python scripts/statistical_analysis.py
```

### 5. (Optional) Single-Capture Deep Evaluation

```powershell
python scripts/evaluate_dpi.py `
    --output output_capture_1.json `
    --ground-truth ground_truth_1.csv
```

---

## Output Files Reference

### Engine Telemetry

| File | Description |
|------|-------------|
| `output.json` | Raw engine telemetry for the most recently processed PCAP |
| `output_capture_1.json` … `output_capture_4.json` | Archived telemetry per capture run |

Each JSON record contains:

```json
{
  "src_ip": "192.168.1.100",
  "dst_ip": "142.250.80.46",
  "dst_port": 443,
  "domain": "google.com",
  "application": "Web Browser",
  "method": "TLS SNI",
  "confidence": 95
}
```

**`method` values:**

| Value | Meaning |
|-------|---------|
| `TLS SNI` | Domain extracted from TLS Client Hello ServerName extension |
| `HTTP Host` | Domain extracted from plaintext HTTP Host header |
| `DNS Query` | Domain observed in DNS query (single-domain cache) |
| `DNS Correlation` | Domain resolved via probabilistic multi-domain DNS cache |
| `Port 443` | Port-based classification only (no domain evidence) |
| `Port 80` | Port-based classification only |
| `Port 53` | DNS port classification |

### Evaluation Metrics

| File | Description |
|------|-------------|
| `baseline_comparison.csv` | Per-capture, per-method metrics (precision, recall, F1, coverage, TP, FP, FN, TN) |
| `baseline_aggregate.csv` | Mean ± std across all 4 captures per method |
| `error_analysis.csv` | Flow-level error breakdown: FP/FN flows with predicted vs. true domain |

### Statistical Analysis

| File | Description |
|------|-------------|
| `statistical_significance.csv` | Wilson score CIs (precision/recall) + bootstrap CIs (F1) for each method |
| `statistical_tests.csv` | Paired t-tests / Wilcoxon signed-rank results between method pairs (p-value, Cohen's d) |
| `results_table.tex` | LaTeX-formatted results table ready for direct inclusion in a paper |

### Figures

| File | Description |
|------|-------------|
| `confusion_matrix_category.png` | Publication-quality 6×7 category confusion matrix (PNG format) |
| `confusion_matrix_category.pdf` | Vector graphic version for direct LaTeX `\includegraphics` inclusion |
| `confusion_matrix.png` | Representative domain disambiguation matrix |
| `baseline_comparison.png` | Bar chart: precision / recall / F1 per method |
| `evidence_coverage.png` | Coverage (fraction of flows classified) per method across captures |
| `evaluation_report.txt` | Human-readable narrative summary with key deltas highlighted |

---

## Dataset Generation Details

`scripts/scale_dataset.py` generates a **1,400-flow labelled dataset** (4 captures × 350 flows each):

- **250 positive flows** (50 domains × 5 sessions each):
  - 70% emit a full TLS Client Hello with SNI → tests `TLS SNI` extraction path
  - 30% emit DNS response + TLS application data only → tests `DNS Correlation` fallback

- **100 negative flows** (connections to public IPs with no associated domain):
  - Tests false-positive rate of each baseline method

**Domain categories (50 total):**

| Category | Count | Examples |
|----------|-------|---------|
| Search | 10 | google.com, bing.com, duckduckgo.com |
| Streaming | 10 | youtube.com, netflix.com, spotify.com |
| Developer | 10 | github.com, stackoverflow.com, docker.com |
| Social | 10 | twitter.com, reddit.com, discord.com |
| E-commerce | 10 | amazon.com, ebay.com, paypal.com |

**Ground truth CSV columns:**

```
src_ip, src_port, dst_ip, dst_port, true_domain, category, session_id, capture_id
```

---

## Evaluation Methodology

Four baseline classifiers are compared:

| Baseline | Method | Description |
|----------|--------|-------------|
| (a) Port-only | Port number | 443 → HTTPS, 80 → HTTP, 53 → DNS |
| (b) SNI-only | TLS SNI / HTTP Host | Uses domain only when SNI/Host header observed |
| (c) SNI + DNS-single | + single DNS cache | Adds DNS Query matches (legacy single-domain cache) |
| (d) SNI + DNS-probabilistic | + multi-domain cache | Adds DNS Correlation (new probabilistic cache) |

**Metrics computed:**

$$\text{Precision} = \frac{TP}{TP + FP} \qquad \text{Recall} = \frac{TP}{TP + FN} \qquad F_1 = \frac{2 \cdot P \cdot R}{P + R}$$

$$\text{Coverage} = \frac{TP + FP}{\text{Total flows}}$$

**Statistical testing:**
- 95% **Wilson score** confidence intervals for precision and recall (exact binomial)
- 95% **Bootstrap** confidence intervals for F1 (1,000 resamples)
- **Paired t-test** (or Wilcoxon signed-rank if non-normal, n = 4 captures) between all method pairs
- **Cohen's d** effect size for each pair comparison

---

## C++ Engine Modules

### `ProbabilisticDnsCache` (new)

*Files: [`include/probabilistic_dns_cache.h`](include/probabilistic_dns_cache.h), [`src/probabilistic_dns_cache.cpp`](src/probabilistic_dns_cache.cpp)*

Thread-safe, weighted multi-domain DNS cache:

- Maps `uint32_t` IP → `std::vector<DnsRecord>` (max 5 entries per IP, sorted by observation weight)
- **TTL enforcement:** expired entries are lazily skipped on lookup and removed by `cleanupExpired()`
- **Ambiguity metric:** `getOverwriteCount()` tracks IPs with multiple associated domains (useful for CDN analysis)
- **WFP sync:** `getActiveMappings()` returns all live `{ip, domain}` pairs for Windows Filtering Platform rule installation
- **Thread safety:** `std::shared_mutex` — concurrent reads, exclusive writes

### `TcpReassembler` (new)

*Files: [`include/tcp_reassembler.h`](include/tcp_reassembler.h), [`src/tcp_reassembler.cpp`](src/tcp_reassembler.cpp)*

Minimal TCP stream reassembler for segmented TLS Client Hellos:

- Tracks 4-tuple flows: `(src_ip, src_port, dst_ip, dst_port)`
- Accumulates TCP segments (up to 2,048 bytes) until SNI can be parsed
- **Idle eviction:** flows inactive for > 5 seconds are purged by `evictOldFlows()`
- Solves the "split Client Hello" limitation where the SNI extension spans two TCP segments

### `DPIEngine` (updated)

*Files: [`include/dpi_engine.h`](include/dpi_engine.h), [`src/dpi_engine.cpp`](src/dpi_engine.cpp)*

Now has a `TcpReassembler tcp_reassembler_` member. TLS inspection on port 443:
1. Attempt direct SNI extraction from current packet
2. If unsuccessful, pass to `tcp_reassembler_.inspectSegment()` for fragment accumulation

### `ConnectionTracker` (updated)

*Files: [`include/connection_tracker.h`](include/connection_tracker.h), [`src/connection_tracker.cpp`](src/connection_tracker.cpp)*

Replaced legacy `ip_to_domain_` map with `ProbabilisticDnsCache dns_cache_`. Key changes:
- `reinstallWfpRules()` uses `dns_cache_.getActiveMappings()`
- Periodic cleanup: `dns_cache_.cleanupExpired()` + `tcp_reassembler_.evictOldFlows()`
- Flow ring-buffer capped at **500** entries (load-bearing for unit test JSON size assertion)

---

## Troubleshooting

### Engine not found

```
[Error] C++ engine binary not found.
```

**Fix:** Run `cmake --build build` first, then verify `.\build\PacketInspector.exe` exists.

### Dataset files missing

The script auto-generates a synthetic dataset. If Python fails:

```powershell
python scripts/scale_dataset.py --synthetic --captures 4 --sessions-per-domain 5 --negative-samples 100 --session-delay 0 --capture-gap 0
```

### `output.json` not produced after engine run

The engine writes `output.json` to the **current working directory**. Always run from the project root:

```powershell
cd "d:\New Projects\DeepPacket-Analyzer-Real-time-packet-capture-and-deep-traffic-analysis-main"
.\build\PacketInspector.exe dataset_capture_1.pcap
```

### `ModuleNotFoundError: No module named 'generate_ground_truth'`

Run Python scripts from the project root, not from inside `scripts/`:

```powershell
# Correct
python scripts/scale_dataset.py --synthetic ...

# Wrong (will fail imports)
cd scripts
python scale_dataset.py --synthetic ...
```

### PowerShell execution policy

```powershell
powershell -ExecutionPolicy Bypass -File .\run_evaluation.ps1
```

### Unicode errors on Windows (cp1252)

All Python scripts call `sys.stdout.reconfigure(encoding="utf-8", errors="replace")` at startup.
If you see garbled output, set:

```powershell
$env:PYTHONIOENCODING = "utf-8"
```

### `npm test` fails after changing flow cap

The test at `test/analytics.test.js:29` asserts `JSON.stringify(data).length < 400000`.
Keep `recent_flows_.size() > 500` in `src/connection_tracker.cpp`. Do not raise without re-running `npm test`.

---

*Generated as part of the DeepPacket Analyzer DPI Research Evaluation Suite.*

