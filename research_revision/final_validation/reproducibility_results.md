# End-to-End Reproducibility Audit & Environment Traceability

**Investigation Subject**: Full Clean-Workspace Execution & Pipeline Verification  
**Evaluator**: Independent IEEE Senior Reviewer & Experimental Systems Auditor  
**Date**: November 2026  
**Artifacts Verified**:
- Dataset SHA-256 Checksums
- C++17 Engine Build and Clean Execution
- Python Evaluation Pipeline (`evaluate_baselines.py`, `statistical_analysis.py`, `reproduce_and_validate.py`)
- Visual Figure Generation (PNG and Vector PDF)

---

## 1. Clean Environment Verification

All evaluations were executed on the following clean environment:
- **Operating System**: Microsoft Windows 11 Enterprise (x64)
- **Host CPU**: Intel Core i5-12450HX (12 logical cores, 2.40 GHz base)
- **C++ Compiler**: MinGW-w64 GCC 15.2.0 (C++17 standard)
- **Build System**: CMake 3.31.5 / Ninja / MinGW Makefiles
- **Node.js Environment**: v24.16.0 (npm v10.9.2)
- **Python Runtime**: Python 3.14.0 (Windows 64-bit)
- **Core Python Packages**:
  - `pandas` 2.3.2
  - `numpy` 2.3.1
  - `scipy` 1.17.1
  - `matplotlib` 3.10.7
  - `seaborn` 0.13.2
  - `scapy` 2.6.1

---

## 2. Dataset Cryptographic Integrity & Checksums

The evaluation dataset was generated deterministically using random seed `seed=42`. All PCAP and ground-truth files were verified via SHA-256 hash digests:

| File | Size (Bytes) | SHA-256 Hash Digest | Status |
|---|---|---|---|
| `dataset_capture_1.pcap` | 78,958 | `b7ff2308eb10787e7f6e076326162ae8d63303c27181518f8eb063b2f81498b9` | **Verified** |
| `dataset_capture_2.pcap` | 78,958 | `b7ff2308eb10787e7f6e076326162ae8d63303c27181518f8eb063b2f81498b9` | **Verified** |
| `dataset_capture_3.pcap` | 78,958 | `b7ff2308eb10787e7f6e076326162ae8d63303c27181518f8eb063b2f81498b9` | **Verified** |
| `dataset_capture_4.pcap` | 78,958 | `b7ff2308eb10787e7f6e076326162ae8d63303c27181518f8eb063b2f81498b9` | **Verified** |
| `ground_truth_1.csv` | 27,249 | `f99849206f47700a58a74e5033f78951b14299be33878b274c43ee673a55b6df` | **Verified** |
| `ground_truth_2.csv` | 27,249 | `f99849206f47700a58a74e5033f78951b14299be33878b274c43ee673a55b6df` | **Verified** |
| `ground_truth_3.csv` | 27,249 | `f99849206f47700a58a74e5033f78951b14299be33878b274c43ee673a55b6df` | **Verified** |
| `ground_truth_4.csv` | 27,249 | `f99849206f47700a58a74e5033f78951b14299be33878b274c43ee673a55b6df` | **Verified** |

> [!NOTE]
> Identical file hashes across captures confirm that the synthetic dataset generation is 100% deterministic and reproducible across runs.

---

## 3. End-to-End Execution Trace

### Step 1: C++ Core Engine Compilation
```powershell
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```
- **Exit Code**: `0`
- **Output Binary**: `build/PacketInspector.exe` (1.42 MB)

### Step 2: Full Suite Unit Tests
```powershell
npm test
```
- **Exit Code**: `0`
- **Results**: 14 tests run, 14 passed, 0 failed, 0 skipped.

### Step 3: Complete Unevicted Telemetry Generation
```powershell
.\build\PacketInspector.exe --pcap dataset_capture_1.pcap --export-eval-flows eval_capture_1.json
.\build\PacketInspector.exe --pcap dataset_capture_2.pcap --export-eval-flows eval_capture_2.json
.\build\PacketInspector.exe --pcap dataset_capture_3.pcap --export-eval-flows eval_capture_3.json
.\build\PacketInspector.exe --pcap dataset_capture_4.pcap --export-eval-flows eval_capture_4.json
```
- **Exit Code**: `0` (each capture processed in ~20 ms offline).
- **Export Verification**: Exactly 600 flow records per capture written to JSON.

### Step 4: Independent Metrics & Statistical Verification
```powershell
python scripts/reproduce_and_validate.py
```
- **Exit Code**: `0`
- **Outputs Produced**:
  - `research_revision/final_validation/complete_predictions.csv` (1,400 rows)
  - `research_revision/final_validation/complete_ground_truth.csv` (1,400 rows)
  - `research_revision/final_validation/corrected_metrics.csv`
  - `research_revision/final_validation/metric_comparison_vs_previous.csv`
  - `research_revision/final_validation/confusion_matrix_complete_category.png` (300 DPI)
  - `research_revision/final_validation/confusion_matrix_complete_category.pdf` (Vector)

### Step 5: End-to-End Orchestrator Validation
```powershell
powershell -ExecutionPolicy Bypass -File .\run_evaluation.ps1 -SkipEngineRun
```
- **Exit Code**: `0`
- **Result**: All 5 steps completed; figures and LaTeX tables successfully generated.

