#!/usr/bin/env bash
# ==============================================================================
# run_evaluation.sh - Automated End-to-End Evaluation Pipeline (POSIX / Bash)
# ==============================================================================
# Executes:
# 1. Dependency and input file verification (4 PCAPs, 4 ground-truth CSVs, C++ binary)
# 2. C++ DPI Engine execution across all captures -> output_capture_N.json
# 3. Baseline comparison & metric computation -> baseline_comparison.csv, error_analysis.csv
# 4. Statistical significance & confidence interval computation -> results_table.tex
# ==============================================================================

set -euo pipefail

echo "=============================================================================="
echo " DEEPPACKET-ANALYZER: END-TO-END RESEARCH EVALUATION PIPELINE"
echo "=============================================================================="

# ------------------------------------------------------------------------------
# STEP 1: Verify Engine Binary
# ------------------------------------------------------------------------------
echo -e "\n[Step 1/5] Locating C++ DPI Engine..."

ENGINE="${DPA_ENGINE_PATH:-}"

if [ -z "$ENGINE" ]; then
    if [ -f "./build/PacketInspector.exe" ]; then
        ENGINE="./build/PacketInspector.exe"
    elif [ -f "./build/PacketInspector" ]; then
        ENGINE="./build/PacketInspector"
    elif [ -f "../build/PacketInspector" ]; then
        ENGINE="../build/PacketInspector"
    elif [ -f "./PacketInspector" ]; then
        ENGINE="./PacketInspector"
    elif command -v PacketInspector >/dev/null 2>&1; then
        ENGINE="$(command -v PacketInspector)"
    fi
fi

if [ -z "$ENGINE" ] || [ ! -f "$ENGINE" ]; then
    echo "[Error] C++ engine binary not found. Set DPA_ENGINE_PATH or run: cmake --build build" >&2
    exit 1
fi

echo "[✓] Found DPI Engine binary: $ENGINE"

# ------------------------------------------------------------------------------
# STEP 2: Verify Input Datasets (4 PCAPs, 4 CSVs)
# ------------------------------------------------------------------------------
echo -e "\n[Step 2/5] Verifying Dataset Files (1,400 flows across 4 captures)..."

MISSING=0
for i in 1 2 3 4; do
    if [ ! -f "dataset_capture_${i}.pcap" ]; then
        echo "[!] Missing: dataset_capture_${i}.pcap"
        MISSING=1
    fi
    if [ ! -f "ground_truth_${i}.csv" ]; then
        echo "[!] Missing: ground_truth_${i}.csv"
        MISSING=1
    fi
done

if [ "$MISSING" -ne 0 ]; then
    echo "[*] Generating synthetic 1,400-flow dataset via scale_dataset.py..."
    python3 scripts/scale_dataset.py --synthetic --captures 4 --sessions-per-domain 5 --negative-samples 100 --session-delay 0 --capture-gap 0
else
    echo "[✓] All 4 PCAP files and 4 ground-truth CSV files verified."
fi

# ------------------------------------------------------------------------------
# STEP 3: Execute C++ Engine Across All Captures
# ------------------------------------------------------------------------------
echo -e "\n[Step 3/5] Processing Captures with DPI Engine..."

for i in 1 2 3 4; do
    PCAP="dataset_capture_${i}.pcap"
    OUT_JSON="output_capture_${i}.json"

    echo "    -> Running $ENGINE on $PCAP..."
    "$ENGINE" --pcap "$PCAP" >/dev/null 2>&1 || "$ENGINE" "$PCAP" >/dev/null 2>&1

    if [ ! -f "output.json" ]; then
        echo "[Error] Engine failed to write output.json for $PCAP" >&2
        exit 1
    fi

    cp -f "output.json" "$OUT_JSON"
    echo "    [✓] Archived output.json -> $OUT_JSON"
done

# ------------------------------------------------------------------------------
# STEP 4: Run Baseline Comparison & Error Analysis
# ------------------------------------------------------------------------------
echo -e "\n[Step 4/5] Executing Baseline Evaluation Suite..."

python3 scripts/evaluate_baselines.py --skip-engine

# ------------------------------------------------------------------------------
# STEP 5: Run Statistical Significance & Confidence Interval Suite
# ------------------------------------------------------------------------------
echo -e "\n[Step 5/5] Computing Statistical Significance & 95% Confidence Intervals..."

python3 scripts/statistical_analysis.py
python3 scripts/plot_publication_matrix.py || true

# ------------------------------------------------------------------------------
# SUMMARY & ARTIFACT DIRECTORY
# ------------------------------------------------------------------------------
echo ""
echo "=============================================================================="
echo " PIPELINE COMPLETE - GENERATED RESEARCH ARTIFACTS"
echo "=============================================================================="

echo "  Telemetry Snapshots:"
ls -lh output_capture_*.json 2>/dev/null || true

echo -e "\n  Quantitative Metrics:"
ls -lh baseline_comparison.csv baseline_aggregate.csv 2>/dev/null || true

echo -e "\n  Error Analysis:"
ls -lh error_analysis.csv 2>/dev/null || true

echo -e "\n  Statistical Significance:"
ls -lh statistical_significance.csv statistical_tests.csv results_table.tex 2>/dev/null || true

echo -e "\n  Publication Figures:"
ls -lh baseline_comparison.png evidence_coverage.png 2>/dev/null || true

echo "=============================================================================="
echo " All results, tables, and figures are ready for LaTeX inclusion."
echo "=============================================================================="

