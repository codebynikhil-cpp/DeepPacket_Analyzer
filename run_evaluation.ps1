# ==============================================================================
# run_evaluation.ps1 - Automated End-to-End Evaluation Pipeline (Windows PowerShell)
# ==============================================================================
# Executes:
#   1. Dependency and input file verification (4 PCAPs, 4 ground-truth CSVs, C++ binary)
#   2. C++ DPI Engine execution across all captures -> output_capture_N.json
#   3. Baseline comparison and metric computation -> baseline_comparison.csv, error_analysis.csv
#   4. Statistical significance and confidence interval computation -> results_table.tex
#   5. Final artifact summary
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\run_evaluation.ps1
#   powershell -ExecutionPolicy Bypass -File .\run_evaluation.ps1 -SkipEngineRun
#   $env:DPA_ENGINE_PATH = ".\build\PacketInspector.exe"
# ==============================================================================

[CmdletBinding()]
param(
    [string]$EnginePath = $env:DPA_ENGINE_PATH,
    [switch]$SkipEngineRun
)

$ErrorActionPreference = "Stop"

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host " DEEPPACKET-ANALYZER: END-TO-END RESEARCH EVALUATION PIPELINE" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# STEP 1: Verify Engine Binary
# ------------------------------------------------------------------------------
Write-Host "`n[Step 1/5] Locating C++ DPI Engine..." -ForegroundColor Yellow

if (-not $EnginePath) {
    $candidates = @(
        ".\build\PacketInspector.exe",
        ".\build\PacketInspector",
        "..\build\PacketInspector.exe",
        ".\PacketInspector.exe"
    )
    foreach ($cand in $candidates) {
        if (Test-Path $cand) {
            $EnginePath = (Resolve-Path $cand).Path
            break
        }
    }
}

if (-not $EnginePath -or -not (Test-Path $EnginePath)) {
    Write-Host "[Error] C++ engine binary not found." -ForegroundColor Red
    Write-Host "        Set DPA_ENGINE_PATH or compile with:" -ForegroundColor Red
    Write-Host "            cmake -B build -G `"MinGW Makefiles`"" -ForegroundColor Red
    Write-Host "            cmake --build build" -ForegroundColor Red
    exit 1
}

Write-Host "[OK] Found DPI Engine binary: $EnginePath" -ForegroundColor Green

# ------------------------------------------------------------------------------
# STEP 2: Verify Input Datasets (4 PCAPs, 4 CSVs)
# ------------------------------------------------------------------------------
Write-Host "`n[Step 2/5] Verifying Dataset Files (4 captures, 350 flows each)..." -ForegroundColor Yellow

$missingFiles = @()
for ($i = 1; $i -le 4; $i++) {
    $pcap = "dataset_capture_${i}.pcap"
    $csv  = "ground_truth_${i}.csv"

    if (-not (Test-Path $pcap)) { $missingFiles += $pcap }
    if (-not (Test-Path $csv))  { $missingFiles += $csv  }
}

if ($missingFiles.Count -gt 0) {
    Write-Host "[!] Missing dataset files:" -ForegroundColor Yellow
    foreach ($mf in $missingFiles) {
        Write-Host "      - $mf" -ForegroundColor Yellow
    }
    Write-Host "[*] Generating synthetic dataset via scale_dataset.py..." -ForegroundColor Cyan
    python scripts/scale_dataset.py --synthetic --captures 4 --sessions-per-domain 5 --negative-samples 100 --session-delay 0 --capture-gap 0
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[Error] Failed to generate dataset. Run python scripts/scale_dataset.py manually." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[OK] All 4 PCAP files and 4 ground-truth CSV files verified." -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# STEP 3: Execute C++ Engine Across All Captures
# ------------------------------------------------------------------------------
Write-Host "`n[Step 3/5] Processing Captures with DPI Engine..." -ForegroundColor Yellow

for ($i = 1; $i -le 4; $i++) {
    $pcap    = "dataset_capture_${i}.pcap"
    $outJson = "output_capture_${i}.json"

    if ($SkipEngineRun -and (Test-Path $outJson)) {
        Write-Host "    -> Capture $i : Using existing $outJson (-SkipEngineRun)" -ForegroundColor Gray
        continue
    }

    Write-Host "    -> Running engine on $pcap ..." -ForegroundColor White

    # Try positional arg first (primary CLI), fall back to --pcap flag
    $exitCode = 0
    try {
        & $EnginePath $pcap 2>$null
        $exitCode = $LASTEXITCODE
    } catch {
        $exitCode = 1
    }

    if ($exitCode -ne 0 -or -not (Test-Path "output.json")) {
        try {
            & $EnginePath --pcap $pcap 2>$null
            $exitCode = $LASTEXITCODE
        } catch {
            $exitCode = 1
        }
    }

    if (-not (Test-Path "output.json")) {
        Write-Host "[Error] Engine failed to produce output.json for $pcap" -ForegroundColor Red
        exit 1
    }

    Copy-Item "output.json" $outJson -Force
    Write-Host "    [OK] Archived output.json -> $outJson" -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# STEP 4: Run Baseline Comparison and Error Analysis
# ------------------------------------------------------------------------------
Write-Host "`n[Step 4/5] Executing Baseline Evaluation Suite..." -ForegroundColor Yellow

python scripts/evaluate_baselines.py --skip-engine
if ($LASTEXITCODE -ne 0) {
    Write-Host "[Error] evaluate_baselines.py failed." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Baseline evaluation complete." -ForegroundColor Green

# ------------------------------------------------------------------------------
# STEP 5: Run Statistical Significance and Confidence Interval Suite
# ------------------------------------------------------------------------------
Write-Host "`n[Step 5/5] Computing Statistical Significance and Publication Figures..." -ForegroundColor Yellow

python scripts/statistical_analysis.py
if ($LASTEXITCODE -ne 0) {
    Write-Host "[Error] statistical_analysis.py failed." -ForegroundColor Red
    exit 1
}

python scripts/plot_publication_matrix.py
if ($LASTEXITCODE -ne 0) {
    Write-Host "[Warning] plot_publication_matrix.py encountered an issue." -ForegroundColor Yellow
}

Write-Host "[OK] Statistical analysis and publication graphics complete." -ForegroundColor Green

# ------------------------------------------------------------------------------
# SUMMARY AND ARTIFACT DIRECTORY
# ------------------------------------------------------------------------------
Write-Host "`n==============================================================================" -ForegroundColor Cyan
Write-Host " PIPELINE COMPLETE - GENERATED RESEARCH ARTIFACTS" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan

$artifactGroups = @(
    [PSCustomObject]@{
        Name  = "Engine Telemetry Snapshots"
        Files = @("output_capture_1.json","output_capture_2.json","output_capture_3.json","output_capture_4.json")
    },
    [PSCustomObject]@{
        Name  = "Quantitative Metrics"
        Files = @("baseline_comparison.csv","baseline_aggregate.csv")
    },
    [PSCustomObject]@{
        Name  = "Error Analysis"
        Files = @("error_analysis.csv")
    },
    [PSCustomObject]@{
        Name  = "Statistical Analysis"
        Files = @("statistical_significance.csv","statistical_tests.csv","results_table.tex")
    },
    [PSCustomObject]@{
        Name  = "Publication Figures"
        Files = @("confusion_matrix_category.png","confusion_matrix_category.pdf","confusion_matrix.png","baseline_comparison.png","evidence_coverage.png")
    }
)

foreach ($group in $artifactGroups) {
    Write-Host "`n  $($group.Name):" -ForegroundColor Yellow
    foreach ($f in $group.Files) {
        if (Test-Path $f) {
            $sz = [math]::Round((Get-Item $f).Length / 1KB, 1)
            Write-Host "    [OK] $f  ($sz KB)" -ForegroundColor Green
        } else {
            Write-Host "    [--] $f  (not generated)" -ForegroundColor DarkGray
        }
    }
}

Write-Host "`n==============================================================================" -ForegroundColor Cyan
Write-Host " All results, tables, and figures are ready for LaTeX inclusion." -ForegroundColor Cyan
Write-Host "==============================================================================`n" -ForegroundColor Cyan
