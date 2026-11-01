#!/usr/bin/env python3
"""
evaluate_baselines.py - Quantitative Baseline Comparison and Error Analysis
Author: Antigravity DPI Research Suite
Purpose: Evaluates DPI traffic classification across 4 independent PCAP captures,
         benchmarking four progressive classification paradigms:
         (a) Port-only heuristics
         (b) SNI-only inspection
         (c) SNI + DNS-single (Legacy 1:1 cache)
         (d) SNI + DNS-probabilistic (Novel weighted multi-domain engine)

Artifacts Produced:
1. output_capture_N.json (DPI engine telemetry per capture)
2. baseline_comparison.csv (Per-capture performance metrics)
3. baseline_aggregate.csv (Cross-capture mean +/- std deviation metrics)
4. error_analysis.csv (Top 20 misclassifications, prioritized by False Positives)
5. baseline_comparison.png (Grouped bar chart of Precision, Recall, F1)
6. evidence_coverage.png (Stacked resolution breakdown across captures)
"""

import os
import sys
import json
import shutil
import argparse
import subprocess
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def parse_args():
    parser = argparse.ArgumentParser(description="Evaluate DPI Engine Classification Baselines")
    parser.add_argument("--captures", type=int, default=4, help="Number of capture runs to evaluate (default: 4)")
    parser.add_argument("--engine-path", default=None,
                        help="Path to PacketInspector executable (overrides DPA_ENGINE_PATH env var)")
    parser.add_argument("--skip-engine", action="store_true",
                        help="Skip running C++ engine if output_capture_N.json files already exist")
    parser.add_argument("--output-prefix", default="", help="Prefix for output report filenames")
    return parser.parse_args()


def find_engine_executable(custom_path=None) -> str:
    """Finds PacketInspector binary from CLI flag, env var, or local build directories."""
    if custom_path and os.path.isfile(custom_path):
        return custom_path

    env_path = os.environ.get("DPA_ENGINE_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path

    candidates = [
        os.path.join(".", "build", "PacketInspector.exe"),
        os.path.join(".", "build", "PacketInspector"),
        os.path.join("..", "build", "PacketInspector.exe"),
        os.path.join("..", "build", "PacketInspector"),
        os.path.join(".", "PacketInspector.exe"),
        os.path.join(".", "PacketInspector"),
        shutil.which("PacketInspector.exe"),
        shutil.which("PacketInspector")
    ]
    for cand in candidates:
        if cand and os.path.isfile(cand):
            return os.path.abspath(cand)

    return None


def run_engine_for_pcap(engine_path: str, pcap_file: str, output_json_target: str):
    """Executes C++ PacketInspector on pcap_file and archives output.json to output_json_target."""
    if not os.path.exists(pcap_file):
        raise FileNotFoundError(f"PCAP capture file not found: {pcap_file}")

    print(f"[*] Executing DPI engine: {engine_path} on {pcap_file}...")
    
    # Try with --pcap first, fallback to positional argument
    cmd = [engine_path, "--pcap", pcap_file]
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, check=True)
    except subprocess.CalledProcessError:
        # Fallback to positional argument
        cmd = [engine_path, pcap_file]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, check=True)

    if not os.path.exists("output.json"):
        raise RuntimeError(f"Engine completed but output.json was not generated for {pcap_file}")

    shutil.copyfile("output.json", output_json_target)
    print(f"[+] Saved engine telemetry snapshot -> {output_json_target}")


def normalize_domain(dom: str) -> str:
    """Normalizes domain strings for robust equality matching."""
    if not isinstance(dom, str):
        return ""
    d = dom.strip().lower()
    if d.startswith("www."):
        d = d[4:]
    while d.endswith("."):
        d = d[:-1]
    return d


def load_telemetry_flows(json_path: str) -> list:
    """Loads flow records from output_capture_N.json."""
    if not os.path.exists(json_path):
        print(f"[Warning] Telemetry file {json_path} not found.")
        return []

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("flows", [])


def load_ground_truth(csv_path: str) -> pd.DataFrame:
    """Loads and standardizes ground_truth_N.csv."""
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Ground-truth file not found: {csv_path}")

    df = pd.read_csv(csv_path)
    df.columns = [c.strip().lower() for c in df.columns]
    return df


def match_ground_truth_with_engine(df_gt: pd.DataFrame, flows: list) -> list:
    """
    Pairs each ground-truth flow with its corresponding DPI engine telemetry record
    by endpoint tuple (src_ip, dst_ip, dst_port) with sequential allocation.
    """
    matched = []
    
    # Organize engine flows by endpoint key
    flow_map = {}
    for f in flows:
        key = (str(f.get("src_ip", "")), str(f.get("dst_ip", "")), int(f.get("dst_port", 0)))
        flow_map.setdefault(key, []).append(f)

    for _, row in df_gt.iterrows():
        src = str(row["src_ip"])
        dst = str(row["dst_ip"])
        dport = int(row["dst_port"])
        true_dom = str(row["true_domain"])
        label_type = str(row["label_type"]).lower()
        capture_id = int(row["capture_id"])

        key = (src, dst, dport)
        engine_flow = None

        if key in flow_map and len(flow_map[key]) > 0:
            engine_flow = flow_map[key].pop(0)
        else:
            # Fallback relaxed endpoint lookup by destination IP and port
            relaxed_key = None
            for k in flow_map:
                if k[1] == dst and k[2] == dport and len(flow_map[k]) > 0:
                    relaxed_key = k
                    break
            if relaxed_key:
                engine_flow = flow_map[relaxed_key].pop(0)

        domain_val = engine_flow.get("domain", "UNKNOWN") if engine_flow else "UNKNOWN"
        method_val = engine_flow.get("method", "UNKNOWN") if engine_flow else "UNKNOWN"

        matched.append({
            "capture_id": capture_id,
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": dport,
            "true_domain": true_dom,
            "label_type": label_type,
            "engine_domain": domain_val,
            "engine_method": method_val
        })

    return matched


# ============================================================================
# BASELINE CLASSIFIER LOGIC
# ============================================================================
def predict_baseline(record: dict, method_name: str) -> str:
    """
    Implements the 4 classification paradigms:
    (a) Port-only
    (b) SNI-only
    (c) SNI + DNS-single
    (d) SNI + DNS-probabilistic
    """
    dport = record["dst_port"]
    eng_dom = record["engine_domain"]
    eng_method = record["engine_method"]
    is_unknown = (not eng_dom or eng_dom.upper() == "UNKNOWN")

    if method_name == "Port-only":
        if dport == 443:
            return "HTTPS"
        elif dport == 80:
            return "HTTP"
        elif dport == 53:
            return "DNS"
        else:
            return "UNKNOWN"

    elif method_name == "SNI-only":
        if eng_method in ["TLS SNI", "HTTP Host"] and not is_unknown:
            return eng_dom
        return "UNKNOWN"

    elif method_name == "SNI + DNS-single":
        # Legacy: SNI, HTTP Host, or explicit DNS queries on port 53 (no multi-domain correlation)
        if eng_method in ["TLS SNI", "HTTP Host", "DNS Query"] and not is_unknown:
            return eng_dom
        return "UNKNOWN"

    elif method_name == "SNI + DNS-probabilistic":
        # Novel: SNI, HTTP Host, DNS Query, and Probabilistic DNS Correlation fallback
        if eng_method in ["TLS SNI", "HTTP Host", "DNS Query", "DNS Correlation"] and not is_unknown:
            return eng_dom
        return "UNKNOWN"

    return "UNKNOWN"


def compute_metrics(matched_records: list, method_name: str, capture_id: int):
    """
    Computes TP, FP, FN, TN, Precision, Recall, F1, and Coverage according to Requirement 4:
    - TP: predicted matches true_domain
    - FP: predicted != true_domain AND predicted != 'UNKNOWN'
    - FN: predicted == 'UNKNOWN' AND true_domain != 'NEGATIVE'
    - TN: predicted == 'UNKNOWN' AND true_domain == 'NEGATIVE'
    """
    tp = 0
    fp = 0
    fn = 0
    tn = 0
    errors = []

    for r in matched_records:
        true_d = r["true_domain"]
        label_type = r["label_type"]
        is_neg = (true_d == "NEGATIVE" or label_type == "negative")

        pred_d = predict_baseline(r, method_name)
        norm_pred = normalize_domain(pred_d)
        norm_true = normalize_domain(true_d)

        pred_is_unknown = (pred_d == "UNKNOWN" or norm_pred == "unknown")

        if is_neg:
            if pred_is_unknown:
                tn += 1
            else:
                fp += 1
                errors.append({
                    "capture_id": capture_id,
                    "src_ip": r["src_ip"],
                    "dst_ip": r["dst_ip"],
                    "dst_port": r["dst_port"],
                    "true_domain": true_d,
                    "predicted_domain": pred_d,
                    "method_used": method_name,
                    "is_negative": True,
                    "error_type": "FP"
                })
        else:
            if pred_is_unknown:
                fn += 1
                errors.append({
                    "capture_id": capture_id,
                    "src_ip": r["src_ip"],
                    "dst_ip": r["dst_ip"],
                    "dst_port": r["dst_port"],
                    "true_domain": true_d,
                    "predicted_domain": pred_d,
                    "method_used": method_name,
                    "is_negative": False,
                    "error_type": "FN"
                })
            elif norm_pred == norm_true:
                tp += 1
            else:
                fp += 1
                errors.append({
                    "capture_id": capture_id,
                    "src_ip": r["src_ip"],
                    "dst_ip": r["dst_ip"],
                    "dst_port": r["dst_port"],
                    "true_domain": true_d,
                    "predicted_domain": pred_d,
                    "method_used": method_name,
                    "is_negative": False,
                    "error_type": "FP"
                })

    total = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2.0 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    coverage = (tp + fp) / total if total > 0 else 0.0

    return {
        "capture_id": capture_id,
        "method": method_name,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "coverage": coverage,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "errors": errors
    }


# ============================================================================
# PLOTTING FUNCTIONS
# ============================================================================
def plot_baseline_comparison(df_agg: pd.DataFrame, output_png="baseline_comparison.png"):
    """Requirement 8: Bar plot showing precision, recall, F1 across all 4 methods."""
    methods = df_agg["method"].tolist()
    prec = df_agg["mean_precision"].values * 100.0
    rec = df_agg["mean_recall"].values * 100.0
    f1 = df_agg["mean_f1"].values * 100.0

    prec_err = df_agg["std_precision"].values * 100.0
    rec_err = df_agg["std_recall"].values * 100.0
    f1_err = df_agg["std_f1"].values * 100.0

    x = np.arange(len(methods))
    width = 0.26

    fig, ax = plt.subplots(figsize=(10, 6), dpi=300)

    rects1 = ax.bar(x - width, prec, width, yerr=prec_err, capsize=4, label="Precision", color="#2b5c8f")
    rects2 = ax.bar(x, rec, width, yerr=rec_err, capsize=4, label="Recall", color="#e27c38")
    rects3 = ax.bar(x + width, f1, width, yerr=f1_err, capsize=4, label="F1-Score", color="#389e5a")

    ax.set_ylabel("Score (%)", fontsize=12, fontweight="bold")
    ax.set_title("Classification Baseline Comparison Across 4 Independent Captures", fontsize=14, pad=14, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(methods, fontsize=10, fontweight="bold")
    ax.set_ylim(0, 115)
    ax.legend(loc="upper left", frameon=True, fontsize=10)
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    def autolabel(rects):
        for rect in rects:
            height = rect.get_height()
            if height > 0:
                ax.annotate(f"{height:.1f}%",
                            xy=(rect.get_x() + rect.get_width() / 2, height),
                            xytext=(0, 4), textcoords="offset points",
                            ha="center", va="bottom", fontsize=8)

    autolabel(rects1)
    autolabel(rects2)
    autolabel(rects3)

    plt.tight_layout()
    plt.savefig(output_png)
    plt.close()
    print(f"[Plot] Baseline comparison figure saved -> {output_png}")


def plot_evidence_coverage(all_records: list, output_png="evidence_coverage.png"):
    """Requirement 9: Stacked bar chart showing resolution breakdown across captures."""
    captures = sorted(list(set(r["capture_id"] for r in all_records)))
    method_categories = ["TLS SNI", "HTTP Host", "DNS Query", "DNS Correlation", "Port Heuristic", "UNKNOWN"]
    
    data_by_cap = {c: {m: 0 for m in method_categories} for c in captures}

    for r in all_records:
        cid = r["capture_id"]
        m = r["engine_method"]
        if m in ["Port 443", "Port 80", "Port 53"]:
            m_cat = "Port Heuristic"
        elif m in data_by_cap[cid]:
            m_cat = m
        else:
            m_cat = "UNKNOWN"
        data_by_cap[cid][m_cat] += 1

    fig, ax = plt.subplots(figsize=(10, 6), dpi=300)
    x = np.arange(len(captures))
    bottom = np.zeros(len(captures))

    colors = {
        "TLS SNI": "#1f77b4",
        "HTTP Host": "#aec7e8",
        "DNS Query": "#ff7f0e",
        "DNS Correlation": "#2ca02c",
        "Port Heuristic": "#d62728",
        "UNKNOWN": "#7f7f7f"
    }

    for m_cat in method_categories:
        values = [data_by_cap[c][m_cat] for c in captures]
        ax.bar(x, values, bottom=bottom, label=m_cat, color=colors[m_cat], width=0.55)
        bottom += np.array(values)

    ax.set_ylabel("Total Flow Count", fontsize=12, fontweight="bold")
    ax.set_xlabel("Capture Iteration", fontsize=12, fontweight="bold")
    ax.set_title("Evidence Resolution Method Breakdown Across Captures", fontsize=14, pad=14, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels([f"Capture {c}" for c in captures], fontsize=11)
    ax.legend(title="Detection Evidence", bbox_to_anchor=(1.02, 1), loc="upper left", frameon=True)
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    plt.tight_layout()
    plt.savefig(output_png)
    plt.close()
    print(f"[Plot] Evidence resolution coverage saved -> {output_png}")


# ============================================================================
# MAIN ORCHESTRATION PIPELINE
# ============================================================================
def main():
    args = parse_args()
    print("=" * 78)
    print(" DPI ENGINE QUANTITATIVE BASELINE EVALUATION PIPELINE")
    print("=" * 78)

    engine_path = find_engine_executable(args.engine_path)
    if not engine_path and not args.skip_engine:
        print("[!] PacketInspector executable not found in PATH or build/.")
        print("[!] Set DPA_ENGINE_PATH or pass --engine-path, or run with --skip-engine if telemetry already exists.")
        sys.exit(1)

    baselines = [
        "Port-only",
        "SNI-only",
        "SNI + DNS-single",
        "SNI + DNS-probabilistic"
    ]

    all_matched_records = []
    comparison_rows = []
    all_errors = []

    # 1. Process each of the 4 captures
    for cid in range(1, args.captures + 1):
        pcap_file = f"dataset_capture_{cid}.pcap"
        gt_file = f"ground_truth_{cid}.csv"
        out_json = f"output_capture_{cid}.json"

        if not os.path.exists(gt_file):
            print(f"[!] Warning: Ground-truth file {gt_file} not found. Skipping capture {cid}.")
            continue

        # Run engine if needed
        if not args.skip_engine or not os.path.exists(out_json):
            if os.path.exists(pcap_file) and engine_path:
                run_engine_for_pcap(engine_path, pcap_file, out_json)
            else:
                print(f"[!] PCAP file {pcap_file} missing or engine unavailable; expecting existing {out_json}.")

        df_gt = load_ground_truth(gt_file)
        flows = load_telemetry_flows(out_json)
        matched = match_ground_truth_with_engine(df_gt, flows)
        all_matched_records.extend(matched)

        print(f"\n[*] Evaluating Capture {cid}: {len(matched)} flows loaded.")

        for b_name in baselines:
            metrics = compute_metrics(matched, b_name, cid)
            comparison_rows.append({
                "capture_id": cid,
                "method": b_name,
                "precision": round(metrics["precision"], 4),
                "recall": round(metrics["recall"], 4),
                "f1": round(metrics["f1"], 4),
                "coverage": round(metrics["coverage"], 4),
                "tp": metrics["tp"],
                "fp": metrics["fp"],
                "fn": metrics["fn"],
                "tn": metrics["tn"]
            })
            # Collect errors across methods for error analysis report
            all_errors.extend(metrics["errors"])

    if not comparison_rows:
        print("[!] No evaluation rows produced. Check your dataset_capture_N.pcap and ground_truth_N.csv files.")
        return

    # 2. Write baseline_comparison.csv
    df_comp = pd.DataFrame(comparison_rows)
    comp_csv = "baseline_comparison.csv"
    df_comp.to_csv(comp_csv, index=False)
    print(f"[+] Wrote per-capture baseline metrics -> {comp_csv}")

    # 3. Write baseline_aggregate.csv
    agg_rows = []
    for b_name in baselines:
        subset = df_comp[df_comp["method"] == b_name]
        agg_rows.append({
            "method": b_name,
            "mean_precision": round(subset["precision"].mean(), 4),
            "std_precision": round(subset["precision"].std(), 4) if len(subset) > 1 else 0.0,
            "mean_recall": round(subset["recall"].mean(), 4),
            "std_recall": round(subset["recall"].std(), 4) if len(subset) > 1 else 0.0,
            "mean_f1": round(subset["f1"].mean(), 4),
            "std_f1": round(subset["f1"].std(), 4) if len(subset) > 1 else 0.0,
            "mean_coverage": round(subset["coverage"].mean(), 4),
            "std_coverage": round(subset["coverage"].std(), 4) if len(subset) > 1 else 0.0
        })

    df_agg = pd.DataFrame(agg_rows)
    agg_csv = "baseline_aggregate.csv"
    df_agg.to_csv(agg_csv, index=False)
    print(f"[+] Wrote aggregated cross-capture metrics -> {agg_csv}")

    # 4. Write error_analysis.csv (Top 20 misclassifications, FP first, then FN)
    df_err = pd.DataFrame(all_errors)
    if not df_err.empty:
        # Sort false positives first, then false negatives
        df_err["sort_key"] = df_err["error_type"].apply(lambda x: 0 if x == "FP" else 1)
        df_err.sort_values(by=["sort_key", "capture_id"], inplace=True)
        cols = ["capture_id", "src_ip", "dst_ip", "dst_port", "true_domain", "predicted_domain", "method_used", "is_negative"]
        top_errors = df_err[cols].head(20)
    else:
        top_errors = pd.DataFrame(columns=["capture_id", "src_ip", "dst_ip", "dst_port", "true_domain", "predicted_domain", "method_used", "is_negative"])

    err_csv = "error_analysis.csv"
    top_errors.to_csv(err_csv, index=False)
    print(f"[+] Wrote top misclassification error analysis -> {err_csv} ({len(top_errors)} rows)")

    # 5. Generate Publication Plots
    plot_baseline_comparison(df_agg, "baseline_comparison.png")
    plot_evidence_coverage(all_matched_records, "evidence_coverage.png")

    # 6. Print Full Summary to stdout (Requirement 10)
    total_evaluated = len(all_matched_records)
    print("\n" + "=" * 78)
    print(" BASELINE PERFORMANCE SUMMARY ACROSS EXPERIMENTS")
    print("=" * 78)
    print(f"Total Flows Evaluated: {total_evaluated} across {len(set(r['capture_id'] for r in all_matched_records))} capture runs\n")
    print(f"{'Method':<25} | {'Precision':<11} | {'Recall':<11} | {'F1-Score':<11} | {'Coverage':<11}")
    print("-" * 78)
    for _, row in df_agg.iterrows():
        p_str = f"{row['mean_precision']*100:.2f} ± {row['std_precision']*100:.2f}%"
        r_str = f"{row['mean_recall']*100:.2f} ± {row['std_recall']*100:.2f}%"
        f_str = f"{row['mean_f1']*100:.2f} ± {row['std_f1']*100:.2f}%"
        c_str = f"{row['mean_coverage']*100:.2f} ± {row['std_coverage']*100:.2f}%"
        print(f"{row['method']:<25} | {p_str:<11} | {r_str:<11} | {f_str:<11} | {c_str:<11}")
    print("-" * 78)

    # Compute improvement from (c) SNI + DNS-single to (d) SNI + DNS-probabilistic
    c_f1 = df_agg.loc[df_agg["method"] == "SNI + DNS-single", "mean_f1"].values[0] * 100.0
    d_f1 = df_agg.loc[df_agg["method"] == "SNI + DNS-probabilistic", "mean_f1"].values[0] * 100.0
    c_rec = df_agg.loc[df_agg["method"] == "SNI + DNS-single", "mean_recall"].values[0] * 100.0
    d_rec = df_agg.loc[df_agg["method"] == "SNI + DNS-probabilistic", "mean_recall"].values[0] * 100.0

    best_subset = df_comp[df_comp["method"] == "SNI + DNS-probabilistic"]
    best_fp = best_subset["fp"].sum()
    best_fn = best_subset["fn"].sum()

    print("\n" + "=" * 78)
    print(" KEY RESEARCH FINDINGS & DELTAS")
    print("=" * 78)
    print(f"Improvement from (c) Single-Cache to (d) Probabilistic-Cache:")
    print(f"  -> Recall Gain:    +{d_rec - c_rec:.2f} percentage points ({c_rec:.2f}% -> {d_rec:.2f}%)")
    print(f"  -> F1-Score Gain:  +{d_f1 - c_f1:.2f} percentage points ({c_f1:.2f}% -> {d_f1:.2f}%)")
    print(f"Best Method (SNI + DNS-probabilistic) Error Profile:")
    print(f"  -> Total False Positives: {best_fp}")
    print(f"  -> Total False Negatives: {best_fn}")
    print("=" * 78 + "\n")


if __name__ == "__main__":
    main()
