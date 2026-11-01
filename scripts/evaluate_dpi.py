#!/usr/bin/env python3
"""
Evaluation Script for DeepPacket-Analyzer
Evaluates classification accuracy of DPI engine telemetry (output.json)
against ground-truth CSV mappings.

Calculates:
- Precision, Recall, F1-Score (Macro and Weighted)
- Confusion Matrix (saved as confusion_matrix.png)
- Evidence Coverage Report (TLS SNI vs DNS Correlation vs HTTP Host)
"""

import os
import sys
import json
import argparse
import pandas as pd
import numpy as np

def parse_args():
    parser = argparse.ArgumentParser(description="Evaluate DPI Engine Classification Performance")
    parser.add_argument("--telemetry", "-t", default="output.json", help="Path to telemetry JSON output from DPI engine")
    parser.add_argument("--ground-truth", "-g", default="ground_truth.csv", help="Path to ground-truth CSV file")
    parser.add_argument("--output-matrix", "-m", default="confusion_matrix.png", help="Path to save confusion matrix image")
    parser.add_argument("--report", "-r", default=None, help="Optional path to save text report")
    return parser.parse_args()

def normalize_domain(domain):
    if not isinstance(domain, str):
        return ""
    d = domain.strip().lower()
    if d.startswith("www."):
        d = d[4:]
    if d.endswith("."):
        d = d[:-1]
    return d

def is_abstention(domain):
    """Domains that represent abstention or fallback protocol label rather than actual identification"""
    d = normalize_domain(domain)
    return d in {"unknown", "https", "http", "tls", "quic", "dns", "", "none", "null"}

def load_telemetry(telemetry_path):
    if not os.path.exists(telemetry_path):
        raise FileNotFoundError(f"Telemetry file not found: {telemetry_path}")
    
    with open(telemetry_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    flows = data.get("flows", [])
    if not flows:
        print(f"[Warning] No flow records found in {telemetry_path}")
    
    df_flows = pd.DataFrame(flows)
    return df_flows

def load_ground_truth(gt_path):
    if not os.path.exists(gt_path):
        raise FileNotFoundError(f"Ground-truth file not found: {gt_path}")
    
    df_gt = pd.read_csv(gt_path)
    # Ensure standard column names
    col_map = {c: c.strip().lower() for c in df_gt.columns}
    df_gt.rename(columns=col_map, inplace=True)
    
    required = ["true_domain"]
    for r in required:
        if r not in df_gt.columns:
            raise ValueError(f"Ground-truth CSV must contain column '{r}'. Available: {list(df_gt.columns)}")
    
    # Normalize true_domain
    df_gt["true_domain_clean"] = df_gt["true_domain"].apply(normalize_domain)
    return df_gt

def match_flows(df_gt, df_flows):
    """
    Matches telemetry flows with ground truth based on endpoints
    (src_ip, dst_ip, dst_port) or IP endpoint matching.
    """
    matched_records = []
    
    if df_flows.empty:
        for _, gt in df_gt.iterrows():
            matched_records.append({
                "true_domain": gt["true_domain_clean"],
                "predicted_domain": "UNKNOWN",
                "predicted_clean": "",
                "method": "None",
                "matched": False
            })
        return pd.DataFrame(matched_records)

    # Clean flow predictions
    df_flows["pred_clean"] = df_flows["domain"].apply(normalize_domain)
    
    # Matching strategy:
    # 1. Exact 3-tuple (src_ip, dst_ip, dst_port)
    # 2. Relaxed IP pair (src_ip, dst_ip) or destination IP + port
    has_tuple = all(k in df_gt.columns and k in df_flows.columns for k in ["src_ip", "dst_ip", "dst_port"])
    
    flows_copy = df_flows.copy()
    flows_copy["used"] = False
    
    for _, gt in df_gt.iterrows():
        true_d = gt["true_domain_clean"]
        pred_match = None
        method = "None"
        
        if has_tuple:
            cand = flows_copy[
                (flows_copy["src_ip"] == str(gt["src_ip"])) &
                (flows_copy["dst_ip"] == str(gt["dst_ip"])) &
                (flows_copy["dst_port"].astype(str) == str(gt["dst_port"])) &
                (~flows_copy["used"])
            ]
            if not cand.empty:
                idx = cand.index[0]
                flows_copy.at[idx, "used"] = True
                pred_match = flows_copy.at[idx, "pred_clean"]
                method = flows_copy.at[idx, "method"]
        
        # Fallback to destination IP matching if exact 3-tuple didn't hit
        if pred_match is None and "dst_ip" in gt and "dst_ip" in flows_copy.columns:
            cand = flows_copy[
                (flows_copy["dst_ip"] == str(gt["dst_ip"])) &
                (~flows_copy["used"])
            ]
            if not cand.empty:
                idx = cand.index[0]
                flows_copy.at[idx, "used"] = True
                pred_match = flows_copy.at[idx, "pred_clean"]
                method = flows_copy.at[idx, "method"]

        # Fallback by domain overlap if IP not specified
        if pred_match is None and true_d:
            cand = flows_copy[
                (flows_copy["pred_clean"] == true_d) &
                (~flows_copy["used"])
            ]
            if not cand.empty:
                idx = cand.index[0]
                flows_copy.at[idx, "used"] = True
                pred_match = flows_copy.at[idx, "pred_clean"]
                method = flows_copy.at[idx, "method"]

        if pred_match is None:
            pred_match = ""
            method = "Abstain"

        matched_records.append({
            "true_domain": true_d,
            "predicted_domain": pred_match if pred_match else "UNKNOWN",
            "predicted_clean": pred_match,
            "method": method if method else "UNKNOWN",
            "matched": bool(pred_match)
        })
    
    return pd.DataFrame(matched_records)

def evaluate_metrics(df_eval):
    y_true = df_eval["true_domain"].tolist()
    y_pred = []
    
    for _, row in df_eval.iterrows():
        p = row["predicted_clean"]
        if is_abstention(p):
            y_pred.append("<ABSTAIN>")
        else:
            y_pred.append(p)
            
    classes = sorted(list(set(y_true)))
    
    # Calculate Precision, Recall, F1
    total_samples = len(y_true)
    correct = sum(1 for yt, yp in zip(y_true, y_pred) if yt == yp)
    abstentions = sum(1 for yp in y_pred if yp == "<ABSTAIN>")
    
    # Per-class metrics
    class_metrics = {}
    for c in classes:
        tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == c and yp == c)
        fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt != c and yp == c)
        fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == c and yp != c)
        
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
        support = sum(1 for yt in y_true if yt == c)
        
        class_metrics[c] = {
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "support": support
        }
    
    # Macro and Weighted Averages
    macro_prec = np.mean([m["precision"] for m in class_metrics.values()])
    macro_rec = np.mean([m["recall"] for m in class_metrics.values()])
    macro_f1 = np.mean([m["f1"] for m in class_metrics.values()])
    
    weights = [m["support"] for m in class_metrics.values()]
    weighted_prec = np.average([m["precision"] for m in class_metrics.values()], weights=weights) if sum(weights) > 0 else 0.0
    weighted_rec = np.average([m["recall"] for m in class_metrics.values()], weights=weights) if sum(weights) > 0 else 0.0
    weighted_f1 = np.average([m["f1"] for m in class_metrics.values()], weights=weights) if sum(weights) > 0 else 0.0
    
    accuracy = correct / total_samples if total_samples > 0 else 0.0
    abstention_rate = abstentions / total_samples if total_samples > 0 else 0.0
    
    return {
        "total_samples": total_samples,
        "correct": correct,
        "abstentions": abstentions,
        "accuracy": accuracy,
        "abstention_rate": abstention_rate,
        "macro_precision": macro_prec,
        "macro_recall": macro_rec,
        "macro_f1": macro_f1,
        "weighted_precision": weighted_prec,
        "weighted_recall": weighted_rec,
        "weighted_f1": weighted_f1,
        "class_metrics": class_metrics,
        "y_true": y_true,
        "y_pred": y_pred,
        "classes": classes
    }

def compute_evidence_coverage(df_eval):
    """
    Evidence Coverage Report:
    Counts how many true labels were correctly identified by:
    - 'TLS SNI'
    - 'DNS Correlation'
    - 'HTTP Host'
    - Others
    """
    correct_rows = df_eval[df_eval["true_domain"] == df_eval["predicted_clean"]]
    coverage_counts = correct_rows["method"].value_counts().to_dict()
    
    total_correct = len(correct_rows)
    coverage_pcts = {}
    for method, count in coverage_counts.items():
        pct = (count / total_correct * 100.0) if total_correct > 0 else 0.0
        coverage_pcts[method] = {"count": count, "percentage": pct}
        
    return coverage_pcts, total_correct

def plot_confusion_matrix(y_true, y_pred, classes, output_path="confusion_matrix.png"):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from sklearn.metrics import confusion_matrix
    except ImportError:
        print("[Notice] matplotlib or scikit-learn not installed. Skipping graphical confusion matrix plot.")
        return

    # Filter or include top 15 classes for visual clarity if too many
    all_labels = classes + (["<ABSTAIN>"] if "<ABSTAIN>" in y_pred else [])
    cm = confusion_matrix(y_true, y_pred, labels=all_labels)
    
    plt.figure(figsize=(10, 8), dpi=300)
    plt.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    plt.title("DPI Engine Flow Classification Confusion Matrix", fontsize=14, pad=12, fontweight="bold")
    plt.colorbar()
    
    tick_marks = np.arange(len(all_labels))
    plt.xticks(tick_marks, all_labels, rotation=45, ha="right", fontsize=9)
    plt.yticks(tick_marks, all_labels, fontsize=9)
    
    thresh = cm.max() / 2.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            val = cm[i, j]
            if val > 0:
                plt.text(j, i, format(val, "d"),
                         ha="center", va="center",
                         color="white" if val > thresh else "black",
                         fontsize=8)
                
    plt.ylabel("True Domain Label", fontsize=11, fontweight="bold")
    plt.xlabel("DPI Engine Predicted Domain", fontsize=11, fontweight="bold")
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    print(f"[Plot] Confusion matrix saved successfully to {output_path}")

def main():
    args = parse_args()
    print("=" * 70)
    print(" DEEPPACKET-ANALYZER RESEARCH EVALUATION SUITE")
    print("=" * 70)
    print(f"[*] Telemetry input:     {args.telemetry}")
    print(f"[*] Ground-truth input:  {args.ground_truth}")
    print(f"[*] Confusion matrix:    {args.output_matrix}")
    
    df_flows = load_telemetry(args.telemetry)
    df_gt = load_ground_truth(args.ground_truth)
    
    print(f"[*] Loaded {len(df_gt)} ground-truth records and {len(df_flows)} engine flows.")
    
    df_eval = match_flows(df_gt, df_flows)
    results = evaluate_metrics(df_eval)
    coverage, total_correct = compute_evidence_coverage(df_eval)
    
    # Formulate output report
    report_lines = []
    report_lines.append("\n" + "=" * 70)
    report_lines.append(" TABLE IV: DPI CLASSIFICATION PERFORMANCE METRICS")
    report_lines.append("=" * 70)
    report_lines.append(f"Total Evaluated Flows:      {results['total_samples']}")
    report_lines.append(f"Correctly Classified:       {results['correct']}")
    report_lines.append(f"Abstentions (<ABSTAIN>):    {results['abstentions']} ({results['abstention_rate']*100:.2f}%)")
    report_lines.append(f"Classification Accuracy:    {results['accuracy']*100:.2f}%")
    report_lines.append("-" * 70)
    report_lines.append(f"Macro Precision:            {results['macro_precision']*100:.2f}%")
    report_lines.append(f"Macro Recall:               {results['macro_recall']*100:.2f}%")
    report_lines.append(f"Macro F1-Score:             {results['macro_f1']*100:.2f}%")
    report_lines.append("-" * 70)
    report_lines.append(f"Weighted Precision:         {results['weighted_precision']*100:.2f}%")
    report_lines.append(f"Weighted Recall:            {results['weighted_recall']*100:.2f}%")
    report_lines.append(f"Weighted F1-Score:          {results['weighted_f1']*100:.2f}%")
    report_lines.append("=" * 70)
    
    report_lines.append("\n" + "=" * 70)
    report_lines.append(" EVIDENCE COVERAGE REPORT (DISAMBIGUATION BREAKDOWN)")
    report_lines.append("=" * 70)
    report_lines.append(f"{'Detection Method':<25} | {'Correct Flows':<15} | {'Coverage Share (%)':<15}")
    report_lines.append("-" * 70)
    for method, stat in sorted(coverage.items(), key=lambda x: x[1]["count"], reverse=True):
        report_lines.append(f"{method:<25} | {stat['count']:<15} | {stat['percentage']:>6.2f}%")
    report_lines.append("-" * 70)
    report_lines.append(f"{'Total Resolved':<25} | {total_correct:<15} | 100.00%")
    report_lines.append("=" * 70)
    
    report_lines.append("\n" + "=" * 70)
    report_lines.append(" PER-DOMAIN BREAKDOWN (TOP CLASSES)")
    report_lines.append("=" * 70)
    report_lines.append(f"{'Domain':<30} | {'Prec (%)':<10} | {'Rec (%)':<10} | {'F1 (%)':<10} | {'Support':<8}")
    report_lines.append("-" * 70)
    for dom, m in sorted(results["class_metrics"].items(), key=lambda x: x[1]["support"], reverse=True):
        report_lines.append(f"{dom:<30} | {m['precision']*100:>8.2f}% | {m['recall']*100:>8.2f}% | {m['f1']*100:>8.2f}% | {m['support']:<8}")
    report_lines.append("=" * 70 + "\n")
    
    full_report = "\n".join(report_lines)
    print(full_report)
    
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(full_report)
        print(f"[*] Report saved to {args.report}")
        
    plot_confusion_matrix(results["y_true"], results["y_pred"], results["classes"], args.output_matrix)

if __name__ == "__main__":
    main()

