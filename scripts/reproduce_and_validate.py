#!/usr/bin/env python3
"""
reproduce_and_validate.py - Complete Independent Evaluation & Statistical Verification
Part of Final Independent Research Validation
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from scipy import stats
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

# Ensure UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

OUTPUT_DIR = "research_revision/final_validation"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 1. Load Ground Truth and Complete Predictions across all 4 captures
all_gt = []
all_matched = []

for c in range(1, 5):
    gt_file = f"ground_truth_{c}.csv"
    eval_json = f"eval_capture_{c}.json"
    
    df_gt = pd.read_csv(gt_file)
    df_gt.columns = [col.strip().lower() for col in df_gt.columns]
    all_gt.append(df_gt)
    
    with open(eval_json, "r", encoding="utf-8") as f:
        flows = json.load(f)["flows"]
        
    # Flow mapping by (src_ip, dst_ip, dst_port)
    flow_map = {}
    for fl in flows:
        key = (str(fl.get("src_ip", "")), str(fl.get("dst_ip", "")), int(fl.get("dst_port", 0)))
        flow_map.setdefault(key, []).append(fl)
        
    for _, row in df_gt.iterrows():
        src = str(row["src_ip"])
        dst = str(row["dst_ip"])
        dport = int(row["dst_port"])
        true_dom = str(row["true_domain"])
        label_type = str(row["label_type"]).lower()
        cap_id = int(row["capture_id"])
        flow_id = int(row["flow_id"])
        
        key = (src, dst, dport)
        engine_flow = None
        if key in flow_map and len(flow_map[key]) > 0:
            engine_flow = flow_map[key].pop(0)
        else:
            # Relaxed lookup by dst_ip and dst_port
            for k in flow_map:
                if k[1] == dst and k[2] == dport and len(flow_map[k]) > 0:
                    engine_flow = flow_map[k].pop(0)
                    break
                    
        domain_val = engine_flow.get("domain", "UNKNOWN") if engine_flow else "UNKNOWN"
        method_val = engine_flow.get("method", "UNKNOWN") if engine_flow else "UNKNOWN"
        confidence_val = engine_flow.get("confidence", "low") if engine_flow else "low"
        policy_val = engine_flow.get("policy", "FORWARD") if engine_flow else "FORWARD"
        
        all_matched.append({
            "capture_id": cap_id,
            "flow_id": flow_id,
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": dport,
            "true_domain": true_dom,
            "label_type": label_type,
            "engine_domain": domain_val,
            "engine_method": method_val,
            "engine_confidence": confidence_val,
            "engine_policy": policy_val
        })

df_all_gt = pd.concat(all_gt, ignore_index=True)
df_all_matched = pd.DataFrame(all_matched)

# Save complete ground truth and complete predictions
df_all_gt.to_csv(os.path.join(OUTPUT_DIR, "complete_ground_truth.csv"), index=False)
df_all_matched.to_csv(os.path.join(OUTPUT_DIR, "complete_predictions.csv"), index=False)
print(f"[+] Saved {len(df_all_gt)} ground-truth rows and {len(df_all_matched)} complete predictions.")

# ============================================================================
# BASELINE EVALUATION LOGIC
# ============================================================================
def predict_baseline(row, method_name):
    dport = row["dst_port"]
    eng_dom = row["engine_domain"]
    eng_method = row["engine_method"]
    is_unknown = (not eng_dom or eng_dom.upper() == "UNKNOWN")
    
    if method_name == "Port-only":
        if dport == 443:
            return "HTTPS"
        elif dport == 80:
            return "HTTP"
        elif dport == 53:
            return "DNS"
        return "UNKNOWN"
    elif method_name == "SNI-only":
        if eng_method in ["TLS SNI", "HTTP Host"] and not is_unknown:
            return eng_dom
        return "UNKNOWN"
    elif method_name == "SNI + DNS-single":
        if eng_method in ["TLS SNI", "HTTP Host", "DNS Query"] and not is_unknown:
            return eng_dom
        return "UNKNOWN"
    elif method_name == "SNI + DNS-probabilistic":
        if eng_method in ["TLS SNI", "HTTP Host", "DNS Query", "DNS Correlation"] and not is_unknown:
            return eng_dom
        return "UNKNOWN"
    return "UNKNOWN"

methods = ["Port-only", "SNI-only", "SNI + DNS-single", "SNI + DNS-probabilistic"]
metrics_records = []

for m in methods:
    for cap in range(1, 5):
        sub = df_all_matched[df_all_matched["capture_id"] == cap]
        tp = fp = fn = tn = 0
        for _, row in sub.iterrows():
            pred = predict_baseline(row, m)
            true_d = row["true_domain"]
            is_neg = (row["label_type"] == "negative")
            
            if is_neg:
                if pred == "UNKNOWN":
                    tn += 1
                else:
                    fp += 1
            else:
                if pred == true_d:
                    tp += 1
                elif pred == "UNKNOWN":
                    fn += 1
                else:
                    fp += 1
                    
        total = len(sub)
        p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * p * r) / (p + r) if (p + r) > 0 else 0.0
        cov = (tp + fp) / total if total > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        
        metrics_records.append({
            "capture_id": cap,
            "method": m,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": p,
            "recall": r,
            "f1": f1,
            "coverage": cov,
            "fpr": fpr
        })

df_metrics = pd.DataFrame(metrics_records)
df_metrics.to_csv(os.path.join(OUTPUT_DIR, "per_capture_metrics.csv"), index=False)

# Aggregate across 4 captures
agg = df_metrics.groupby("method").agg(
    tp=("tp", "sum"),
    fp=("fp", "sum"),
    fn=("fn", "sum"),
    tn=("tn", "sum"),
    mean_precision=("precision", "mean"),
    std_precision=("precision", "std"),
    mean_recall=("recall", "mean"),
    std_recall=("recall", "std"),
    mean_f1=("f1", "mean"),
    std_f1=("f1", "std"),
    mean_coverage=("coverage", "mean"),
    std_coverage=("coverage", "std"),
    mean_fpr=("fpr", "mean"),
    std_fpr=("fpr", "std")
).reset_index()

# Compute overall precision, recall, f1 from summed TP/FP/FN/TN
agg["overall_precision"] = agg["tp"] / (agg["tp"] + agg["fp"])
agg["overall_recall"] = agg["tp"] / (agg["tp"] + agg["fn"])
agg["overall_f1"] = 2 * agg["overall_precision"] * agg["overall_recall"] / (agg["overall_precision"] + agg["overall_recall"])
agg["overall_precision"] = agg["overall_precision"].fillna(0.0)
agg["overall_recall"] = agg["overall_recall"].fillna(0.0)
agg["overall_f1"] = agg["overall_f1"].fillna(0.0)

agg.to_csv(os.path.join(OUTPUT_DIR, "corrected_metrics.csv"), index=False)
print("\n[+] Corrected Aggregate Metrics:")
print(agg[["method", "tp", "fp", "fn", "tn", "overall_precision", "overall_recall", "overall_f1", "mean_coverage"]])

# Comparison against previously reported metrics
comparison_table = pd.DataFrame([
    {
        "Method": "Port-only",
        "Prev_Precision": "0.0%", "Corrected_Precision": f"{agg.loc[agg['method']=='Port-only', 'overall_precision'].values[0]*100:.1f}%",
        "Prev_Recall": "0.0%", "Corrected_Recall": f"{agg.loc[agg['method']=='Port-only', 'overall_recall'].values[0]*100:.1f}%",
        "Prev_F1": "0.0%", "Corrected_F1": f"{agg.loc[agg['method']=='Port-only', 'overall_f1'].values[0]*100:.1f}%",
        "Prev_TP": 0, "Corrected_TP": int(agg.loc[agg['method']=='Port-only', 'tp'].values[0]),
        "Prev_FN": 0, "Corrected_FN": int(agg.loc[agg['method']=='Port-only', 'fn'].values[0])
    },
    {
        "Method": "SNI-only",
        "Prev_Precision": "100.0%", "Corrected_Precision": f"{agg.loc[agg['method']=='SNI-only', 'overall_precision'].values[0]*100:.1f}%",
        "Prev_Recall": "53.2%", "Corrected_Recall": f"{agg.loc[agg['method']=='SNI-only', 'overall_recall'].values[0]*100:.1f}%",
        "Prev_F1": "69.5%", "Corrected_F1": f"{agg.loc[agg['method']=='SNI-only', 'overall_f1'].values[0]*100:.1f}%",
        "Prev_TP": 532, "Corrected_TP": int(agg.loc[agg['method']=='SNI-only', 'tp'].values[0]),
        "Prev_FN": 468, "Corrected_FN": int(agg.loc[agg['method']=='SNI-only', 'fn'].values[0])
    },
    {
        "Method": "SNI + DNS-single",
        "Prev_Precision": "100.0%", "Corrected_Precision": f"{agg.loc[agg['method']=='SNI + DNS-single', 'overall_precision'].values[0]*100:.1f}%",
        "Prev_Recall": "53.2%", "Corrected_Recall": f"{agg.loc[agg['method']=='SNI + DNS-single', 'overall_recall'].values[0]*100:.1f}%",
        "Prev_F1": "69.5%", "Corrected_F1": f"{agg.loc[agg['method']=='SNI + DNS-single', 'overall_f1'].values[0]*100:.1f}%",
        "Prev_TP": 532, "Corrected_TP": int(agg.loc[agg['method']=='SNI + DNS-single', 'tp'].values[0]),
        "Prev_FN": 468, "Corrected_FN": int(agg.loc[agg['method']=='SNI + DNS-single', 'fn'].values[0])
    },
    {
        "Method": "SNI + DNS-probabilistic",
        "Prev_Precision": "100.0%", "Corrected_Precision": f"{agg.loc[agg['method']=='SNI + DNS-probabilistic', 'overall_precision'].values[0]*100:.1f}%",
        "Prev_Recall": "80.0%", "Corrected_Recall": f"{agg.loc[agg['method']=='SNI + DNS-probabilistic', 'overall_recall'].values[0]*100:.1f}%",
        "Prev_F1": "88.9%", "Corrected_F1": f"{agg.loc[agg['method']=='SNI + DNS-probabilistic', 'overall_f1'].values[0]*100:.1f}%",
        "Prev_TP": 800, "Corrected_TP": int(agg.loc[agg['method']=='SNI + DNS-probabilistic', 'tp'].values[0]),
        "Prev_FN": 200, "Corrected_FN": int(agg.loc[agg['method']=='SNI + DNS-probabilistic', 'fn'].values[0])
    }
])
comparison_table.to_csv(os.path.join(OUTPUT_DIR, "metric_comparison_vs_previous.csv"), index=False)
print("\n[+] Metric Comparison vs Previous Truncated Telemetry:")
print(comparison_table.to_string(index=False))

# ============================================================================
# CONFUSION MATRIX GENERATION
# ============================================================================
# Generate predictions for SNI + DNS-probabilistic
df_all_matched["pred_prob"] = df_all_matched.apply(lambda r: predict_baseline(r, "SNI + DNS-probabilistic"), axis=1)

# Category-level mapping
cat_map = {
    "google.com": "Search", "bing.com": "Search", "duckduckgo.com": "Search", "yahoo.com": "Search", "baidu.com": "Search",
    "yandex.com": "Search", "ecosia.org": "Search", "qwant.com": "Search", "brave.com": "Search", "startpage.com": "Search",
    "youtube.com": "Streaming", "netflix.com": "Streaming", "twitch.tv": "Streaming", "spotify.com": "Streaming", "soundcloud.com": "Streaming",
    "vimeo.com": "Streaming", "dailymotion.com": "Streaming", "hulu.com": "Streaming", "disneyplus.com": "Streaming", "primevideo.com": "Streaming",
    "github.com": "Developer", "gitlab.com": "Developer", "stackoverflow.com": "Developer", "bitbucket.org": "Developer", "npmjs.com": "Developer",
    "pypi.org": "Developer", "docker.com": "Developer", "huggingface.co": "Developer", "kaggle.com": "Developer", "leetcode.com": "Developer",
    "twitter.com": "Social", "facebook.com": "Social", "instagram.com": "Social", "linkedin.com": "Social", "reddit.com": "Social",
    "discord.com": "Social", "telegram.org": "Social", "whatsapp.com": "Social", "snapchat.com": "Social", "pinterest.com": "Social",
    "amazon.com": "E-Commerce", "ebay.com": "E-Commerce", "walmart.com": "E-Commerce", "aliexpress.com": "E-Commerce", "target.com": "E-Commerce",
    "etsy.com": "E-Commerce", "shopify.com": "E-Commerce", "paypal.com": "E-Commerce", "alibaba.com": "E-Commerce", "wix.com": "E-Commerce",
    "NEGATIVE": "Negative", "UNKNOWN": "Unclassified"
}

def get_cat(dom):
    if dom == "NEGATIVE": return "Negative"
    if dom == "UNKNOWN": return "Unclassified"
    return cat_map.get(dom, "Other")

df_all_matched["true_category"] = df_all_matched["true_domain"].apply(get_cat)
df_all_matched["pred_category"] = df_all_matched["pred_prob"].apply(get_cat)

categories = ["Search", "Streaming", "Developer", "Social", "E-Commerce", "Negative"]
pred_categories = categories + ["Unclassified"]

cm_cat = pd.crosstab(
    df_all_matched["true_category"],
    df_all_matched["pred_category"],
    rownames=["True Category"],
    colnames=["Predicted Category"],
    dropna=False
).reindex(index=categories, columns=pred_categories, fill_value=0)

plt.figure(figsize=(9, 7))
sns.heatmap(cm_cat, annot=True, fmt="d", cmap="Blues", cbar=True, linewidths=0.5)
plt.title("Category-Level Complete Confusion Matrix (1,400 Flows)\nUnevicted Ground Truth vs. DeepPacket Analyzer", fontsize=12, pad=15)
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "confusion_matrix_complete_category.png"), dpi=300)
plt.savefig(os.path.join(OUTPUT_DIR, "confusion_matrix_complete_category.pdf"))
plt.close()

# ============================================================================
# STATISTICAL REPRODUCTION & INDEPENDENCE VALIDATION
# ============================================================================
# Check the 50 domain paired observations between SNI-only and SNI+DNS-probabilistic
domain_perf = []
domains = [d for d in df_all_matched["true_domain"].unique() if d != "NEGATIVE"]

for d in domains:
    sub_d = df_all_matched[df_all_matched["true_domain"] == d]
    n_flows = len(sub_d) # 20 flows per domain (5 sessions * 4 captures)
    
    sni_tp = sum(sub_d.apply(lambda r: predict_baseline(r, "SNI-only") == d, axis=1))
    prob_tp = sum(sub_d.apply(lambda r: predict_baseline(r, "SNI + DNS-probabilistic") == d, axis=1))
    
    domain_perf.append({
        "domain": d,
        "category": cat_map.get(d, "Unknown"),
        "n_flows": n_flows,
        "sni_tp": sni_tp,
        "sni_recall": sni_tp / n_flows,
        "prob_tp": prob_tp,
        "prob_recall": prob_tp / n_flows,
        "delta_recall": (prob_tp - sni_tp) / n_flows
    })

df_domains = pd.DataFrame(domain_perf)
df_domains.to_csv(os.path.join(OUTPUT_DIR, "domain_paired_observations.csv"), index=False)

diffs = df_domains["delta_recall"].values
t_stat, p_val = stats.ttest_rel(df_domains["prob_recall"], df_domains["sni_recall"])
mean_diff = np.mean(diffs)
std_diff = np.std(diffs, ddof=1)
cohen_d = mean_diff / std_diff if std_diff > 0 else np.nan

wilc_stat, wilc_p = stats.wilcoxon(df_domains["prob_recall"], df_domains["sni_recall"])

print(f"\n[+] Domain-Level Paired Tests (N=50 domains):")
print(f"    Mean recall delta: {mean_diff*100:.2f}% (std: {std_diff*100:.2f}%)")
print(f"    Paired t-test: t(49) = {t_stat:.4f}, p = {p_val:.4e}")
print(f"    Cohen's d = {cohen_d:.4f}")
print(f"    Wilcoxon signed-rank: W = {wilc_stat}, p = {wilc_p:.4e}")

# Check confidence intervals for domain recall
ci_sni = stats.t.interval(0.95, df=len(df_domains)-1, loc=np.mean(df_domains["sni_recall"]), scale=stats.sem(df_domains["sni_recall"]))
ci_prob = stats.t.interval(0.95, df=len(df_domains)-1, loc=np.mean(df_domains["prob_recall"]), scale=stats.sem(df_domains["prob_recall"]))
ci_delta = stats.t.interval(0.95, df=len(df_domains)-1, loc=mean_diff, scale=stats.sem(diffs))

# Wilson score CI for False Positive Rate
total_negatives = agg.loc[agg["method"]=="SNI + DNS-probabilistic", "tn"].values[0] + agg.loc[agg["method"]=="SNI + DNS-probabilistic", "fp"].values[0]
total_fp = agg.loc[agg["method"]=="SNI + DNS-probabilistic", "fp"].values[0]

z = 1.95996
p_hat = total_fp / total_negatives
wilson_denom = 1 + z**2 / total_negatives
wilson_center = (p_hat + z**2 / (2 * total_negatives)) / wilson_denom
wilson_half = (z * np.sqrt((p_hat * (1 - p_hat) + z**2 / (4 * total_negatives)) / total_negatives)) / wilson_denom
ci_lower = max(0.0, wilson_center - wilson_half)
ci_upper = min(1.0, wilson_center + wilson_half)

print(f"\n[+] Zero False Positive Audit:")
print(f"    Total Negative Flows: {total_negatives}")
print(f"    Total False Positives: {total_fp}")
print(f"    False Positive Rate: {p_hat*100:.4f}%")
print(f"    95% Wilson Score CI for FPR: [{ci_lower*100:.4f}%, {ci_upper*100:.4f}%]")

# Save statistical summary to CSV
stat_summary = pd.DataFrame([
    {"metric": "Paired t-statistic", "value": f"{t_stat:.4f}"},
    {"metric": "Paired t p-value", "value": f"{p_val:.4e}"},
    {"metric": "Cohen's d", "value": f"{cohen_d:.4f}"},
    {"metric": "Wilcoxon W-statistic", "value": f"{wilc_stat}"},
    {"metric": "Wilcoxon p-value", "value": f"{wilc_p:.4e}"},
    {"metric": "Mean Recall SNI-only", "value": f"{np.mean(df_domains['sni_recall'])*100:.2f}% (95% CI: [{ci_sni[0]*100:.2f}%, {ci_sni[1]*100:.2f}%])"},
    {"metric": "Mean Recall SNI+DNS-prob", "value": f"{np.mean(df_domains['prob_recall'])*100:.2f}% (95% CI: [{ci_prob[0]*100:.2f}%, {ci_prob[1]*100:.2f}%])"},
    {"metric": "Mean Lift (Recall Delta)", "value": f"{mean_diff*100:.2f}% (95% CI: [{ci_delta[0]*100:.2f}%, {ci_delta[1]*100:.2f}%])"},
    {"metric": "False Positive Rate (FPR)", "value": f"{p_hat*100:.4f}% (95% Wilson CI: [{ci_lower*100:.4f}%, {ci_upper*100:.4f}%])"}
])
stat_summary.to_csv(os.path.join(OUTPUT_DIR, "statistical_summary.csv"), index=False)
print(f"\n[✓] All reproduction and validation outputs successfully exported to {OUTPUT_DIR}.")

