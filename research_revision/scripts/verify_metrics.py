#!/usr/bin/env python3
"""
Independent Mathematical and Metric Verification Script.
Recomputes all metrics from raw ground truth and engine telemetry.
Generates:
- verified_metrics.csv
- per_session_metrics.csv
- per_domain_metrics.csv
"""

import os
import sys
import json
import numpy as np
import pandas as pd

# Reconfigure output encoding for UTF-8
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

def normalize_domain(dom):
    if not isinstance(dom, str):
        return ""
    d = dom.strip().lower()
    if d.startswith("www."):
        d = d[4:]
    while d.endswith("."):
        d = d[:-1]
    return d

def is_abstention(domain):
    d = normalize_domain(domain)
    return d in {"", "unknown", "https", "http", "tls", "quic", "dns", "none", "null", "abstain"}

def load_data(capture_ids=[1, 2, 3, 4]):
    matched_records = []
    
    for cid in capture_ids:
        gt_path = f"ground_truth_{cid}.csv"
        out_path = f"output_capture_{cid}.json"
        
        if not os.path.exists(gt_path) or not os.path.exists(out_path):
            raise FileNotFoundError(f"Missing {gt_path} or {out_path}")
            
        df_gt = pd.read_csv(gt_path)
        with open(out_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        flows = data.get("flows", [])
        
        # Build 3-tuple and 2-tuple lookup
        flow_map = {}
        for fl in flows:
            key = (str(fl.get("src_ip")), str(fl.get("dst_ip")), int(fl.get("dst_port", 0)))
            flow_map.setdefault(key, []).append(fl)
            
        for _, row in df_gt.iterrows():
            src = str(row["src_ip"])
            dst = str(row["dst_ip"])
            dport = int(row["dst_port"])
            true_d = normalize_domain(str(row["true_domain"]))
            label_type = str(row["label_type"]).lower()
            
            key = (src, dst, dport)
            cand = None
            if key in flow_map and len(flow_map[key]) > 0:
                cand = flow_map[key].pop(0)
            else:
                # Relaxed dst_ip match
                for k in flow_map:
                    if k[1] == dst and k[2] == dport and len(flow_map[k]) > 0:
                        cand = flow_map[k].pop(0)
                        break
                        
            eng_dom = normalize_domain(cand.get("domain", "")) if cand else ""
            eng_method = str(cand.get("method", "UNKNOWN")) if cand else "UNKNOWN"
            
            matched_records.append({
                "capture_id": cid,
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": dport,
                "true_domain": true_d,
                "label_type": label_type,
                "engine_domain": eng_dom,
                "engine_method": eng_method
            })
            
    return pd.DataFrame(matched_records)

def evaluate_method(df, method_name):
    """
    Computes all binary and multiclass metrics for a specific classification baseline.
    """
    records = []
    
    for _, row in df.iterrows():
        dport = row["dst_port"]
        eng_dom = row["engine_domain"]
        eng_method = row["engine_method"]
        true_d = row["true_domain"]
        is_neg = (row["label_type"] == "negative" or true_d == "negative")
        
        pred_d = ""
        
        if method_name == "Port-only":
            pred_d = "https" if dport == 443 else ("http" if dport == 80 else ("dns" if dport == 53 else ""))
        elif method_name == "SNI-only":
            if eng_method in ["TLS SNI", "HTTP Host"] and not is_abstention(eng_dom):
                pred_d = eng_dom
        elif method_name == "SNI + DNS-single":
            # True single-domain DNS evaluation: if method is SNI/Host or if DNS correlation produced a single mapping
            # (In existing engine output, DNS correlation was logged as 'DNS Correlation')
            # To evaluate single-domain vs probabilistic accurately:
            if eng_method in ["TLS SNI", "HTTP Host", "DNS Query"] and not is_abstention(eng_dom):
                pred_d = eng_dom
        elif method_name == "SNI + DNS-probabilistic":
            if eng_method in ["TLS SNI", "HTTP Host", "DNS Query", "DNS Correlation"] and not is_abstention(eng_dom):
                pred_d = eng_dom
                
        # Metric determination
        # TP: predicted is non-empty and matches true_domain exactly
        # FP: predicted is non-empty and does NOT match true_domain
        # FN: predicted is empty/unknown and true_domain is NOT negative
        # TN: predicted is empty/unknown and true_domain IS negative
        is_tp = False
        is_fp = False
        is_fn = False
        is_tn = False
        
        if pred_d != "":
            if not is_neg and pred_d == true_d:
                is_tp = True
            else:
                is_fp = True
        else:
            if not is_neg:
                is_fn = True
            else:
                is_tn = True
                
        records.append({
            "capture_id": row["capture_id"],
            "true_domain": true_d,
            "pred_domain": pred_d if pred_d != "" else "UNKNOWN",
            "is_neg": is_neg,
            "tp": 1 if is_tp else 0,
            "fp": 1 if is_fp else 0,
            "fn": 1 if is_fn else 0,
            "tn": 1 if is_tn else 0
        })
        
    df_eval = pd.DataFrame(records)
    return df_eval

def compute_summary_metrics(df_eval):
    tp = df_eval["tp"].sum()
    fp = df_eval["fp"].sum()
    fn = df_eval["fn"].sum()
    tn = df_eval["tn"].sum()
    total = len(df_eval)
    
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
    spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    acc = (tp + tn) / total if total > 0 else 0.0
    cov = (tp + fp) / total if total > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    
    return {
        "TP": int(tp), "FP": int(fp), "FN": int(fn), "TN": int(tn),
        "Total": total,
        "Precision": prec,
        "Recall": rec,
        "F1": f1,
        "Specificity": spec,
        "Accuracy": acc,
        "Coverage": cov,
        "FPR": fpr,
        "FNR": fnr
    }

def main():
    print("=" * 78)
    print(" INDEPENDENT MATHEMATICAL AND METRIC AUDIT")
    print("=" * 78)
    
    df_all = load_data([1, 2, 3, 4])
    print(f"[*] Loaded {len(df_all)} flow records across 4 captures.")
    
    methods = ["Port-only", "SNI-only", "SNI + DNS-single", "SNI + DNS-probabilistic"]
    
    # 1. Overall Verified Metrics
    overall_rows = []
    for m in methods:
        df_res = evaluate_method(df_all, m)
        metrics = compute_summary_metrics(df_res)
        metrics["Method"] = m
        overall_rows.append(metrics)
        
    df_verified = pd.DataFrame(overall_rows)
    # Reorder columns
    cols = ["Method", "Total", "TP", "FP", "FN", "TN", "Precision", "Recall", "F1", "Specificity", "Accuracy", "Coverage", "FPR", "FNR"]
    df_verified = df_verified[cols]
    
    df_verified.to_csv("research_revision/results/verified_metrics.csv", index=False)
    print("[+] Saved research_revision/results/verified_metrics.csv")
    print("\nVERIFIED AGGREGATE METRICS:")
    print(df_verified.to_string(index=False))
    
    # 2. Per-Session Metrics
    session_rows = []
    for cid in [1, 2, 3, 4]:
        df_c = df_all[df_all["capture_id"] == cid]
        for m in methods:
            df_res = evaluate_method(df_c, m)
            metrics = compute_summary_metrics(df_res)
            metrics["Capture_ID"] = cid
            metrics["Method"] = m
            session_rows.append(metrics)
            
    df_session = pd.DataFrame(session_rows)
    df_session = df_session[["Capture_ID", "Method", "TP", "FP", "FN", "TN", "Precision", "Recall", "F1", "Coverage"]]
    df_session.to_csv("research_revision/results/per_session_metrics.csv", index=False)
    print("[+] Saved research_revision/results/per_session_metrics.csv")
    
    # 3. Per-Domain Metrics for SNI + DNS-probabilistic
    df_prob = evaluate_method(df_all, "SNI + DNS-probabilistic")
    domain_rows = []
    domains = sorted(df_prob["true_domain"].unique())
    for d in domains:
        sub = df_prob[df_prob["true_domain"] == d]
        tp_d = sub["tp"].sum()
        fp_d = sub["fp"].sum()
        fn_d = sub["fn"].sum()
        tn_d = sub["tn"].sum()
        total_d = len(sub)
        rec_d = tp_d / (tp_d + fn_d) if (tp_d + fn_d) > 0 else (1.0 if d == "negative" and tn_d == total_d else 0.0)
        prec_d = tp_d / (tp_d + fp_d) if (tp_d + fp_d) > 0 else (1.0 if d == "negative" else 0.0)
        f1_d = (2 * prec_d * rec_d) / (prec_d + rec_d) if (prec_d + rec_d) > 0 else 0.0
        domain_rows.append({
            "Domain": d,
            "Total_Flows": total_d,
            "TP": tp_d,
            "FP": fp_d,
            "FN": fn_d,
            "TN": tn_d,
            "Precision": prec_d,
            "Recall": rec_d,
            "F1": f1_d
        })
        
    df_domains = pd.DataFrame(domain_rows)
    df_domains.to_csv("research_revision/results/per_domain_metrics.csv", index=False)
    print("[+] Saved research_revision/results/per_domain_metrics.csv")
    print("=" * 78)

if __name__ == "__main__":
    main()

