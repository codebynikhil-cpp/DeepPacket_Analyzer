#!/usr/bin/env python3
"""
Publication-Quality Confusion Matrix Generator for DPI Research.
Aggregates telemetry flows across captures and renders:
1. Category-level confusion matrix with normalized recall & flow counts (confusion_matrix_category.png + .pdf)
2. Upgraded high-contrast domain-level / method confusion matrix (confusion_matrix.png)
"""

import os
import sys
import json
import glob
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

# Ensure UTF-8 output
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

DATASET_CATEGORIES = {
    "Search": [
        "google.com", "bing.com", "duckduckgo.com", "yahoo.com", "baidu.com",
        "yandex.com", "ecosia.org", "qwant.com", "brave.com", "startpage.com"
    ],
    "Streaming": [
        "youtube.com", "netflix.com", "twitch.tv", "spotify.com", "soundcloud.com",
        "vimeo.com", "dailymotion.com", "hulu.com", "disneyplus.com", "primevideo.com"
    ],
    "Developer": [
        "github.com", "gitlab.com", "stackoverflow.com", "bitbucket.org", "npmjs.com",
        "pypi.org", "docker.com", "huggingface.co", "kaggle.com", "leetcode.com"
    ],
    "Social": [
        "twitter.com", "facebook.com", "instagram.com", "linkedin.com", "reddit.com",
        "discord.com", "telegram.org", "whatsapp.com", "snapchat.com", "pinterest.com"
    ],
    "E-Commerce": [
        "amazon.com", "ebay.com", "aliexpress.com", "paypal.com", "etsy.com",
        "walmart.com", "target.com", "shopify.com", "alibaba.com", "wix.com"
    ]
}

DOMAIN_TO_CATEGORY = {}
for cat, domains in DATASET_CATEGORIES.items():
    for d in domains:
        DOMAIN_TO_CATEGORY[d.lower()] = cat

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
    d = normalize_domain(domain)
    return d in {"", "unknown", "https", "http", "tls", "quic", "dns", "none", "null", "abstain"}

def load_data(capture_ids=[1, 2, 3, 4]):
    records = []
    for cid in capture_ids:
        gt_file = f"ground_truth_{cid}.csv"
        out_file = f"output_capture_{cid}.json"
        
        if not os.path.exists(gt_file) or not os.path.exists(out_file):
            print(f"[!] Skipping capture {cid}: missing {gt_file} or {out_file}")
            continue
            
        df_gt = pd.read_csv(gt_file)
        with open(out_file, "r", encoding="utf-8") as f:
            engine_data = json.load(f)
            
        flows = engine_data.get("flows", [])
        df_flows = pd.DataFrame(flows)
        
        # Build lookup table for flows
        flow_lookup = {}
        for _, fl in df_flows.iterrows():
            key = (str(fl.get("src_ip")), str(fl.get("dst_ip")), str(fl.get("dst_port")))
            flow_lookup[key] = fl
            # Secondary key: dst_ip only
            dst_key = str(fl.get("dst_ip"))
            if dst_key not in flow_lookup:
                flow_lookup[dst_key] = fl
                
        for _, gt in df_gt.iterrows():
            src_ip = str(gt.get("src_ip", ""))
            dst_ip = str(gt.get("dst_ip", ""))
            dst_port = str(gt.get("dst_port", ""))
            true_d = normalize_domain(str(gt.get("true_domain", "")))
            
            # Lookup flow
            cand = flow_lookup.get((src_ip, dst_ip, dst_port))
            if cand is None:
                cand = flow_lookup.get(dst_ip)
                
            pred_d = ""
            method = "Abstain"
            if cand is not None:
                pred_d = normalize_domain(str(cand.get("domain", "")))
                method = str(cand.get("method", "Unknown"))
                
            # Determine True Category
            if "negative" in true_d or true_d == "":
                true_cat = "Negative / Noise"
            else:
                true_cat = DOMAIN_TO_CATEGORY.get(true_d, "Other")
                
            # Determine Predicted Category
            if is_abstention(pred_d):
                pred_cat = "Unclassified (Abstain)"
            else:
                pred_cat = DOMAIN_TO_CATEGORY.get(pred_d, "Other / Novel")
                
            records.append({
                "capture_id": cid,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "true_domain": true_d,
                "true_category": true_cat,
                "pred_domain": pred_d if not is_abstention(pred_d) else "UNKNOWN",
                "pred_category": pred_cat,
                "method": method
            })
            
    return pd.DataFrame(records)

def generate_category_matrix(df, out_png="confusion_matrix_category.png", out_pdf="confusion_matrix_category.pdf"):
    categories = ["Search", "Streaming", "Developer", "Social", "E-Commerce", "Negative / Noise"]
    pred_categories = ["Search", "Streaming", "Developer", "Social", "E-Commerce", "Negative / Noise", "Unclassified (Abstain)"]
    
    # Filter only relevant categories present
    row_cats = [c for c in categories if c in df["true_category"].values]
    col_cats = [c for c in pred_categories if c in df["pred_category"].values or c in row_cats]
    
    # Compute raw counts
    counts = np.zeros((len(row_cats), len(col_cats)), dtype=int)
    for i, r_cat in enumerate(row_cats):
        sub = df[df["true_category"] == r_cat]
        for j, c_cat in enumerate(col_cats):
            counts[i, j] = len(sub[sub["pred_category"] == c_cat])
            
    # Compute row-normalized percentages
    row_sums = counts.sum(axis=1, keepdims=True)
    norm = np.divide(counts.astype(float), row_sums, out=np.zeros_like(counts, dtype=float), where=row_sums != 0) * 100.0
    
    # Text annotations: percentage on top, counts in parens below
    annot = np.empty_like(counts, dtype=object)
    for i in range(len(row_cats)):
        for j in range(len(col_cats)):
            val = counts[i, j]
            pct = norm[i, j]
            if val > 0:
                annot[i, j] = f"{pct:.1f}%\n({val:,})"
            else:
                annot[i, j] = "—"
                
    # Plotting setup
    plt.rcParams["font.sans-serif"] = "DejaVu Sans"
    plt.rcParams["font.family"] = "sans-serif"
    
    fig, ax = plt.subplots(figsize=(11, 7.5), dpi=300)
    
    # Custom high-contrast colormap
    cmap = sns.color_palette("Blues", as_cmap=True)
    
    sns.heatmap(
        norm,
        annot=annot,
        fmt="",
        cmap=cmap,
        vmin=0.0,
        vmax=100.0,
        cbar_kws={
            "label": "Classification Rate (% of True Category)",
            "shrink": 0.85,
            "pad": 0.03
        },
        linewidths=1.2,
        linecolor="#e2e8f0",
        square=False,
        ax=ax,
        annot_kws={"fontsize": 11, "fontweight": "bold", "linespacing": 1.2}
    )
    
    # Labels and titles
    ax.set_title(
        "DPI Multi-Domain Classification — Category Confusion Matrix\n"
        f"(Evaluated across {len(df):,} network flows, 4 independent capture rounds)",
        fontsize=13,
        pad=16,
        fontweight="bold",
        color="#1e293b"
    )
    
    ax.set_xticklabels(col_cats, rotation=25, ha="right", fontsize=10, fontweight="bold", color="#334155")
    ax.set_yticklabels(row_cats, rotation=0, fontsize=10, fontweight="bold", color="#334155")
    
    ax.set_xlabel("Engine Predicted Category", fontsize=12, fontweight="bold", labelpad=12, color="#0f172a")
    ax.set_ylabel("True Ground-Truth Category", fontsize=12, fontweight="bold", labelpad=12, color="#0f172a")
    
    # Subtle frame styling
    for _, spine in ax.spines.items():
        spine.set_visible(True)
        spine.set_color("#cbd5e1")
        spine.set_linewidth(1.0)
        
    plt.tight_layout()
    plt.savefig(out_png, dpi=300, bbox_inches="tight")
    plt.savefig(out_pdf, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved high-resolution category matrix: {out_png} and {out_pdf}")

def generate_upgraded_confusion_matrix(df, out_png="confusion_matrix.png"):
    """
    Renders an upgraded, clean confusion matrix for top active domains + noise,
    replacing the old 51x51 crammed version with a clean, readable, publication-grade layout.
    """
    # Select top 15 domains + negative noise + abstain
    top_domains = df[df["true_domain"] != "negative"]["true_domain"].value_counts().head(12).index.tolist()
    top_domains = sorted(top_domains) + ["negative"]
    
    pred_labels = [d for d in top_domains] + ["UNKNOWN"]
    
    sub_df = df[df["true_domain"].isin(top_domains)].copy()
    
    counts = np.zeros((len(top_domains), len(pred_labels)), dtype=int)
    for i, t_d in enumerate(top_domains):
        subset = sub_df[sub_df["true_domain"] == t_d]
        for j, p_d in enumerate(pred_labels):
            counts[i, j] = len(subset[subset["pred_domain"] == p_d])
            
    row_sums = counts.sum(axis=1, keepdims=True)
    norm = np.divide(counts.astype(float), row_sums, out=np.zeros_like(counts, dtype=float), where=row_sums != 0) * 100.0
    
    annot = np.empty_like(counts, dtype=object)
    for i in range(len(top_domains)):
        for j in range(len(pred_labels)):
            val = counts[i, j]
            pct = norm[i, j]
            if val > 0:
                annot[i, j] = f"{pct:.0f}%\n({val})"
            else:
                annot[i, j] = "—"
                
    fig, ax = plt.subplots(figsize=(12, 8.5), dpi=300)
    
    cmap = sns.color_palette("mako_r", as_cmap=True)
    
    sns.heatmap(
        norm,
        annot=annot,
        fmt="",
        cmap=cmap,
        vmin=0.0,
        vmax=100.0,
        cbar_kws={"label": "Classification Rate (%)", "shrink": 0.8},
        linewidths=0.8,
        linecolor="#cbd5e1",
        ax=ax,
        annot_kws={"fontsize": 9, "fontweight": "semibold", "linespacing": 1.2}
    )
    
    ax.set_title(
        "DPI Flow Classification — Representative Domain Disambiguation Matrix\n"
        "(Evaluated on Positive Flow Classes & Unregistered Negative Controls)",
        fontsize=13,
        pad=16,
        fontweight="bold",
        color="#1e293b"
    )
    
    ax.set_xticklabels(pred_labels, rotation=35, ha="right", fontsize=9.5, fontweight="semibold", color="#334155")
    ax.set_yticklabels(top_domains, rotation=0, fontsize=9.5, fontweight="semibold", color="#334155")
    
    ax.set_xlabel("Engine Classified Domain", fontsize=11.5, fontweight="bold", labelpad=10, color="#0f172a")
    ax.set_ylabel("True Flow Domain", fontsize=11.5, fontweight="bold", labelpad=10, color="#0f172a")
    
    plt.tight_layout()
    plt.savefig(out_png, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved upgraded domain confusion matrix: {out_png}")

if __name__ == "__main__":
    print("=" * 70)
    print(" GENERATING PUBLICATION-GRADE CONFUSION MATRICES")
    print("=" * 70)
    df_all = load_data([1, 2, 3, 4])
    print(f"[*] Aggregated {len(df_all):,} matched flows across 4 captures.")
    
    generate_category_matrix(df_all)
    generate_upgraded_confusion_matrix(df_all)
    print("=" * 70)
    print("[✓] All publication figures successfully generated.")
    print("=" * 70)

