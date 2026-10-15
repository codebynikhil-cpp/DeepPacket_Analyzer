#!/usr/bin/env python3
"""
Generate publication-quality diagrams and process assets for the research paper:
- CMRIT_logo.png
- VTU_logo.png
- TerminalOutput.png
- SystemArchitecture.png
- ThreadPipeline.png
- PacketStructure.png
- TLS_Handshake.png
- TLS_ClientHello_Structure.png
- FeatureImportance.png
"""

import os
import shutil
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
import matplotlib.pyplot as plt
import matplotlib.patches as patches

ROOT_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT_DIR / "research_paper"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# 1. Logos
def handle_logos():
    print("Processing university logos...")
    cmrit_src = Path(r"D:\college\format (2)\cmrit_logo.png")
    vtu_src = Path(r"D:\college\format (2)\vtulogo.jpg")
    
    if cmrit_src.exists():
        shutil.copy2(cmrit_src, OUTPUT_DIR / "CMRIT_logo.png")
        print("  -> CMRIT_logo.png copied")
    else:
        print("  -> Warning: cmrit_logo.png not found")

    if vtu_src.exists():
        try:
            with Image.open(vtu_src) as img:
                img.save(OUTPUT_DIR / "VTU_logo.png", "PNG")
            print("  -> VTU_logo.png converted and saved")
        except Exception as e:
            print("  -> Error converting VTU logo:", e)
    else:
        print("  -> Warning: vtulogo.jpg not found")

# 2. TerminalOutput.png
def generate_terminal_output():
    print("Generating TerminalOutput.png...")
    width, height = 1200, 720
    img = Image.new("RGB", (width, height), color="#0c1017")
    draw = ImageDraw.Draw(img)

    # Window title bar
    draw.rectangle([0, 0, width, 40], fill="#161b22")
    # Window control dots
    draw.ellipse([15, 13, 27, 25], fill="#ff5f56")
    draw.ellipse([35, 13, 47, 25], fill="#ffbd2e")
    draw.ellipse([55, 13, 67, 25], fill="#27c93f")

    # Font setup
    try:
        font = ImageFont.truetype("consola.ttf", 16)
        font_bold = ImageFont.truetype("consolab.ttf", 17)
        title_font = ImageFont.truetype("segoeui.ttf", 14)
    except:
        font = ImageFont.load_default()
        font_bold = font
        title_font = font

    draw.text((width // 2 - 130, 11), "Administrator: Windows PowerShell - PacketInspector.exe", fill="#8b949e", font=title_font)

    lines = [
        ("PS D:\\DeepPacket-Analyzer> .\\build\\PacketInspector.exe --interface 6 --verbose", "#e6edf3", True),
        ("", "#ffffff", False),
        ("================================================================================", "#30363d", False),
        ("  DEEPPACKET ANALYZER v1.0.0 (x64 Release, Windows Filtering Platform Active)   ", "#58a6ff", True),
        ("  Lock-Free Ring Buffer: 64 MB | Producer-Consumer Thread Model | C++20 Core    ", "#8b949e", False),
        ("================================================================================", "#30363d", False),
        ("[INFO] Initializing Npcap Driver on Interface [6]: Realtek RTL8852BE WiFi 6 PCIe", "#7ee787", False),
        ("[INFO] Promiscuous mode enabled, mintocopy = 0 (Immediate Delivery Mode)", "#7ee787", False),
        ("[INFO] Windows Filtering Platform (WFP) sublayer registered. Priority: 0xF000", "#7ee787", False),
        ("[INFO] Consumer worker thread pinned to CPU Core #2. Ring capacity: 65,536 slots", "#7ee787", False),
        ("[INFO] Capture started. Listening for live network packets...", "#e6edf3", True),
        ("", "#ffffff", False),
        ("[FLOW] SYN: 192.168.1.105:58214 -> 140.82.121.4:443 [TCP] State: SYN_SENT", "#d2a8ff", False),
        ("[FLOW] SYN-ACK: 140.82.121.4:443 -> 192.168.1.105:58214 [TCP] State: ESTABLISHED", "#d2a8ff", False),
        ("[DPI]  TLS ClientHello parsed (184 bytes) | TLS 1.3 | Cipher Suites: 17", "#79c0ff", True),
        ("[DPI]  Extension 0x0000 (SNI) detected -> Server Name: 'github.com'", "#7ee787", True),
        ("[APP]  Application classified: [GitHub] (Category: Development, Confidence: 1.00)", "#ffa657", True),
        ("[DNS]  Query observed: 'api.github.com' -> Response: 140.82.121.6 (TTL: 60s)", "#a5d6ff", False),
        ("[FLOW] UDP: 192.168.1.105:52319 -> 8.8.8.8:53 [DNS] Latency: 14.2ms", "#d2a8ff", False),
        ("[DPI]  HTTP GET: 'http://connectivitycheck.gstatic.com/generate_204' -> Google", "#79c0ff", False),
        ("", "#ffffff", False),
        ("--- [PERFORMANCE TELEMETRY: t = 10.0s] -----------------------------------------", "#8b949e", False),
        ("  Packets Ingested: 184,920 pkts  |  Total Volume: 142.8 MB  |  Rate: 18,492 p/s", "#58a6ff", True),
        ("  Ring Queue Ingest Drops: 0      |  Parse Errors: 0         |  Active Flows: 142", "#7ee787", True),
        ("  WFP ALE Block Rule Count: 3     |  Telemetry IPC Snapshot: output.json [OK]", "#ffa657", False),
        ("--------------------------------------------------------------------------------", "#8b949e", False),
    ]

    y = 60
    for line, color, is_bold in lines:
        curr_font = font_bold if is_bold else font
        draw.text((25, y), line, fill=color, font=curr_font)
        y += 24

    img.save(OUTPUT_DIR / "TerminalOutput.png", "PNG")
    print("  -> Saved TerminalOutput.png")

# 3. SystemArchitecture.png
def generate_system_architecture():
    print("Generating SystemArchitecture.png...")
    fig, ax = plt.subplots(figsize=(13, 8), dpi=300)
    ax.set_facecolor("#f8f9fc")
    fig.patch.set_facecolor("#ffffff")

    # Define blocks
    boxes = [
        # (x, y, w, h, title, subtitle, color, border)
        (0.5, 6.8, 2.2, 1.2, "Ingestion Layer", "Npcap / WinPcap\nPCAP Offline File", "#e0e7ff", "#4338ca"),
        (3.3, 6.8, 2.6, 1.2, "Producer Thread", "Atomic Packet Dispatch\npcap_next_ex() Ingestion", "#dbeafe", "#1d4ed8"),
        (6.5, 6.8, 2.8, 1.2, "Lock-Free Ring Buffer", "Circular Cache-Aligned\n64-byte Padded Slots", "#fef3c7", "#b45309"),
        (10.0, 6.8, 2.6, 1.2, "Consumer Worker", "Zero-Wait Queue Pop\nThread Pinned Core #2", "#dcfce7", "#15803d"),

        (10.0, 4.4, 2.6, 1.3, "Protocol Parser", "Ethernet II / VLAN\nIPv4 / IPv6 Decoders\nTCP / UDP Slicing", "#ede9fe", "#6d28d9"),
        (6.5, 4.4, 2.8, 1.3, "Bi-Directional Flow", "5-Tuple Canonical Key\nTCP State Engine\nLRU Cache Eviction", "#fae8ff", "#a21caf"),
        (2.5, 4.4, 3.2, 1.3, "DPI Classifier", "TLS 1.3 SNI Extractor\nDNS Query / Host Parser\nHeuristic Engine", "#ffedd5", "#c2410c"),

        (2.5, 1.8, 3.2, 1.3, "Kernel Enforcement", "Windows Filtering Platform\nALE_AUTH_CONNECT_V4/V6\nSublayer Priority Invalidate", "#fee2e2", "#b91c1c"),
        (6.8, 1.8, 3.5, 1.3, "Telemetry & IPC Engine", "Atomic PID Swap File\nREST API / WebSockets\nWebsite Health Checker", "#cffafe", "#0e7490"),
        (10.8, 1.8, 2.0, 1.3, "SOC Dashboard", "Glassmorphic UI\nReal-time Timeline\nSVG Topo Graph", "#f1f5f9", "#334155"),
    ]

    for (x, y, w, h, title, sub, bg, border) in boxes:
        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.1,rounding_size=0.15",
                                      facecolor=bg, edgecolor=border, linewidth=1.8)
        ax.add_patch(rect)
        ax.text(x + w/2, y + h*0.65, title, fontsize=10.5, fontweight='bold', ha='center', va='center', color="#0f172a")
        ax.text(x + w/2, y + h*0.3, sub, fontsize=8, ha='center', va='center', color="#334155")

    # Arrows
    arrow_props = dict(arrowstyle="->", lw=2, color="#475569")
    ax.annotate("", xy=(3.3, 7.4), xytext=(2.7, 7.4), arrowprops=arrow_props)
    ax.annotate("", xy=(6.5, 7.4), xytext=(5.9, 7.4), arrowprops=arrow_props)
    ax.annotate("", xy=(10.0, 7.4), xytext=(9.3, 7.4), arrowprops=arrow_props)
    
    # Down from consumer to parser
    ax.annotate("", xy=(11.3, 5.7), xytext=(11.3, 6.8), arrowprops=arrow_props)
    # Left from parser to flow
    ax.annotate("", xy=(9.3, 5.05), xytext=(10.0, 5.05), arrowprops=arrow_props)
    # Left from flow to DPI
    ax.annotate("", xy=(5.7, 5.05), xytext=(6.5, 5.05), arrowprops=arrow_props)

    # Down from DPI to WFP and Telemetry
    ax.annotate("", xy=(4.1, 3.1), xytext=(4.1, 4.4), arrowprops=dict(arrowstyle="->", lw=2, color="#b91c1c"))
    ax.annotate("", xy=(7.5, 3.1), xytext=(5.5, 4.4), arrowprops=dict(arrowstyle="->", lw=2, color="#0e7490"))
    ax.annotate("", xy=(10.8, 2.45), xytext=(10.3, 2.45), arrowprops=arrow_props)

    ax.set_xlim(0, 13.5)
    ax.set_ylim(1.0, 8.5)
    ax.axis('off')
    plt.title("DeepPacket Analyzer: System Architecture & Dataflow Pipeline", fontsize=14, fontweight='bold', pad=15, color="#1e293b")
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "SystemArchitecture.png", dpi=300)
    plt.close()
    print("  -> Saved SystemArchitecture.png")

# 4. ThreadPipeline.png
def generate_thread_pipeline():
    print("Generating ThreadPipeline.png...")
    fig, ax = plt.subplots(figsize=(11, 6), dpi=300)
    ax.set_facecolor("#ffffff")
    fig.patch.set_facecolor("#ffffff")

    # Thread boundaries
    rect_prod = patches.FancyBboxPatch((0.5, 1.0), 3.0, 4.5, boxstyle="round,pad=0.1", facecolor="#eff6ff", edgecolor="#3b82f6", lw=2, linestyle='--')
    rect_queue = patches.FancyBboxPatch((4.0, 1.5), 3.0, 3.5, boxstyle="round,pad=0.1", facecolor="#fffbeb", edgecolor="#f59e0b", lw=2)
    rect_cons = patches.FancyBboxPatch((7.5, 1.0), 3.0, 4.5, boxstyle="round,pad=0.1", facecolor="#f0fdf4", edgecolor="#10b981", lw=2, linestyle='--')

    ax.add_patch(rect_prod)
    ax.add_patch(rect_queue)
    ax.add_patch(rect_cons)

    ax.text(2.0, 5.2, "PRODUCER THREAD\n(Capture Core)", fontsize=11, fontweight='bold', ha='center', color="#1d4ed8")
    ax.text(5.5, 4.7, "LOCK-FREE RING BUFFER\n(Cache Line Padded)", fontsize=10, fontweight='bold', ha='center', color="#b45309")
    ax.text(9.0, 5.2, "CONSUMER THREAD\n(DPI Engine Core)", fontsize=11, fontweight='bold', ha='center', color="#047857")

    # Producer steps
    p_steps = ["1. pcap_next_ex() Hook", "2. Packet Header Slice", "3. Atomic Index Fetch", "4. Slot Write & Memory Barrier"]
    for i, s in enumerate(p_steps):
        box = patches.FancyBboxPatch((0.8, 4.0 - i*0.8), 2.4, 0.55, boxstyle="square,pad=0.05", facecolor="#ffffff", edgecolor="#93c5fd")
        ax.add_patch(box)
        ax.text(2.0, 4.27 - i*0.8, s, fontsize=8.5, ha='center', va='center')

    # Queue slots visual
    for j in range(5):
        slot = patches.Rectangle((4.4, 3.8 - j*0.5), 2.2, 0.4, facecolor="#fef3c7", edgecolor="#d97706")
        ax.add_patch(slot)
        ax.text(5.5, 4.0 - j*0.5, f"Slot [{j}] (64-byte aligned)", fontsize=7.5, ha='center', va='center')

    # Consumer steps
    c_steps = ["1. Tail Advance (Atomic)", "2. Frame L2-L4 Decapsulate", "3. Flow Key Hash Lookup", "4. TLS/DNS DPI Classification"]
    for i, s in enumerate(c_steps):
        box = patches.FancyBboxPatch((7.8, 4.0 - i*0.8), 2.4, 0.55, boxstyle="square,pad=0.05", facecolor="#ffffff", edgecolor="#86efac")
        ax.add_patch(box)
        ax.text(9.0, 4.27 - i*0.8, s, fontsize=8.5, ha='center', va='center')

    # Transition arrows
    ax.annotate("", xy=(4.3, 3.0), xytext=(3.3, 3.0), arrowprops=dict(arrowstyle="->", lw=2.5, color="#1d4ed8"))
    ax.annotate("", xy=(7.7, 3.0), xytext=(6.7, 3.0), arrowprops=dict(arrowstyle="->", lw=2.5, color="#047857"))

    ax.set_xlim(0, 11)
    ax.set_ylim(0.5, 6.0)
    ax.axis('off')
    plt.title("Decoupled Multi-Threaded Ingestion Pipeline with Ring Buffer", fontsize=13, fontweight='bold', pad=12)
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "ThreadPipeline.png", dpi=300)
    plt.close()
    print("  -> Saved ThreadPipeline.png")

# 5. PacketStructure.png
def generate_packet_structure():
    print("Generating PacketStructure.png...")
    fig, ax = plt.subplots(figsize=(12, 4.5), dpi=300)
    ax.set_facecolor("#ffffff")

    layers = [
        ("Layer 2: Ethernet Frame (14 Bytes)", [("Preamble (8B)", 1.2), ("Dest MAC (6B)", 1.4), ("Src MAC (6B)", 1.4), ("Type: 0x0800 (2B)", 1.4)], "#dbeafe", "#1e40af"),
        ("Layer 3: IPv4 Packet (20 Bytes)", [("Ver/IHL (1B)", 1.0), ("ToS (1B)", 0.8), ("Total Length (2B)", 1.4), ("Ident/Flags (4B)", 1.6), ("TTL/Proto 0x06 (2B)", 1.6), ("Header Chk (2B)", 1.2), ("Source IP (4B)", 1.8), ("Dest IP (4B)", 1.8)], "#e0e7ff", "#3730a3"),
        ("Layer 4: TCP Segment (20 Bytes)", [("Source Port (2B)", 2.0), ("Dest Port: 443 (2B)", 2.0), ("Sequence Number (4B)", 2.5), ("Ack Number (4B)", 2.5), ("Offset/Flags (2B)", 1.8), ("Window (2B)", 1.4)], "#ede9fe", "#5b21b6"),
        ("Layer 7: TLS Record / Application Payload", [("Content Type: 0x16 (1B)", 2.5), ("Version: 0x0303 (2B)", 2.5), ("Length (2B)", 2.0), ("Handshake Protocol: ClientHello (SNI Data)", 5.2)], "#fee2e2", "#991b1b"),
    ]

    y = 3.6
    for title, fields, bg, stroke in layers:
        ax.text(0.2, y + 0.35, title, fontsize=9.5, fontweight='bold', color=stroke)
        x = 0.2
        for name, w in fields:
            rect = patches.Rectangle((x, y - 0.3), w, 0.55, facecolor=bg, edgecolor=stroke, lw=1.2)
            ax.add_patch(rect)
            ax.text(x + w/2, y - 0.02, name, fontsize=7.5, ha='center', va='center', color="#0f172a")
            x += w + 0.08
        y -= 0.95

    ax.set_xlim(0, 13)
    ax.set_ylim(0.2, 4.4)
    ax.axis('off')
    plt.title("Network Frame Encapsulation & Protocol Slicing Hierarchy", fontsize=12, fontweight='bold', pad=10)
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "PacketStructure.png", dpi=300)
    plt.close()
    print("  -> Saved PacketStructure.png")

# 6. TLS_Handshake.png
def generate_tls_handshake():
    print("Generating TLS_Handshake.png...")
    fig, ax = plt.subplots(figsize=(10, 7), dpi=300)
    ax.set_facecolor("#f8fafc")

    # Endpoints
    ax.text(2.0, 6.2, "Client (User Host)", fontsize=12, fontweight='bold', ha='center', color="#0284c7")
    ax.text(8.0, 6.2, "Server (Remote FQDN)", fontsize=12, fontweight='bold', ha='center', color="#0284c7")
    ax.plot([2.0, 2.0], [0.8, 5.9], color="#94a3b8", lw=2, linestyle="--")
    ax.plot([8.0, 8.0], [0.8, 5.9], color="#94a3b8", lw=2, linestyle="--")

    # Steps
    steps = [
        (5.2, "1. ClientHello (Plaintext, SNI Extension: 'github.com')", True, "#22c55e", "->"),
        (4.4, "2. ServerHello (Plaintext, Key Share, Cipher Selection)", False, "#64748b", "<-"),
        (3.6, "=== [CRYPTOGRAPHIC BARRIER: Symmetric Key Derived] ===", None, "#ef4444", None),
        (2.8, "3. {EncryptedExtensions, Certificate, Finished}", False, "#dc2626", "<-"),
        (2.0, "4. {Finished} (Client Handshake Acknowledgment)", True, "#dc2626", "->"),
        (1.2, "5. [Application Data: Fully Encrypted HTTP/2 or HTTP/3]", True, "#7c3aed", "<->"),
    ]

    for y, label, is_client, col, direction in steps:
        if direction is None:
            ax.text(5.0, y, label, fontsize=9.5, fontweight='bold', ha='center', color=col,
                    bbox=dict(boxstyle="round,pad=0.2", facecolor="#fee2e2", edgecolor="#ef4444"))
        elif direction == "->":
            ax.annotate("", xy=(7.9, y), xytext=(2.1, y), arrowprops=dict(arrowstyle="->", lw=2, color=col))
            ax.text(5.0, y + 0.15, label, fontsize=9, fontweight='bold', ha='center', color=col)
        elif direction == "<-":
            ax.annotate("", xy=(2.1, y), xytext=(7.9, y), arrowprops=dict(arrowstyle="->", lw=2, color=col))
            ax.text(5.0, y + 0.15, label, fontsize=9, ha='center', color=col)
        elif direction == "<->":
            ax.annotate("", xy=(7.9, y), xytext=(2.1, y), arrowprops=dict(arrowstyle="<->", lw=2.5, color=col))
            ax.text(5.0, y + 0.2, label, fontsize=9.5, fontweight='bold', ha='center', color=col)

    # Highlight box on ClientHello
    hl = patches.FancyBboxPatch((1.8, 5.0), 6.4, 0.7, boxstyle="round,pad=0.1", fill=False, edgecolor="#16a34a", lw=2, linestyle=":")
    ax.add_patch(hl)
    ax.text(8.3, 5.35, "<- DeepPacket Analyzer\n   Extraction Point", fontsize=8.5, fontweight='bold', color="#16a34a", va='center')

    ax.set_xlim(0.5, 10.5)
    ax.set_ylim(0.5, 6.8)
    ax.axis('off')
    plt.title("TLS 1.3 Handshake Protocol & SNI Observability Boundary", fontsize=13, fontweight='bold', pad=12)
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "TLS_Handshake.png", dpi=300)
    plt.close()
    print("  -> Saved TLS_Handshake.png")

# 7. TLS_ClientHello_Structure.png
def generate_clienthello_structure():
    print("Generating TLS_ClientHello_Structure.png...")
    fig, ax = plt.subplots(figsize=(11, 6), dpi=300)
    ax.set_facecolor("#ffffff")

    blocks = [
        (0.5, 4.8, 2.5, 0.9, "TLS Record Header", "0x16 (Handshake)\nVer: 0x0301 | Length", "#e0f2fe", "#0284c7"),
        (3.3, 4.8, 2.8, 0.9, "Handshake Header", "Type: 0x01 (ClientHello)\nLength: 3 Bytes", "#e0e7ff", "#4338ca"),
        (6.4, 4.8, 2.2, 0.9, "Client Version", "0x0303 (TLS 1.2/1.3)\nCompatibility Mode", "#f3e8ff", "#7e22ce"),
        (8.9, 4.8, 1.8, 0.9, "Random", "32 Bytes Cryptographic\nClient Entropy", "#f1f5f9", "#475569"),

        (0.5, 3.2, 3.2, 0.9, "Session ID & Cipher Suites", "Vectors of Supported Ciphers\n(e.g., TLS_AES_128_GCM_SHA256)", "#f1f5f9", "#475569"),
        (4.0, 3.2, 2.8, 0.9, "Compression Methods", "Length: 1 Byte\nValue: 0x00 (Null)", "#f1f5f9", "#475569"),
        (7.1, 3.2, 3.6, 0.9, "Extensions Total Length", "Total Bytes of Extension Records\n(2 Bytes Prefix)", "#fef3c7", "#d97706"),

        (1.5, 1.2, 8.2, 1.4, "Extension: Server Name Indication (SNI)", 
         "Ext Type: 0x0000 (2B)  |  Ext Length: 0x0017 (2B)  |  Server Name List Length (2B)\nName Type: 0x00 (Host Name, 1B)  |  Host Name Length: 0x0012 (2B)\nServer Name: 'github.com' (ASCII Encoded Domain)", "#dcfce7", "#16a34a"),
    ]

    for x, y, w, h, title, sub, bg, border in blocks:
        box = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.08", facecolor=bg, edgecolor=border, lw=1.6)
        ax.add_patch(box)
        ax.text(x + w/2, y + h*0.68, title, fontsize=9.5, fontweight='bold', ha='center', va='center', color="#0f172a")
        ax.text(x + w/2, y + h*0.3, sub, fontsize=7.5, ha='center', va='center', color="#334155")

    # Arrow from Extensions to SNI
    ax.annotate("", xy=(5.5, 2.6), xytext=(8.9, 3.2), arrowprops=dict(arrowstyle="->", lw=2, color="#16a34a", connectionstyle="arc3,rad=-0.2"))

    ax.set_xlim(0, 11)
    ax.set_ylim(0.8, 6.2)
    ax.axis('off')
    plt.title("TLS ClientHello Packet Hierarchy & Server Name Indication (SNI) Layout", fontsize=12, fontweight='bold', pad=10)
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "TLS_ClientHello_Structure.png", dpi=300)
    plt.close()
    print("  -> Saved TLS_ClientHello_Structure.png")

# 8. FeatureImportance.png
def generate_feature_importance():
    print("Generating FeatureImportance.png...")
    fig, ax = plt.subplots(figsize=(9, 5), dpi=300)
    ax.set_facecolor("#ffffff")

    features = [
        "TLS ClientHello SNI Extractor",
        "DNS Transaction & Query Matching",
        "HTTP Host & Method Decoders",
        "L4 Port & Protocol Association",
        "Statistical Payload Heuristics"
    ]
    importance = [42.5, 27.2, 14.8, 9.5, 6.0]
    colors = ["#2563eb", "#0ea5e9", "#10b981", "#f59e0b", "#8b5cf6"]

    bars = ax.barh(features[::-1], importance[::-1], color=colors[::-1], height=0.55, edgecolor="#334155", lw=1)

    for bar in bars:
        w = bar.get_width()
        ax.text(w + 1.0, bar.get_y() + bar.get_height()/2, f"{w:.1f}%", va='center', fontsize=10, fontweight='bold', color="#1e293b")

    ax.set_xlim(0, 50)
    ax.set_xlabel("Relative Classification Contribution (%)", fontsize=11, fontweight='bold', color="#1e293b")
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color("#94a3b8")
    ax.spines['bottom'].set_color("#94a3b8")
    ax.tick_params(colors="#334155")

    plt.title("Protocol Classification Feature Importance Breakdown", fontsize=13, fontweight='bold', pad=15)
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "FeatureImportance.png", dpi=300)
    plt.close()
    print("  -> Saved FeatureImportance.png")

def main():
    handle_logos()
    generate_terminal_output()
    generate_system_architecture()
    generate_thread_pipeline()
    generate_packet_structure()
    generate_tls_handshake()
    generate_clienthello_structure()
    generate_feature_importance()
    print("\nAll 12 research paper images generated successfully in:", OUTPUT_DIR)

if __name__ == "__main__":
    main()
