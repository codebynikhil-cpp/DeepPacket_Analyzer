#!/usr/bin/env python3
"""
DeepPacket Analyzer - Prepare DeepSeek Upload Bundle
Generates:
1. DeepPacket_Analyzer_Full_Project.txt (Unified single text file with all core files & README)
2. DeepPacket_Analyzer_Full_Project.md  (Unified markdown file with code highlighting)
3. DeepPacket_Analyzer_Source_Bundle.zip (Clean zip file with project source structure)
4. all_project_files/ (Directory with clean copies of all essential source files)
"""

import os
import shutil
import zipfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT_DIR / "deepseek_upload"
FILES_DIR = OUTPUT_DIR / "all_project_files"

INCLUDED_FILES = [
    # Documentation & Root Configs
    "README.md",
    "CMakeLists.txt",
    "package.json",
    "rules.json",
    "critical_websites.json",
    "server.js",
    "PROJECT_AUDIT.md",
    "PROJECT_IMPROVEMENT_PLAN.md",
    "BENCHMARK.md",
    "WINDOWS_SETUP.md",
    "DEMO.md",
    "docs/TELEMETRY.md",

    # Headers (Core C++ Engine)
    "include/connection_tracker.h",
    "include/dns_parser.h",
    "include/dpi_engine.h",
    "include/fast_path.h",
    "include/http_parser.h",
    "include/live_capture_source.h",
    "include/packet_parser.h",
    "include/packet_queue.h",
    "include/packet_source.h",
    "include/pcap_file_source.h",
    "include/pcap_reader.h",
    "include/pcap_wrapper.h",
    "include/platform.h",
    "include/rule_manager.h",
    "include/sni_extractor.h",
    "include/stats_collector.h",
    "include/traffic_analytics.h",
    "include/types.h",
    "include/wfp_enforcement.h",

    # Source Files (C++ Engine)
    "src/main.cpp",
    "src/connection_tracker.cpp",
    "src/dns_parser.cpp",
    "src/dpi_engine.cpp",
    "src/fast_path.cpp",
    "src/http_parser.cpp",
    "src/live_capture_source.cpp",
    "src/packet_parser.cpp",
    "src/packet_source.cpp",
    "src/pcap_reader.cpp",
    "src/rule_manager.cpp",
    "src/sni_extractor.cpp",
    "src/stats_collector.cpp",
    "src/traffic_analytics.cpp",
    "src/types.cpp",
    "src/wfp_enforcement.cpp",

    # Backend / Node Library
    "lib/health.js",

    # Frontend UI (Dashboard)
    "public/index.html",
    "public/style.css",
    "public/app.js",
    "public/js/charts.js",
    "public/js/dom.js",
    "public/js/explorer.js",
    "public/js/network.js",
    "public/js/rules.js",

    # Scripts & Test Suite
    "scripts/benchmark.js",
    "scripts/benchmark-mixed.js",
    "scripts/demo.js",
    "scripts/live-smoke.js",
    "scripts/ui-test-server.js",
    "scripts/engine-path.js",
    "tests/offline.test.js",
    "tests/server.test.js",
    "tests/analytics.test.js",
    "tests/health.test.js",
    "tests/helpers/traffic-fixture.js",
    "tests/browser/dashboard.spec.js",
]

def get_language(path_str: str) -> str:
    ext = os.path.splitext(path_str)[1].lower()
    mapping = {
        ".cpp": "cpp",
        ".h": "cpp",
        ".js": "javascript",
        ".json": "json",
        ".html": "html",
        ".css": "css",
        ".md": "markdown",
        ".txt": "text",
    }
    return mapping.get(ext, "")

def main():
    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    FILES_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Creating DeepSeek upload artifacts in: {OUTPUT_DIR}")

    # Copy individual files into files_copy directory
    valid_files = []
    for rel_path in INCLUDED_FILES:
        src_path = ROOT_DIR / rel_path
        if src_path.exists():
            dest_path = FILES_DIR / rel_path
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_path, dest_path)
            valid_files.append(rel_path)
        else:
            print(f"Warning: File not found: {rel_path}")

    # Create Zip File
    zip_path = OUTPUT_DIR / "DeepPacket_Analyzer_Source_Bundle.zip"
    print(f"Generating ZIP bundle: {zip_path.name}")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for rel_path in valid_files:
            file_path = FILES_DIR / rel_path
            zipf.write(file_path, arcname=rel_path)

    # Header section for consolidated files
    overview_header = """================================================================================
DEEPPACKET ANALYZER: REAL-TIME PACKET CAPTURE & DEEP TRAFFIC ANALYSIS ENGINE
================================================================================
Author / Maintainer: codebynikhil-cpp
Repository: https://github.com/codebynikhil-cpp/DeepPacket_Analyzer
Architecture:
- High-Performance C++20 Capture & DPI Engine (Npcap / WinPcap & PCAP offline replay)
- Multi-Threaded Architecture: Fast Ring Buffer / Lock-free Packet Queue, Dedicated Consumer
- Deep Packet Inspection: TLS SNI Extraction, DNS Query/Response, HTTP Host/Method Parsing
- Windows Filtering Platform (WFP) Kernel-level Rule Enforcement & Dynamic Connection Blocking
- Node.js WebSocket Bridge & Real-Time REST Control API (server.js)
- Zero-Dependency Vanilla CSS/JS Modern Dark Glassmorphism SOC Dashboard

TABLE OF INCLUDED FILES:
"""
    for i, f in enumerate(valid_files, 1):
        overview_header += f"{i:2d}. {f}\n"
    overview_header += "================================================================================\n\n"

    # 1. Generate DeepPacket_Analyzer_Full_Project.txt
    txt_path = OUTPUT_DIR / "DeepPacket_Analyzer_Full_Project.txt"
    print(f"Generating single consolidated text file: {txt_path.name}")
    with open(txt_path, "w", encoding="utf-8") as out_txt:
        out_txt.write(overview_header)
        for rel_path in valid_files:
            file_path = ROOT_DIR / rel_path
            sep = "=" * 80
            out_txt.write(f"\n{sep}\n")
            out_txt.write(f"FILE: {rel_path}\n")
            out_txt.write(f"{sep}\n\n")
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                out_txt.write(content)
                if not content.endswith("\n"):
                    out_txt.write("\n")
            except Exception as e:
                out_txt.write(f"Error reading file: {e}\n")

    # 2. Generate DeepPacket_Analyzer_Full_Project.md
    md_path = OUTPUT_DIR / "DeepPacket_Analyzer_Full_Project.md"
    print(f"Generating single consolidated markdown file: {md_path.name}")
    with open(md_path, "w", encoding="utf-8") as out_md:
        out_md.write("# DeepPacket Analyzer - Complete Project Source & Documentation\n\n")
        out_md.write(overview_header.replace("=", "---"))
        for rel_path in valid_files:
            file_path = ROOT_DIR / rel_path
            lang = get_language(rel_path)
            out_md.write(f"\n\n## File: `{rel_path}`\n\n")
            out_md.write(f"```{lang}\n")
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                out_md.write(content)
                if not content.endswith("\n"):
                    out_md.write("\n")
            except Exception as e:
                out_md.write(f"Error reading file: {e}\n")
            out_md.write("```\n")

    # Print summary
    txt_size_kb = os.path.getsize(txt_path) / 1024
    md_size_kb = os.path.getsize(md_path) / 1024
    zip_size_kb = os.path.getsize(zip_path) / 1024

    print("\nGeneration completed successfully!")
    print(f"  - Files copied: {len(valid_files)}")
    print(f"  - Text bundle:   {txt_path.name} ({txt_size_kb:.1f} KB)")
    print(f"  - Markdown file: {md_path.name} ({md_size_kb:.1f} KB)")
    print(f"  - ZIP archive:   {zip_path.name} ({zip_size_kb:.1f} KB)")
    print(f"  - Clean folder:  {FILES_DIR}")

if __name__ == "__main__":
    main()
