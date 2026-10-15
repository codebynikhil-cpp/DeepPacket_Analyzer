# DeepPacket Analyzer - Academic Research Paper

This folder contains the complete, publication-ready research paper for **DeepPacket Analyzer (DPA)** written in standard IEEE conference LaTeX format.

## File Manifest
- [`main.tex`](./main.tex): Complete, self-contained LaTeX document including abstract, system architecture, mathematical formulations, algorithms, benchmarks, comparative analysis tables, and embedded bibliography.
- [`references.bib`](./references.bib): BibTeX bibliography file for tools or workflows that compile using `bibtex`.

## How to Compile

### Option 1: Overleaf (Recommended - Zero Installation)
1. Open [Overleaf](https://www.overleaf.com/).
2. Create a **New Project** -> **Upload Project**.
3. Upload `main.tex` (and optionally `references.bib`).
4. Click **Recompile** to generate the PDF immediately.

### Option 2: Local LaTeX Installation (TeX Live, MiKTeX, MacTeX)
Run the following commands in this directory:
```bash
pdflatex main.tex
pdflatex main.tex
```

## Paper Highlights
- **Title**: *DeepPacket Analyzer: A High-Throughput Multi-Threaded Deep Packet Inspection and Kernel-Enforced Traffic Classification Engine*
- **Architecture**: Lock-free cache-aligned ring buffer, C++20 multi-threading, WFP kernel driver enforcement.
- **Deep Packet Inspection**: TLS 1.3 ClientHello SNI extraction algorithm, RFC 1035 DNS parser, HTTP parser, heuristic fallback.
- **Empirical Evaluation**: 384k+ pkts/s throughput, $<1\mu s$ parsing latency, 0% queue drop rate, $<35$ MB memory footprint.
- **Comparative Analysis**: Full comparative table against Wireshark, Snort 3, and Zeek.
