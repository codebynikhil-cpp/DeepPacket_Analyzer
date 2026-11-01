# Large-Scale Labeled PCAP Dataset Collection Pipeline

`scripts/scale_dataset.py` generates large-scale labeled network traffic datasets for evaluating deep packet inspection (DPI), flow classification, and disambiguation algorithms.

## Dataset Structure

The benchmark produces 4 independent capture iterations:
- **PCAP Captures**: `dataset_capture_1.pcap` through `dataset_capture_4.pcap`
- **Ground-Truth CSVs**: `ground_truth_1.csv` through `ground_truth_4.csv`

### Per-Capture Composition:
- **50 Domains across 5 Categories**:
  - **Search**: `google.com`, `bing.com`, `duckduckgo.com`, `yahoo.com`, `baidu.com`, `yandex.com`, `ecosia.org`, `qwant.com`, `brave.com`, `startpage.com`
  - **Streaming**: `youtube.com`, `netflix.com`, `twitch.tv`, `spotify.com`, `soundcloud.com`, `vimeo.com`, `dailymotion.com`, `hulu.com`, `disneyplus.com`, `primevideo.com`
  - **Developer**: `github.com`, `gitlab.com`, `stackoverflow.com`, `bitbucket.org`, `npmjs.com`, `pypi.org`, `docker.com`, `huggingface.co`, `kaggle.com`, `leetcode.com`
  - **Social**: `twitter.com`, `facebook.com`, `instagram.com`, `linkedin.com`, `reddit.com`, `discord.com`, `telegram.org`, `whatsapp.com`, `snapchat.com`, `pinterest.com`
  - **E-commerce**: `amazon.com`, `ebay.com`, `aliexpress.com`, `paypal.com`, `etsy.com`, `walmart.com`, `target.com`, `shopify.com`, `alibaba.com`, `wix.com`
- **5 Independent Sessions** per domain (separated by idle delays to force fresh TCP handshakes and DNS resolutions) = **250 positive flows**.
- **100 Negative Flows**: Direct IP connections (DNS root resolvers, public servers, and unregistered IPs) on port 443 with no SNI or domain name to test false-positive rates.
- **Total per capture**: 350 flows.
- **Grand Total across 4 captures**: **1,400 labeled flows** (>1,000 requirement).

---

## Running on Windows (with Npcap / Wireshark)

### 1. Prerequisites
- **Python 3.9+** with `requests`:
  ```bash
  pip install requests urllib3 scapy
  ```
- **Wireshark / Npcap**: Install Wireshark with the **Npcap** driver checked.
  The script automatically detects `dumpcap.exe` at:
  `C:\Program Files\Wireshark\dumpcap.exe`

### 2. Identify Active Network Interface
Run the interface listing command:
```bash
python scripts/scale_dataset.py --list-interfaces
```
Output will list your adapters, for example:
```text
1. \Device\NPF_{...} (Local Area Connection)
6. \Device\NPF_{...} (Wi-Fi)
10. \Device\NPF_{...} (Ethernet)
```
Note the interface number corresponding to your active connection (e.g. `6` for Wi-Fi or `10` for Ethernet).

### 3. Run Full Live Capture (Elevated / Admin Terminal)
Open PowerShell or Command Prompt as **Administrator** and run:
```bash
# Capture using Wi-Fi interface (e.g., interface 6)
python scripts/scale_dataset.py --interface 6 --session-delay 30 --capture-gap 300
```
- `--session-delay 30`: 30-second cooldown between sessions to force new TCP sockets and DNS cache expiration.
- `--capture-gap 300`: 5-minute pause between the 4 independent capture iterations.

### 4. Fast Dry-Run / Synthetic Mode
If testing without administrator rights or in CI/CD without an active sniffer driver:
```bash
python scripts/scale_dataset.py --synthetic --session-delay 0 --capture-gap 5
```

---

## Evaluating the Captured Dataset

Once the captures are complete, run your DPI engine and evaluation script:

```bash
# 1. Inspect Capture 1 with DPI engine
./build/PacketInspector.exe dataset_capture_1.pcap

# 2. Compute Precision, Recall, F1, and Confusion Matrix
python scripts/evaluate_dpi.py --telemetry output.json --ground-truth ground_truth_1.csv --output-matrix confusion_matrix_1.png
```

---

## CSV Ground-Truth Schema

Each `ground_truth_N.csv` file contains the following columns:

| Column | Type | Description |
| :--- | :--- | :--- |
| `capture_id` | integer | Capture sequence index (1 - 4) |
| `flow_id` | integer | Unique sequential flow identifier |
| `src_ip` | string | Local source IP of the probing machine |
| `dst_ip` | string | Resolved target IPv4 address |
| `dst_port` | integer | Target port (`443` or `53`) |
| `true_domain` | string | Ground-truth hostname or `"NEGATIVE"` |
| `label_type` | string | `"positive"` or `"negative"` |
| `timestamp` | string | ISO 8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`) |

