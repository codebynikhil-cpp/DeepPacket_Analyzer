# Telemetry contract

The engine atomically replaces `output.json`; Express serves it through `GET /data`. The existing root schema is preserved (`schema_version: 1`), with additive fields. Missing additions in older snapshots are shown as unavailable instead of reconstructed statistics.

## Root fields

| Field | Meaning |
| --- | --- |
| `session_id` | Identifier of this engine process, used to reset browser rate deltas. |
| `generated_at` | UTC snapshot time with millisecond resolution. This is not packet capture time. |
| `engine_state` | `running` or `stopped`. |
| `packets` | Successfully parsed frames in this engine run. |
| `bytes` | Original frame lengths when supplied by capture, otherwise captured lengths. |
| `parse_errors` | Frames the packet parser rejected; excluded from `packets`. |
| `protocols` | Packet counts for TCP, UDP, ICMP (including ICMPv6), ARP, and Other. |
| `connections` | Currently retained bidirectional IP flows; maximum 10,000. This is not a count of currently open sockets. |
| `dropped` | Packets matching policy. Offline export excludes them; live monitor mode only records the decision. |
| `capture_drops`, `processing_drops` | Npcap drop count and queue-full drop count respectively. |
| `flows` | Last 100 recorded flows, with classification evidence, policy, captured first/last timestamps in microseconds, packet count, and frame bytes. |
| `applications`, `domains` | Bounded hostname-evidence counts. DNS queries remain independent when a browser reuses one DNS socket for many sites. Known services receive friendly application labels; unfamiliar sites remain visible by hostname. Unnamed protocol traffic is also represented in `applications`. |
| `dns`, `http`, `alerts` | Bounded recent observations/events. Alerts are heuristics, not confirmed threats. Offline processing speed never produces a live traffic-rate alert. |
| `wfp` | Reported Windows filtering engine status and installed filter counts; not a per-packet denial receipt. |

`/data` adds `status`: `live` for fresh live telemetry, `stale` for old or undated snapshots, `offline` for a stopped engine or PCAP mode. Missing, invalid JSON, or invalid root telemetry returns HTTP 503 with `status: unavailable`. `/mode` and all existing rule/health routes remain available.

## `analysis` object

| Field | Meaning / retention |
| --- | --- |
| `recent_packets` | Latest 300 parsed packets, in processing order. |
| `capture_start_us`, `capture_end_us` | Earliest/latest frame timestamps in Unix microseconds. `null` until a packet is processed. |
| `capture_duration_ms` | Span between captured timestamps, not engine wall time. |
| `timeline` | Counts and bytes grouped into one-second capture intervals; latest 300 seconds. Gaps are shown as gaps, and the latest interval may be partial. |
| `size_distribution` | Exact counts over all parsed frames: 0–64, 65–128, 129–256, 257–512, 513–1024, 1025+ bytes. |
| `tracked_endpoints` | Unique IP addresses tracked, up to 4,096. |
| `top_talkers` | Top 20 tracked IPs by sent + received frame bytes, with separate sent/received packet and byte counts. The overview shows six. |
| `ports` | Top 20 transport protocol/port pairs by source + destination observations. The overview shows six. A packet contributes at each endpoint port. |
| `endpoints_limited`, `ports_limited` | True if new keys exceeded 4,096. Existing keys continue accumulating exact observations; the inventory is partial. |
| `packet_limit`, `timeline_seconds`, `aggregate_limit` | Explicit retention limits for clients. |

Packet records include a sequential **parsed-frame** ID, capture timestamp, original/captured lengths, Ethernet addresses/type, IP addresses/version/TTL or hop limit, protocol, transport ports, TCP flags/sequence/acknowledgment, payload length, directly observed application/name/method, and policy. Fields unavailable for that protocol are `null`. IDs reset with the engine session and are not byte offsets or original PCAP record numbers if earlier frames were rejected.

Packet payload bytes are not copied into telemetry. The packet inspector exposes the headers actually parsed. Selected packet/flow details are a stable snapshot; live updates do not silently replace the inspected record.

The dashboard does not archive live traffic. Offline source PCAPs remain available for older details; optional CLI PCAP export contains forwarded frames only. Demo servers add `data_source: synthetic_fixture` so the UI visibly distinguishes generated test frames from real traffic.

Hostname visibility depends on the protocols present in the capture. Plain DNS, HTTP Host, and an unencrypted TLS ClientHello SNI can provide a name. A reused connection may have completed its handshake before capture started. DNS-over-HTTPS, Encrypted Client Hello, and protected QUIC Initial packets can hide names from this passive analyzer. In those cases the system reports protocol/IP evidence instead of inventing a website name.

## Browser behavior

- Poll once per second after the preceding request completes; reduce polling while the tab is hidden. No overlapping telemetry requests.
- Update tables/charts only when a snapshot changes. Packet, flow, application, and domain tables use pagination.
- Calculate live packet rate from counter deltas and `generated_at`; restart the calculation after session changes or resume.
- Pause updates freezes the browser only. JSON export is the displayed snapshot; CSV export contains matching records in the retained packet window, with spreadsheet formula prefixes neutralized.
- The SVG graph uses recent flow endpoints and volumes, limited to 18 hosts and 40 links. Node position does not identify a physical device role; the central endpoint is the one with the most observed flow relationships.
- Health probes use at most four concurrent requests, a four-second request deadline, a ten-second result cache, and shared in-flight work. Configuration/rule changes invalidate cache selection.
