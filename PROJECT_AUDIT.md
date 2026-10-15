# DeepPacket Analyzer audit and implementation record

Audit started 2026-09-29; implementation verified 2026-09-30. This builds on the previous improvements; existing local changes are retained.

## Architecture inspected

| Component | Entry point | Responsibility |
| --- | --- | --- |
| C++17 engine | `src/main.cpp`, `CMakeLists.txt` | Offline PCAP or live Npcap input, parse, classify, match rules, optional filtered PCAP output. |
| Live capture | `src/live_capture_source.cpp`, `include/packet_queue.h` | Producer/consumer queue, bounded at 10,000 frames, capture/processing drop counters. |
| Parsing and classification | `src/packet_parser.cpp`, DNS/HTTP/SNI parsers, `src/dpi_engine.cpp` | Ethernet, IPv4/IPv6, transport headers, visible application evidence. No stream reassembly or encrypted payload inspection. |
| Flow and policy | `src/connection_tracker.cpp`, `src/rule_manager.cpp`, `src/wfp_enforcement.cpp` | Bidirectional flows, DNS correlation, rules, outbound IPv4 WFP integration. |
| Storage | `output.json`, `rules.json`, `critical_websites.json` | Local files; no database. Telemetry is atomically replaced. |
| API | `server.js` | Express, localhost by default, authenticated rule writes, telemetry and health endpoints. |
| Browser | `public/index.html`, `public/style.css`, `public/app.js` | Plain JavaScript, Chart.js via CDN, periodic API reads, flows/rules/alerts/health. |

Existing routes: `/`, `/data`, `/mode`, `/rules` (GET/POST/DELETE), `/rules/status`, `/critical-websites`, `/health`. CLI capture controls and filtered PCAP export must remain available.

## Baseline verification

- Nine existing API and offline engine tests pass.
- The dashboard starts and renders existing saved capture data in Chrome without page errors.
- The existing saved capture is old and has no engine timestamp; the dashboard correctly reports stale data.
- A desktop screenshot was captured locally in `artifacts/before-desktop.png` (ignored runtime artifact).
- No browser start/stop capture API exists. A pause button must pause dashboard updates only and say so.
- Existing telemetry has counters and 100 recent flows, but no individual packet records, port totals, packet size histogram, or capture timeline. These must be measured by the engine before displaying them.

## Confirmed defects / gaps

1. Rule and website configuration readers scan lines instead of parsing JSON. Compact JSON is not handled correctly. Rule reload clears existing rules before confirming that the replacement is valid.
2. Filtered PCAP output writes an uninitialized global header, making the export unreliable.
3. Health checks run sequentially and concurrent dashboard requests can repeat the same probes. Rule changes do not invalidate the cache.
4. Charts depend on an unpinned external CDN; a chart load failure prevents the rest of the polling code from starting.
5. The dashboard renders entire tables every 500 ms and has no pagination, packet inspector, chart range control, or endpoint exploration.
6. Flow protocol labels default to ICMP for unrecognized IP protocols. Flow records do not expose packet/byte totals even though the engine sees each frame.
7. Packet rate history exists only in the browser and is unavailable for completed PCAP analysis. Engine timestamps have one-second resolution.
8. The README describes a classification cache in FastPath; the implementation is a payload/port eligibility check.

## Implementation approach

First fix configuration loading, export, and health checks. Extend telemetry additively with bounded packet metadata, observed traffic buckets, endpoint/port aggregates, frame sizes, capture span, and flow counters. Keep every current API and CLI mode. Build a consistent dark interface with modular vanilla JavaScript and locally served Chart.js, a paginated packet explorer, packet/flow detail drawer, and an SVG communication graph derived from captured flows. The graph describes observed communication, not physical topology.

Use engine-generated fixtures and real local capture checks for verification. Browser tests must exercise filters, charts, details, rules, exports, empty/stale/error states, and desktop/mobile layouts. Label synthetic test captures explicitly and keep personal live-capture screenshots out of tracked documentation.

## Known boundaries

Production readiness requires more than appearance. WFP enforcement needs a controlled elevated Windows verification; this session must not claim per-flow Windows denial from packet telemetry. QUIC SNI, TLS decryption, TCP reassembly, historical storage, and browser capture control remain outside the existing supported feature set. Classification labels are evidence categories, not calibrated probabilities.

## Delivered changes

- Preserved every existing API route, CLI capture mode, application/domain view, rule type, website health view, DNS/HTTP observation, alert view, and filtered-PCAP output.
- Fixed JSON configuration parsing, invalid replacement policy handling, PCAP output headers, repeated health probes, misleading protocol evidence labels, unknown flow protocol labels, and offline processing-speed alerts. Rule revision notifications and acknowledgments now use atomic file replacement; revision polling provides a fallback when reload notifications overlap.
- Added measured metadata and bounded aggregates through `TrafficAnalytics`, plus flow frame/byte totals and parse-error counters. No raw payload bytes are retained in dashboard telemetry.
- Replaced the light, long dashboard with a dark workspace using separate views, bounded tables, a native accessible inspection dialog, clear statuses, and local chart assets.
- Added capture-time timeline controls, protocol click-to-filter, endpoint and port exploration, packet size distribution, an interactive SVG communication graph, JSON snapshot export, and filtered CSV metadata export.
- Added a labeled synthetic demo, browser automation, mixed-traffic fixtures, documentation screenshots, an executable path resolver, and repeatable Release benchmarks.

## Dependencies

- **Chart.js 4.5.1:** the existing chart library is now a pinned local runtime dependency instead of an unpinned CDN script.
- **nlohmann/json 3.12.0:** vendored MIT-licensed C++ header for actual JSON configuration parsing and structured analytics output.
- **Playwright:** development-only browser testing using installed Chrome on this Windows machine. No frontend framework or 3D runtime was added.

## Verification evidence

- Release C++ build passes with MinGW GCC 15.2.0.
- `npm test`: 14 engine/API/analytics checks pass, none skipped. The additional hostname tests verify that reused DNS flows retain multiple sites and that short brand domains do not match inside unrelated hostnames.
- `npm run test:ui`: seven browser scenarios pass, covering chart and graph interaction, filters, sorting, pagination, packet/flow details, CSV/JSON exports, rule writes, pause/resume, stale/unavailable/legacy snapshots, missing chart assets, and widths 360/390/768/1024/1440 px. The ordinary overview run reports no browser errors or external asset requests.
- Five-second Npcap monitor check on the enumerated WiFi adapter (index 6 for this run): 9 parsed packets, 0 capture drops, 0 queue drops, 0 parse errors, 9 retained packet records, and a successful rule-revision acknowledgment. WFP remained inactive.
- A 100,000-packet mixed synthetic Release run took 2,150 ms and emitted 209,967 bytes of telemetry with bounded retention. See `BENCHMARK.md` for methods and limitations.
- `npm audit` reports zero known npm dependency vulnerabilities; this is not a complete security assessment.

Remaining verification: elevated WFP behavior, independent classification accuracy labels, cross-platform builds/browsers, and production load testing. Application-name mappings remain domain heuristics; direct-name evidence must not be presented as proof that every friendly application label is correct.
