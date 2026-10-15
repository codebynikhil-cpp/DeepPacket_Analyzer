# DeepPacket Analyzer: improvement plan

## Goal

Turn the current packet analyzer into a reproducible, trustworthy final-year project that is easy to demonstrate and discuss in interviews. The release should show what the engine observed, how it classified a flow, whether a rule was actually enforced, and what the known limits are.

This document records the implementation plan and its current progress.

The expanded September 2026 implementation is documented in [PROJECT_AUDIT.md](PROJECT_AUDIT.md), with a reproducible walkthrough in [DEMO.md](DEMO.md). It includes a dark multi-view workspace, packet metadata inspection, bounded analytics, an observed-communication graph, locally served charts, and browser regression tests. Existing capture modes, API routes, and rule features remain available.

## Implementation status

The first implementation pass now includes localhost binding, a rule token for changes, input validation, safe dashboard rendering of captured text, atomic timestamped telemetry, live/stale/offline states, rule reload acknowledgement, a responsive layout, flow search and evidence details, full IPv6 address flow keys, bounded recent logs, parser bounds checks, automated API/offline-PCAP checks, and a reproducible offline benchmark. A five-second monitor-mode smoke test on interface 7 captured 57 packets with zero reported drops. The README and Windows setup guide have been updated. The remaining work is listed below: elevated WFP verification, broader protocol fixtures and classification accuracy measurement, demo recording, and optional add-ons. The original findings table records the baseline and should not be read as the current state of every item.

| Phase | Status | Evidence / remaining work |
| --- | --- | --- |
| 1. Baseline and docs | Implemented | Build, synthetic PCAP integration tests, revised README and setup guide. |
| 2. Control plane | Implemented for local use | Rule token, validation, safe rendering, atomic telemetry, state reporting, reload acknowledgement. Per-rule WFP denial receipts remain future work. |
| 3. Engine correctness | In progress | Automated checks cover HTTP, DNS, TLS SNI, IPv6, fragments, malformed headers, link types, rule matching, and API behavior. More real-world PCAPs and elevated WFP verification are needed. |
| 4. UI redesign | Implemented and browser-tested | Dark workspace, packet/flow inspection, search/filter/sort/pagination, timeline/protocol/size/endpoint/port views, communication graph, local assets, and exports. Browser scenarios pass at 360–1440 px. A target-user usability review remains. |
| 5. Explainable classification | First pass implemented | Flow evidence method, evidence strength, rule reason, and WFP engine state are shown. Confidence labels are qualitative, not calibrated scores. |
| 6. Measurement and presentation | In progress | Synthetic offline benchmark in `BENCHMARK.md`; demo recording and independently labeled accuracy sample remain. |

## Current baseline

The repository already contains:

- A C++17 engine with live capture and offline PCAP processing (`src/main.cpp`, `src/live_capture_source.cpp`, `src/pcap_reader.cpp`).
- Ethernet, IPv4/IPv6, TCP/UDP, DNS, HTTP Host, and TLS SNI parsing; flow tracking and application classification (`src/packet_parser.cpp`, `src/dpi_engine.cpp`, `src/connection_tracker.cpp`).
- IP, domain, application, and port rules, plus outbound IPv4 Windows Filtering Platform (WFP) enforcement (`src/rule_manager.cpp`, `src/wfp_enforcement.cpp`).
- A Node.js API and a dashboard showing metrics, flows, alerts, rules, and website health (`server.js`, `public/`).

The C++ target builds with `cmake --build build -j 2`. The saved `output.json` contains data from an earlier run, but it is not a substitute for a repeatable test. Live capture and WFP enforcement still need an explicit verification run.

### Gaps found in the source

| Priority | Finding | Required change |
| --- | --- | --- |
| P0 | Rule-changing endpoints in `server.js` have no authentication; CORS is broadly enabled. | Bind to localhost by default, restrict origins, protect writes, and validate all rule values. |
| P0 | `public/app.js` inserts packet, domain, health, and rule data into `innerHTML`. | Render untrusted values as text and remove inline event handlers. |
| P0 | `output.json` is written directly while Node reads it; the dashboard shows the browser's current time as its last update. | Write a complete snapshot atomically, include an engine timestamp, and show live/stale/offline state accurately. |
| P1 | The README describes the queue as lock-free, but `include/packet_queue.h` uses a mutex. | Correct the architecture description; retain the queue unless measurement shows it is a bottleneck. |
| P1 | QUIC SNI extraction in `src/sni_extractor.cpp` is a byte-pattern shortcut. | Mark QUIC domain extraction unsupported until a proper QUIC Initial decoder is implemented and tested. Keep QUIC protocol detection separate. |
| P1 | IPv6 addresses are displayed as `IPv6` and tracking uses only part of each address; WFP filters use the V4 layer. | Parse/store full IPv6 addresses and label enforcement as IPv4-only until V6 filters are implemented. |
| P1 | `package.json` has a placeholder `npm test`; no checked-in test captures are present. | Add deterministic packet fixtures and automated engine/API checks. |
| P1 | `WINDOWS_SETUP.md` contains old filenames and build commands. | Replace with one verified Windows setup path and a short troubleshooting section. |
| P2 | Dashboard layout has fixed desktop columns and no responsive breakpoints. | Redesign page hierarchy and mobile/tablet layouts. |

The word **blocked** must be used carefully throughout the product: a packet rejected during offline PCAP filtering, a rule matched in monitor mode, and a connection denied by an active WFP filter are different outcomes.

## Release scope and order

### Phase 1 — Reproducible baseline and truthful documentation (about 1 week)

**Changes**

1. Define a telemetry contract: packet count, bytes, packet rate, capture drops, processing drops, flow count, classification method, policy match, and WFP state. Define units and when each counter resets.
2. Add a small redistributable PCAP fixture set containing DNS, HTTP, TLS ClientHello, malformed/truncated packets, IPv4, and IPv6. Keep any real-world capture with personal traffic out of the repository.
3. Add a command that runs offline analysis against the fixtures and checks expected JSON fields and counts.
4. Update `README.md` and `WINDOWS_SETUP.md` to match the current executable, flags, dependencies, queue design, QUIC status, and WFP scope.

**Done when:** a reviewer can clone, build, run the fixture analysis, and reproduce the documented output without live network access.

### Phase 2 — Secure and reliable control plane (about 1–2 weeks)

**Changes**

1. In `server.js`, bind to `127.0.0.1` by default and make the host/port configurable. Remove broad CORS unless a separate frontend origin is needed.
2. Require an administrator secret or authenticated local session for `POST /rules` and `DELETE /rules`. Keep read-only dashboard access a separate policy decision.
3. Validate and normalize rule input on the server: IPv4 format, domain/wildcard syntax, known app names, and integer ports from 1 to 65535. Reject unsupported or malformed values with useful errors. Limit request size.
4. Replace rule UI inline handlers and all insertion of captured strings into HTML with DOM text nodes or a trusted escaping function. Make buttons disable while a save is in progress.
5. Write telemetry to a temporary file and atomically replace `output.json`; add `generated_at`, engine status, and schema version. Have `/data` report missing, malformed, and stale snapshots explicitly.
6. Show rule lifecycle in the API/UI: **saved**, **loaded by engine**, and **enforced by WFP**. Do not report enforcement merely because a rule was saved.

**Done when:** malformed rules are rejected; injected HTML is displayed as text; a stopped engine is visibly stale; a monitor-only session never claims that WFP blocked a connection.

### Phase 3 — Engine correctness and tests (about 1–2 weeks)

**Changes**

1. Add parser tests for short headers, invalid lengths, IPv4 fragmentation, TCP options, IPv6 extension headers, and DNS name compression. Fix issues the fixtures expose.
2. Preserve full IPv6 source/destination addresses in parsed packets and flow keys. Keep IPv6 enforcement disabled and clearly marked until the V6 path is implemented.
3. Test rule matching and reload, including wildcard boundaries, overlapping domain/IP rules, duplicate rules, and removal of the last WFP reference.
4. Replace the QUIC SNI shortcut with an explicit `unknown` classification. A correct QUIC Initial decoder can be a later feature if there is time for standards-based parsing and fixtures.
5. Add API tests for read-only data access, valid/invalid rule changes, unauthorized requests, and corrupted or absent telemetry.
6. Run one controlled Windows live-capture and WFP test. Record OS version, Npcap setup, privileges, commands, observed result, and cleanup behavior.

**Done when:** the automated checks pass with one command, malformed packets do not crash the engine, and the WFP demo distinguishes rule matches from confirmed enforcement.

### Phase 4 — UI redesign (about 1–2 weeks)

Use the existing HTML/CSS/JavaScript first. Introduce a frontend framework only if state management becomes difficult after the data contract is stable.

**Information architecture**

| View | Purpose | Main elements |
| --- | --- | --- |
| Overview | Know whether the system is working and what changed. | Capture source, actual update time, mode/WFP state, packets per second, active flows, drops, blocked outcomes, throughput chart. |
| Flows | Investigate traffic. | Search, filters for time/protocol/application/decision, sortable columns, detail drawer. |
| Rules | Change policy safely. | Validated form, active rules table, applied/enforced state, errors, removal confirmation. |
| Alerts | Explain actionable events. | Severity, timestamp, affected flow, reason, link to flow detail. |
| Diagnostics | Explain project limits and health. | Engine/API status, queue depth, capture drops, WFP status, version, last error. |

**Visual and interaction changes**

1. Set a consistent type scale, spacing scale, colors, button styles, and status badges. Use color and text together for status.
2. At narrow widths, collapse navigation, stack metric cards, and let large tables scroll horizontally or switch to compact rows. Check 360 px, 768 px, and 1440 px widths.
3. Add visible keyboard focus, labeled controls, table headers, useful loading/empty/error states, and reduced-motion handling. Target WCAG 2.2 AA where applicable.
4. Keep the chart time axis tied to engine timestamps. Pause or mark the chart stale when telemetry stops; do not append zeroes that look like real observations.
5. Avoid re-rendering every large table every 500 ms. Update changed metrics and rows only, or use a slower bounded refresh for tables.

**Done when:** a reviewer can see capture status, locate one flow, inspect its evidence, and manage one rule on desktop and mobile using keyboard or pointer.

### Phase 5 — One standout add-on: explainable classification (about 1 week)

Add per-flow evidence so the product can explain its conclusions:

```text
Flow → observed domain/application → evidence source → confidence → matching rule → actual enforcement state
```

Evidence source should be one of `TLS SNI`, `HTTP Host`, `DNS correlation`, `port heuristic`, or `unknown`. Record the observation timestamp and distinguish a directly observed domain from one inferred using a DNS-to-IP association. Start with explicit confidence levels based on the method and known limits; do not present them as calibrated probabilities without measurement.

**Done when:** clicking a flow shows why it was classified and whether a rule was only matched, saved, or enforced.

### Phase 6 — Measurements and portfolio presentation (about 1 week)

1. Measure packet rate, CPU, memory, queue depth, processing drops, and output-file size on at least two fixture sizes. Record machine details and exact commands.
2. Manually label a sample of flows and publish a classification table: correct, incorrect, and unknown, grouped by evidence method. Report unknowns rather than excluding them.
3. Add architecture and data-flow diagrams, a short demo video or GIF, UI screenshots, and a clear limitations section to the README.
4. Prepare a five-minute demo: offline fixture analysis → investigate a flow → create a rule → show reload/enforcement status → show measured results.

**Done when:** a company reviewer can reproduce the demo and understand both the results and their limits.

## Optional add-ons after the release is solid

| Add-on | Value | Prerequisite |
| --- | --- | --- |
| Historical sessions and export to CSV/JSON | Compare captures and share findings. | Stable telemetry schema and privacy controls. |
| Rule simulation / dry run | Preview which observed flows a rule would affect. | Correct flow evidence and rule matching tests. |
| IPv6 WFP enforcement | Closes a real coverage gap. | Full IPv6 flow representation and controlled V6 tests. |
| Proper QUIC Initial inspection | Improves HTTP/3 visibility. | Standards-based parsing and reproducible QUIC fixtures. |
| Anomaly detection | Adds research scope. | Labeled data, a baseline, and false-positive evaluation. |

Recommended order: **rule simulation**, then **historical sessions**, then **IPv6 enforcement**. QUIC and anomaly detection are larger research tasks; keep them outside the first polished release unless the core phases finish early.

## Suggested implementation sequence in the repository

1. `README.md`, `WINDOWS_SETUP.md`, fixture directory, test runner.
2. `src/stats_collector.cpp` and telemetry schema; then `server.js` reading and status responses.
3. `server.js` rule validation/authentication; then `public/app.js` safe rendering and rule feedback.
4. `src/packet_parser.cpp`, flow keys, `src/sni_extractor.cpp`, and engine tests.
5. `public/index.html`, `public/style.css`, `public/app.js` redesign.
6. Classification evidence fields in the C++ engine, telemetry, API, and flow detail UI.
7. Benchmarks, screenshots, demo script, and final README.

## Decisions used for this implementation

The implementation uses a **local-only application**, **plain HTML/CSS/JavaScript for the UI**, and **explainable classification as the main add-on**. QUIC SNI is labeled unsupported. Before a public demonstration, review the UI with a target user, label a diverse accuracy sample, and verify WFP with an elevated Windows session.
