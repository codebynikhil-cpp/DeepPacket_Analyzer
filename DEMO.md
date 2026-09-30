# Demonstrating DeepPacket Analyzer

## Reproducible offline walkthrough

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j 2
npm ci
npm test
npm run test:ui
npm run demo
```

Open **http://127.0.0.1:3001**. The capture is intentionally synthetic and named `synthetic-demo.pcap`. Its documentation-only IP addresses and HTTP/TLS/DNS/TCP/UDP/ICMP frames are generated locally, then processed by the real engine. The dashboard never substitutes invented statistics for missing data.

1. **Overview:** explain offline status, packet/byte totals, capture span, and the timeline's capture timestamps. Switch packets to bytes and change the time range.
2. **Protocol mix:** select UDP to jump to matching packets. Filter port 53, inspect a packet, and expand the actual captured headers.
3. **Packet explorer:** clear filters, sort a column, change pages, search `github.com`, and export the filtered metadata as CSV. Explain the latest-300-packet retention boundary.
4. **Connections:** inspect a flow's domain, evidence method, packet/byte totals, and policy. Use View related packets. Only packets still in the retained window can appear.
5. **Graph and top talkers:** zoom/pan the communication graph or select a host. Explain that links come from observed flows and are not a physical network map.
6. **Rules:** use the token printed by the demo server (`synthetic-demo-only` by default). Add `*.example.com` and show Saved / awaiting engine reload. The offline demo engine has already exited, so this does not demonstrate live reload or enforcement. Remove the rule afterward.
7. **Diagnostics:** show retention limits and the distinction between observed policy matches and Windows filtering enforcement.

The demo runs isolated files under `artifacts/demo` and never alters normal capture/rule files. Stop with Ctrl+C. Running it again resets its own sample data and policy. `npm start` serves your normal `output.json` on port 3000.

## Live monitor walkthrough

List interfaces and select the active adapter; interface numbers can change:

```powershell
.\build\PacketInspector.exe --list-interfaces
.\build\PacketInspector.exe --interface 6
```

Start `npm start` separately and open http://127.0.0.1:3000. Inspect your own permitted traffic. The dashboard's Pause updates button freezes the view; stop the capture in its terminal.

`npm run smoke:live -- 6` runs a five-second monitor check in a temporary workspace and verifies that a harmless test rule revision is acknowledged. It installs no WFP filters. Live capture permissions depend on your Npcap setup.

## What the current evidence supports

The project demonstrates native packet parsing, bounded telemetry, a local control API, visible classification evidence, responsive interactive analysis, automated browser/API/engine checks, and reproducible measurements. It has not established calibrated classification accuracy or general production capacity. WFP protect mode still needs an elevated, controlled validation before presenting enforcement as verified.

Screenshots in `docs/images` use the synthetic fixture. They are safe to share without publishing personal network captures.
