# Windows setup

## Prerequisites

- Windows 10 or 11.
- A C++17 compiler and CMake 3.16 or newer. Visual Studio 2022 with the **Desktop development with C++** workload or MinGW-w64 can be used.
- Node.js 20 or newer.
- Npcap for live packet capture. Install its WinPcap-compatible API mode if your setup requires it.

Offline PCAP analysis and the dashboard can be used without Npcap. WFP protect mode requires an elevated terminal. Live capture permissions depend on the Npcap installation.

## Build and check

From the repository directory in PowerShell:

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
npm install
npm test
npm run test:ui
```

The executable may be `build\PacketInspector.exe` with a single-configuration generator or `build\Release\PacketInspector.exe` with Visual Studio. The test and demo scripts search these locations; `DPA_ENGINE_PATH` can override them. Browser tests use installed Chrome on Windows. Set `DPA_BROWSER=msedge` to use installed Edge instead.

## Run the dashboard and analyzer

Start the dashboard in one terminal:

```powershell
$env:DPA_RULE_TOKEN = 'choose-a-private-token'
npm start
```

Open `http://127.0.0.1:3000`. The server listens on localhost by default. Enter the token in the **Management token** field in Firewall rules before adding or removing rules. If `DPA_RULE_TOKEN` is unset, the server generates a token and prints it in the terminal. The browser keeps it only in the current page.

For an isolated offline demonstration, run `npm run demo` and open `http://127.0.0.1:3001`. It uses an explicitly synthetic capture, runs without Npcap or elevation, and keeps demonstration files in `artifacts/demo`.

In another terminal, list capture interfaces:

```powershell
.\build\PacketInspector.exe --list-interfaces
```

Start monitor mode with the appropriate interface index:

```powershell
.\build\PacketInspector.exe --interface 1
```

For protect mode, open PowerShell as Administrator and run:

```powershell
.\build\PacketInspector.exe --interface 1 --protect
```

The dashboard distinguishes WFP active from monitor only. A saved rule or packet rule match alone is not proof that Windows denied a connection. WFP enforcement currently covers outbound IPv4 connections; existing connections may remain open after a rule is added.

Run an offline capture without elevation:

```powershell
.\build\PacketInspector.exe --pcap .\capture.pcap
```

The analyzer writes `output.json` in its current working directory. Start it from the repository root if you want the dashboard server to read that file.

## If something fails

- **Executable not found:** check whether CMake placed it in `build\Release` instead of `build`.
- **No interfaces:** verify Npcap is installed and run `--list-interfaces` again.
- **WFP inactive:** run the analyzer from an elevated terminal and read `wfp.status` in `output.json`.
- **Dashboard says stale:** check that the analyzer is running and that both processes use the repository directory. A finished offline analysis is correctly shown as offline.
- **Rule change says unauthorized:** enter the token printed by `npm start`, or set `DPA_RULE_TOKEN` before launching it.
- **Packet explorer says metadata unavailable:** rebuild and rerun the engine. Old snapshots still support aggregate views but do not contain the new packet metadata.
- **Charts unavailable:** run `npm ci` and restart the Node server so `/vendor/chart.js` is served locally.
- **Dashboard updates paused:** click Resume updates. This control does not start or stop the capture process.
