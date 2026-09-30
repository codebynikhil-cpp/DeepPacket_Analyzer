# Offline benchmark baseline

Run `npm run benchmark` and `npm run benchmark:mixed` after building `PacketInspector`. The scripts create PCAPs in a temporary directory, process them with the local executable, verify packet counts, and delete their own temporary files. Fixture generation is excluded from the elapsed times below. Wall time includes process startup, telemetry output, and shutdown.

## Release measurement on 2026-09-30

Environment: Windows 11 Home Single Language (10.0.26200), Intel Core i5-12450HX, 12 logical processors, approximately 16 GB RAM, Node.js 24.16.0, MinGW GCC 15.2.0. Configured with `cmake -S . -B build -DCMAKE_BUILD_TYPE=Release`, then `cmake --build build -j 2`. Includes the new packet metadata and aggregate collection. Earlier results used an unoptimized build and should not be compared as equivalent configurations.

| Synthetic packets | Wall time | Approximate packets/s | Processing drops |
| ---: | ---: | ---: | ---: |
| 1,000 | 582 ms | 1,718 | 0 |
| 10,000 | 583 ms | 17,159 | 0 |
| 50,000 | 1,091 ms | 45,845 | 0 |

The first fixture repeats one IPv4 HTTP flow, so it exercises an easy classification mix.

## Mixed synthetic capture

`npm run benchmark:mixed` combines HTTP Host, TLS SNI, DNS, TCP data/ACK, UDP, and ICMP frames with varied frame lengths and flow endpoints. It is deterministic test data, not a recording of real traffic or an accuracy dataset.

| Packets | Wall time | Approximate packets/s | Parse errors | JSON snapshot bytes |
| ---: | ---: | ---: | ---: | ---: |
| 10,000 | 625 ms | 15,998 | 0 | 209,335 |
| 100,000 | 2,150 ms | 46,510 | 0 | 209,967 |

Both mixed runs retain 300 packet records, 100 recent flow records, and at most 300 timeline buckets. This shows that the browser payload stays bounded for these fixtures; it is not a peak-process-memory measurement.

These results do **not** establish live capture capacity, WFP enforcement latency, CPU or peak memory limits, or classification accuracy on diverse real traffic. The rule-reload thread's shutdown interval and process startup dominate small captures. Repeat measurements on a controlled machine and report the exact workload and build mode before quoting throughput in a resume or presentation.
