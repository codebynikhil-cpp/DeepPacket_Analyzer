#!/usr/bin/env python3
"""
PCAP Ground-Truth Dataset Generator
Generates labeled network traffic (PCAP) and corresponding ground_truth.csv
for evaluating DeepPacket-Analyzer's classification and disambiguation engines.

Features:
- Queries/generates traffic for top 20 domains
- Generates DNS queries & answers (testing ProbabilisticDnsCache)
- Generates TLS Client Hellos with SNI extension
- Generates multi-segment (fragmented) TLS Client Hellos (testing TcpReassembler)
- Outputs:
    1. ground_truth.pcap (standard libpcap format)
    2. ground_truth.csv (src_ip, dst_ip, dst_port, true_domain, protocol, timestamp)
- Supports live capture (--live) with requests, and standalone synthetic generation (--synthetic, default)
"""

import os
import sys
import time
import socket
import argparse
import csv
import struct
import random

# Top 20 domains for research dataset
TOP_DOMAINS = [
    "google.com",
    "youtube.com",
    "github.com",
    "stackoverflow.com",
    "wikipedia.org",
    "microsoft.com",
    "amazon.com",
    "cloudflare.com",
    "reddit.com",
    "netflix.com",
    "linkedin.com",
    "bing.com",
    "twitch.tv",
    "twitter.com",
    "instagram.com",
    "mozilla.org",
    "yahoo.com",
    "spotify.com",
    "adobe.com",
    "apple.com"
]

def parse_args():
    parser = argparse.ArgumentParser(description="Generate labeled PCAP and ground_truth.csv dataset")
    parser.add_argument("--output-pcap", "-p", default="ground_truth.pcap", help="Output PCAP file")
    parser.add_argument("--output-csv", "-c", default="ground_truth.csv", help="Output ground truth CSV file")
    parser.add_argument("--live", action="store_true", help="Perform live HTTP/HTTPS requests and packet capture")
    parser.add_argument("--interface", "-i", default=None, help="Network interface for live capture")
    parser.add_argument("--split-tls-ratio", type=float, default=0.25, help="Proportion of TLS flows split across 2 TCP segments (0.0 - 1.0)")
    parser.add_argument("--dns-correlation-ratio", type=float, default=0.30, help="Proportion of flows where TLS SNI is omitted to evaluate DNS Correlation fallback")
    return parser.parse_args()

def ip_checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while (s >> 16) > 0:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def build_dns_query(domain: str, txid: int = 0x1234) -> bytes:
    """Builds a DNS A-record query payload (UDP payload)"""
    parts = domain.strip().split(".")
    qname = b""
    for part in parts:
        bpart = part.encode("ascii")
        qname += struct.pack("!B", len(bpart)) + bpart
    qname += b"\x00"
    # Header: txid, flags=0x0100 (standard query), qdcount=1, ancount=0, nscount=0, arcount=0
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    # Question: qtype=1 (A), qclass=1 (IN)
    question = qname + struct.pack("!HH", 1, 1)
    return header + question

def build_dns_response(domain: str, ip_str: str, ttl: int = 300, txid: int = 0x1234) -> bytes:
    """Builds a DNS A-record response payload (UDP payload)"""
    query_payload = build_dns_query(domain, txid)
    # Change flags to response (0x8180: Standard query response, No error)
    header = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    question = query_payload[12:]
    
    # Answer section: pointer to question name (0xc00c), type A (1), class IN (1), ttl, data_len 4, IPv4 bytes
    ip_bytes = socket.inet_aton(ip_str)
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, ttl, 4) + ip_bytes
    return header + question + answer

def build_tls_client_hello(domain: str) -> bytes:
    """Constructs a standard TLS 1.2/1.3 Client Hello with SNI extension"""
    host_bytes = domain.encode("ascii")
    # SNI extension
    sni_entry = struct.pack("!BH", 0, len(host_bytes)) + host_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    
    # Supported versions extension (TLS 1.3 / 1.2)
    supp_vers_data = b"\x02\x03\x04\x03\x03"
    supp_vers_ext = struct.pack("!HH", 0x002B, len(supp_vers_data)) + supp_vers_data
    
    extensions = sni_ext + supp_vers_ext
    extensions_block = struct.pack("!H", len(extensions)) + extensions
    
    client_version = b"\x03\x03" # TLS 1.2
    random_bytes = os.urandom(32)
    session_id = b"\x00" # Length 0
    cipher_suites = struct.pack("!H", 4) + b"\x13\x01\x13\x02" # TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
    compression_methods = b"\x01\x00"
    
    body = client_version + random_bytes + session_id + cipher_suites + compression_methods + extensions_block
    # Handshake header: type 0x01 (Client Hello), 3-byte length
    handshake_len = len(body)
    handshake_header = bytes([1, (handshake_len >> 16) & 0xFF, (handshake_len >> 8) & 0xFF, handshake_len & 0xFF])
    handshake = handshake_header + body
    
    # Record header: type 0x16 (Handshake), version 0x0301 (TLS 1.0), 2-byte length
    record = struct.pack("!BHH", 0x16, 0x0301, len(handshake)) + handshake
    return record

def build_ipv4_packet(src_ip: str, dst_ip: str, protocol: int, payload: bytes,
                      src_port: int, dst_port: int, seq: int = 1000, ack: int = 0,
                      tcp_flags: int = 0x18) -> bytes:
    """Builds a complete Ethernet + IPv4 + (TCP or UDP) frame"""
    eth_header = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"
    
    if protocol == 6: # TCP
        tcp_len = 20 + len(payload)
        data_offset = (5 << 4) # 20 bytes header
        tcp_header_no_cksum = struct.pack("!HHIIBBHHH",
                                          src_port, dst_port,
                                          seq, ack,
                                          data_offset, tcp_flags,
                                          64240, 0, 0)
        transport = tcp_header_no_cksum + payload
    elif protocol == 17: # UDP
        udp_len = 8 + len(payload)
        udp_header = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
        transport = udp_header + payload
    else:
        transport = payload
        
    total_len = 20 + len(transport)
    ip_hdr_no_cksum = struct.pack("!BBHHHBBH4s4s",
                                  0x45, 0, total_len,
                                  random.randint(1000, 65000), 0x4000,
                                  64, protocol, 0,
                                  socket.inet_aton(src_ip),
                                  socket.inet_aton(dst_ip))
    cksum = ip_checksum(ip_hdr_no_cksum)
    ip_header = struct.pack("!BBHHHBBH4s4s",
                            0x45, 0, total_len,
                            random.randint(1000, 65000), 0x4000,
                            64, protocol, cksum,
                            socket.inet_aton(src_ip),
                            socket.inet_aton(dst_ip))
    return eth_header + ip_header + transport

def write_pcap_file(filepath: str, packets: list):
    """Writes list of (timestamp_sec, timestamp_usec, packet_bytes) to a standard PCAP file"""
    with open(filepath, "wb") as f:
        # PCAP Global Header (24 bytes)
        # magic_number: 0xa1b2c3d4, version 2.4, thiszone 0, sigfigs 0, snaplen 65535, linktype 1 (Ethernet)
        f.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        
        for ts_sec, ts_usec, pkt in packets:
            incl_len = len(pkt)
            orig_len = len(pkt)
            hdr = struct.pack("!IIII", ts_sec, ts_usec, incl_len, orig_len)
            f.write(hdr)
            f.write(pkt)

def run_synthetic_dataset(output_pcap: str, output_csv: str, split_tls_ratio: float = 0.25, dns_correlation_ratio: float = 0.30):
    print(f"[*] Generating synthetic labeled dataset for {len(TOP_DOMAINS)} domains...")
    client_ip = "192.168.1.100"
    dns_server_ip = "8.8.8.8"
    
    packets = []
    csv_rows = []
    
    base_time = int(time.time()) - 3600
    us_offset = 0
    
    # Deterministic mapping for top domains to unique IPs (and a couple shared multi-tenant CDN IPs!)
    ip_map = {}
    shared_cdn_ip = "104.21.48.12" # Cloudflare shared IP for multi-domain cache testing
    
    for idx, domain in enumerate(TOP_DOMAINS):
        if idx in (7, 8): # cloudflare.com, reddit.com share CDN IP
            ip_map[domain] = shared_cdn_ip
        else:
            ip_map[domain] = f"142.250.{100 + idx}.{10 + idx}"
            
    client_port = 45000
    
    for idx, domain in enumerate(TOP_DOMAINS):
        dest_ip = ip_map[domain]
        dest_port = 443
        client_port += 1
        
        # 1. DNS Query Packet (Client -> DNS Server UDP 53)
        dns_q = build_dns_query(domain, txid=0x1000 + idx)
        q_pkt = build_ipv4_packet(client_ip, dns_server_ip, 17, dns_q, client_port, 53)
        packets.append((base_time, us_offset, q_pkt))
        us_offset += 2000
        
        # 2. DNS Response Packet (DNS Server -> Client UDP 53)
        dns_r = build_dns_response(domain, dest_ip, ttl=300, txid=0x1000 + idx)
        r_pkt = build_ipv4_packet(dns_server_ip, client_ip, 17, dns_r, 53, client_port)
        packets.append((base_time, us_offset, r_pkt))
        us_offset += 5000
        
        # Log ground-truth row for the upcoming TLS session
        ts_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(base_time))
        csv_rows.append({
            "timestamp": ts_str,
            "src_ip": client_ip,
            "src_port": client_port,
            "dst_ip": dest_ip,
            "dst_port": dest_port,
            "true_domain": domain,
            "protocol": "TCP/TLS"
        })
        
        # 3. TLS Traffic
        # Some flows use DNS correlation fallback (e.g. encrypted session without cleartext SNI)
        use_dns_correlation = (idx % int(1.0 / max(dns_correlation_ratio, 0.05))) == 0 if dns_correlation_ratio > 0 else False
        
        seq_start = 100000 + (idx * 5000)

        if use_dns_correlation:
            # TLS Application Data (0x17 0x03 0x03) - no SNI in payload
            app_data = b"\x17\x03\x03\x00\x20" + os.urandom(32)
            pkt = build_ipv4_packet(client_ip, dest_ip, 6, app_data, client_port, dest_port,
                                    seq=seq_start, tcp_flags=0x18)
            packets.append((base_time, us_offset, pkt))
            us_offset += 12000
        else:
            tls_payload = build_tls_client_hello(domain)
            
            # Test TCP Reassembler: Should this flow be split across two packets?
            should_split = (idx % int(1.0 / max(split_tls_ratio, 0.05))) == 0 if split_tls_ratio > 0 else False
            
            if should_split and len(tls_payload) > 40:
                # Split point in the middle of Client Hello
                split_pos = 28
                seg1 = tls_payload[:split_pos]
                seg2 = tls_payload[split_pos:]
                
                pkt1 = build_ipv4_packet(client_ip, dest_ip, 6, seg1, client_port, dest_port,
                                         seq=seq_start, tcp_flags=0x18) # PSH+ACK
                packets.append((base_time, us_offset, pkt1))
                us_offset += 3000
                
                pkt2 = build_ipv4_packet(client_ip, dest_ip, 6, seg2, client_port, dest_port,
                                         seq=seq_start + split_pos, tcp_flags=0x18)
                packets.append((base_time, us_offset, pkt2))
                us_offset += 10000
            else:
                # Single complete segment
                pkt = build_ipv4_packet(client_ip, dest_ip, 6, tls_payload, client_port, dest_port,
                                        seq=seq_start, tcp_flags=0x18)
                packets.append((base_time, us_offset, pkt))
                us_offset += 12000
            
        if us_offset >= 1000000:
            base_time += us_offset // 1000000
            us_offset = us_offset % 1000000

    # Write PCAP
    write_pcap_file(output_pcap, packets)
    print(f"[+] Wrote {len(packets)} packets to {output_pcap}")
    
    # Write CSV
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "true_domain", "protocol"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)
    print(f"[+] Wrote {len(csv_rows)} labeled ground-truth records to {output_csv}")

def run_live_capture(output_pcap: str, output_csv: str, interface=None):
    try:
        import requests
        from scapy.all import AsyncSniffer, wrpcap
    except ImportError as e:
        print(f"[!] Live capture dependencies missing ({e}). Falling back to synthetic generation.")
        run_synthetic_dataset(output_pcap, output_csv)
        return

    print(f"[*] Initializing live packet sniffer on interface: {interface or 'default'}...")
    try:
        sniffer = AsyncSniffer(iface=interface, filter="tcp port 443 or udp port 53", count=500, timeout=25)
        sniffer.start()
        time.sleep(1)
    except Exception as err:
        print(f"[!] Could not start live sniffer ({err}). Note: Administrator/Npcap permissions required.")
        print("[*] Falling back to synthetic wire-accurate PCAP generator.")
        run_synthetic_dataset(output_pcap, output_csv)
        return

    csv_rows = []
    print("[*] Sending HTTP/HTTPS requests to target domains...")
    for dom in TOP_DOMAINS:
        url = f"https://{dom}"
        try:
            # Resolve IP
            dest_ip = socket.gethostbyname(dom)
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            csv_rows.append({
                "timestamp": ts,
                "src_ip": "local",
                "src_port": 0,
                "dst_ip": dest_ip,
                "dst_port": 443,
                "true_domain": dom,
                "protocol": "TCP/TLS"
            })
            requests.get(url, timeout=2, headers={"User-Agent": "Mozilla/5.0 (DPI-Benchmark/1.0)"})
            print(f"  [✓] {dom:<25} -> {dest_ip}")
        except Exception:
            pass

    time.sleep(2)
    sniffer.stop()
    packets = sniffer.results
    if packets and len(packets) > 0:
        wrpcap(output_pcap, packets)
        print(f"[+] Captured {len(packets)} live packets to {output_pcap}")
        with open(output_csv, "w", newline="", encoding="utf-8") as f:
            fieldnames = ["timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "true_domain", "protocol"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(csv_rows)
        print(f"[+] Wrote {len(csv_rows)} records to {output_csv}")
    else:
        print("[!] No packets captured live. Falling back to wire dataset generator.")
        run_synthetic_dataset(output_pcap, output_csv)

def main():
    args = parse_args()
    print("=" * 70)
    print(" GROUND-TRUTH DATASET GENERATION PIPELINE")
    print("=" * 70)
    if args.live:
        run_live_capture(args.output_pcap, args.output_csv, args.interface)
    else:
        run_synthetic_dataset(args.output_pcap, args.output_csv, args.split_tls_ratio, args.dns_correlation_ratio)
    print("=" * 70)
    print("[*] Dataset generation complete!")

if __name__ == "__main__":
    main()
