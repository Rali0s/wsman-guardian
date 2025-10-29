#!/usr/bin/env python3
"""
tiny_bpf_port_test.py
Simple BPF test: sniff TCP port 80 and 443, print concise packet info to stdout.
- No files, no disk writes.
- Detects HTTP start-lines and TLS ClientHello (basic).
- Works on macOS & Linux (requires root to sniff).
"""

import argparse
from scapy.all import sniff, IP, TCP, Raw
from datetime import datetime
import sys

def is_tls_client_hello(payload: bytes) -> bool:
    # TLS record content type 0x16 = Handshake, version bytes next; handshake type 0x01 = ClientHello
    # Minimal safe check: payload[0]==0x16 and payload[5]==0x01 (if long enough)
    if not payload or len(payload) < 6:
        return False
    try:
        return payload[0] == 0x16 and payload[5] == 0x01
    except Exception:
        return False

def http_start_line(payload: bytes) -> str | None:
    if not payload:
        return None
    try:
        s = payload.decode('utf-8', errors='ignore')
        # look for common HTTP methods or status line
        lines = s.splitlines()
        if not lines:
            return None
        first = lines[0].strip()
        if first.startswith(('GET ','POST ','PUT ','DELETE ','HEAD ','OPTIONS ','PATCH ')) or first.startswith('HTTP/1.'):
            return first
    except Exception:
        return None
    return None

def pkt_handler(pkt):
    ts = datetime.utcnow().isoformat() + 'Z'
    if IP in pkt and TCP in pkt:
        ip = pkt[IP]
        tcp = pkt[TCP]
        src = f"{ip.src}:{tcp.sport}"
        dst = f"{ip.dst}:{tcp.dport}"
        info = f"{ts} {src} -> {dst} len={len(pkt)} flags={tcp.flags}"
        payload = b''
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            http_line = http_start_line(payload)
            if http_line:
                info += f" HTTP: {http_line[:80]}"
                print(info)
                return
            if is_tls_client_hello(payload):
                info += " TLS: ClientHello"
                print(info)
                return
        # generic TCP line if nothing special
        print(info)

def main():
    ap = argparse.ArgumentParser(description="BPF test for ports 80 and 443 — stdout only")
    ap.add_argument('--iface', '-i', default=None, help='interface (e.g., en0). Default: scapy chooses')
    ap.add_argument('--count', '-c', type=int, default=0, help='number of packets to capture (0 = infinite)')
    args = ap.parse_args()

    # Build a BPF that matches tcp port 80 or 443 (both directions)
    bpf = 'tcp port 80 or tcp port 443'

    try:
        print(f"[+] Starting BPF sniff (filter: \"{bpf}\") on iface={args.iface or '(auto)'}; Ctrl-C to stop")
        sniff(iface=args.iface, filter=bpf, prn=pkt_handler, store=False, count=(args.count or None))
    except PermissionError:
        print("Permission denied: run as root (sudo).", file=sys.stderr)
    except Exception as e:
        print("Sniffer error:", e, file=sys.stderr)

if __name__ == '__main__':
    main()