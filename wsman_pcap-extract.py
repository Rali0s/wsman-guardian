#!/usr/bin/env python3
"""
wsman_pcap-extract.py
- Use pyshark to parse a pcap file and extract HTTP payloads; find SOAP envelopes.
Requires: pip install pyshark
"""

import pyshark
import argparse
import json
from lxml import etree
from datetime import datetime

def is_wsman_http(pkt):
    try:
        if 'HTTP' in pkt:
            # many HTTP packets; check ports
            ports = {int(pkt.ip.src_port), int(pkt.ip.dst_port)} if hasattr(pkt.ip, 'src_port') else set()
            return bool({5985, 5986, 8530, 8531} & ports) or 'wsman' in str(pkt.http).lower()
    except Exception:
        pass
    return False

def extract_soap_from_http_body(body_raw):
    try:
        txt = body_raw
        if isinstance(txt, bytes):
            txt = txt.decode('utf-8', errors='ignore')
        if '<Envelope' in txt and 'Body' in txt:
            # return a short snippet
            return txt
    except Exception:
        pass
    return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('pcap', help='input pcap file')
    parser.add_argument('--out', default='wsman_extracted.jsonl', help='output JSONL')
    args = parser.parse_args()
    cap = pyshark.FileCapture(args.pcap, decode_as={'tcp.port==5985':'http','tcp.port==8530':'http'}, keep_packets=False)
    with open(args.out, 'w', encoding='utf-8') as fh:
        for pkt in cap:
            try:
                if hasattr(pkt, 'http'):
                    body = getattr(pkt.http, 'file_data', None)
                    if body:
                        soap = extract_soap_from_http_body(body)
                        if soap:
                            rec = {
                                'ts': pkt.sniff_time.isoformat(),
                                'src': pkt.ip.src + ':' + pkt.tcp.srcport,
                                'dst': pkt.ip.dst + ':' + pkt.tcp.dstport,
                                'soap_snippet': soap[:2000]
                            }
                            fh.write(json.dumps(rec) + '\n')
            except Exception:
                continue
    print("Done. Output ->", args.out)

if __name__ == '__main__':
    main()
