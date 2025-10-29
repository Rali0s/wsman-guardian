#!/usr/bin/env python3
#
# brew install python@3.12
# brew install wireshark   # gives libpcap + optional tshark
# pip3 install scapy lxml  # (pyshark is optional if you prefer tshark-based parsing)
# if you’ll use pyshark live: pip3 install pyshark
#
# wsman_live_bpf_pcap.py  — macOS-safe live sniffer (libpcap) for WS-Man/WSUS HTTP traffic

import argparse, json, sys, os
from datetime import datetime
from lxml import etree
from scapy.all import sniff, TCP, Raw, IP

REDACT_TAGS = ('Password','Credential','BinarySecurityToken','Secret')

def redact_xml(xml_text):
    try:
        parser = etree.XMLParser(recover=True, remove_comments=True)
        root = etree.fromstring(xml_text.encode('utf-8'), parser=parser)
        for tag in REDACT_TAGS:
            for el in root.xpath(f"//*[local-name() = '{tag}']"):
                el.text = '[REDACTED]'
        return etree.tostring(root, pretty_print=True, encoding='utf-8').decode('utf-8')
    except Exception:
        return xml_text

def soap_from_payload(payload_bytes):
    if not payload_bytes:
        return None
    try:
        body = payload_bytes.split(b'\r\n\r\n', 1)[1] if b'\r\n\r\n' in payload_bytes else payload_bytes
        body_str = body.decode('utf-8', errors='ignore').strip()
        if '<Envelope' in body_str and '<Body' in body_str:
            # find action + pretty body
            try:
                root = etree.fromstring(body_str.encode('utf-8'), parser=etree.XMLParser(recover=True))
                # SOAP body
                body_el = (root.find('.//{http://schemas.xmlsoap.org/soap/envelope/}Body') or
                           root.find('.//{http://www.w3.org/2003/05/soap-envelope}Body'))
                body_xml = etree.tostring(body_el, pretty_print=True, encoding='utf-8').decode('utf-8') if body_el is not None else None
                # WS-Addressing Action
                action_el = (root.find('.//{http://schemas.xmlsoap.org/ws/2004/08/addressing}Action') or
                             root.find('.//{http://www.w3.org/2005/08/addressing}Action'))
                action = action_el.text if action_el is not None else None
                return {'xml': body_str, 'body': body_xml, 'action': action}
            except Exception:
                return {'xml': body_str, 'body': None, 'action': None}
    except Exception:
        pass
    return None

def main():
    ap = argparse.ArgumentParser(description="macOS live WS-Man/WSUS passive sniffer (pcap)")
    ap.add_argument('--iface', default=None, help='Interface (e.g., en0). Default: scapy chooses.')
    ap.add_argument('--out', default='/tmp/wsman_netlog.jsonl', help='JSONL output')
    # Only HTTP ports; HTTPS (5986/8531) can’t be decoded without keys
    ap.add_argument('--ports', default='5985,8530', help='Comma list of ports to sniff (HTTP).')
    ap.add_argument('--bpf', default=None, help='Custom BPF filter (overrides ports).')
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    ports = [p.strip() for p in args.ports.split(',') if p.strip()]
    bpf = args.bpf or ' or '.join([f'tcp port {p}' for p in ports])

    print(f"[+] Sniffing on iface={args.iface or '(auto)'} BPF='{bpf}' -> {args.out}")
    def handler(pkt):
        try:
            if IP in pkt and TCP in pkt:
                raw = pkt.getlayer(Raw).load if pkt.haslayer(Raw) else b''
                soap = soap_from_payload(raw)
                if soap:
                    rec = {
                        'ts': datetime.utcnow().isoformat() + 'Z',
                        'src': f"{pkt[IP].src}:{pkt[TCP].sport}",
                        'dst': f"{pkt[IP].dst}:{pkt[TCP].dport}",
                        'len': len(raw),
                        'soap_action': soap.get('action'),
                        'soap_body_snippet': (soap.get('body') or '')[:2000],
                        'soap_redacted_snippet': redact_xml(soap['xml'])[:4000],
                    }
                    with open(args.out, 'a', encoding='utf-8') as fh:
                        fh.write(json.dumps(rec) + '\n')
                    print(f"[WS-Man] {rec['src']} -> {rec['dst']} action={rec['soap_action']} len={rec['len']}")
        except Exception as e:
            print("parse error:", e, file=sys.stderr)

    sniff(iface=args.iface, filter=bpf, prn=handler, store=False)

if __name__ == '__main__':
    main()
