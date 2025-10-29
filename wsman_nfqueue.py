#!/usr/bin/env python3
"""
wsman_nfqueue.py
- Capture selected packets via netfilterqueue (Linux).
- Parse TCP payloads for HTTP (port 5985) or WSUS (8530) and extract SOAP XML.
- Optionally redact sensitive fields, send JSON to local collector (PowerShell).
- Replay helper is present but disabled by default; use at your own risk and only in a lab.

Requires:
  pip install netfilterqueue scapy lxml requests
  apt-get install libnetfilter-queue-dev (or equivalent)
Run as root.
"""

import argparse
import json
import socket
import sys
import threading
from datetime import datetime
from lxml import etree
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw, Ether, send, conf

# CONFIG
LOCAL_COLLECTOR = ('127.0.0.1', 17000)   # PowerShell listener
FILTER_PORTS = {5985, 5986, 8530, 8531}  # ports of interest (5986 is TLS; we cannot decrypt here)
REPLAY_ENABLED = False                   # SAFE DEFAULT: do not replay packets unless you set True after confirming lab mode
REPLAY_TARGET = ('127.0.0.1', 18000)     # where to send replayed HTTP bodies (lab endpoint)

def tcp_payload_from_pkt(pkt):
    """
    Return (src_ip, src_port, dst_ip, dst_port, payload_bytes) or None
    """
    try:
        raw = pkt.get_payload()
        pkt_scapy = IP(raw)
        if TCP in pkt_scapy:
            t = pkt_scapy[TCP]
            if t.dport in FILTER_PORTS or t.sport in FILTER_PORTS:
                payload = bytes(t.payload)
                return (pkt_scapy.src, t.sport, pkt_scapy.dst, t.dport, payload, pkt_scapy)
    except Exception as e:
        print("scapy parse err:", e)
    return None

def extract_soap_from_http(payload_bytes):
    """
    Attempt to find and parse SOAP XML inside an HTTP request/response payload.
    Returns dict {xml, action, parsed} or None
    """
    try:
        txt = None
        # If payload contains b'\r\n\r\n' then headers separate from body
        if b'\r\n\r\n' in payload_bytes:
            hdr, body = payload_bytes.split(b'\r\n\r\n', 1)
            txt = body
        else:
            txt = payload_bytes
        # try decode
        txt_str = txt.decode('utf-8', errors='ignore').strip()
        if txt_str.startswith('<') and 'Envelope' in txt_str:
            # parse xml with lxml
            root = etree.fromstring(txt_str.encode('utf-8'))
            # find SOAP body
            ns = {k:v for k,v in root.nsmap.items() if k}
            body_el = root.find('.//{http://schemas.xmlsoap.org/soap/envelope/}Body')
            if body_el is None:
                # sometimes SOAP 1.2
                body_el = root.find('.//{http://www.w3.org/2003/05/soap-envelope}Body')
            parsed_body = etree.tostring(body_el, pretty_print=True, encoding='utf-8').decode('utf-8') if body_el is not None else None
            action = None
            # look for WS-Man Action header in XML
            action_el = root.find('.//{http://schemas.xmlsoap.org/ws/2004/08/addressing}Action')
            if action_el is not None:
                action = action_el.text
            return {'xml': txt_str, 'action': action, 'body': parsed_body}
    except Exception as e:
        # not XML or parse fail
        return None
    return None

def redact_soap(xml_text, redact_tags=('Password','Credential','BinarySecurityToken')):
    """
    Simple redaction: remove contents of known sensitive tags.
    Returns redacted xml string.
    """
    try:
        parser = etree.XMLParser(recover=True)
        root = etree.fromstring(xml_text.encode('utf-8'), parser=parser)
        for tag in redact_tags:
            for el in root.findall('.//{}'.format(tag)):
                el.text = '[REDACTED]'
        return etree.tostring(root, pretty_print=True, encoding='utf-8').decode('utf-8')
    except Exception:
        # fallback: simple string replace (best-effort)
        txt = xml_text
        for t in redact_tags:
            txt = txt.replace(f'<{t}>', f'<{t}>[REDACTED]')
            txt = txt.replace(f'</{t}>', f'</{t}>')
        return txt

def forward_to_collector(json_obj):
    """
    Send JSON to local collector via TCP. Best-effort, non-blocking.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(LOCAL_COLLECTOR)
        s.sendall((json.dumps(json_obj) + "\n").encode('utf-8'))
        s.close()
    except Exception as e:
        print("forward err:", e)

def replay_http_to_target(src_ip, src_port, dst_ip, dst_port, payload_bytes):
    """
    Lab-only: craft a new TCP connection to the original destination and send the HTTP payload.
    Disabled by default (REPLAY_ENABLED=False). Use only in isolated lab environment.
    """
    if not REPLAY_ENABLED:
        return False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect(REPLAY_TARGET)  # deliberately send to REPLAY_TARGET not original destination, to avoid misuse
        s.sendall(payload_bytes)
        s.close()
        return True
    except Exception as e:
        print("replay err:", e)
        return False

def handle_nfqueue_pkt(nf_pkt):
    """
    Callback for packets from NFQUEUE.
    """
    try:
        data = tcp_payload_from_pkt(nf_pkt)
        if not data:
            nf_pkt.accept()
            return
        src_ip, src_port, dst_ip, dst_port, payload, scapy_pkt = data
        info = {
            'ts': datetime.utcnow().isoformat() + 'Z',
            'src': f"{src_ip}:{src_port}",
            'dst': f"{dst_ip}:{dst_port}",
            'length': len(payload),
        }
        soap = extract_soap_from_http(payload)
        if soap:
            redacted = redact_soap(soap['xml'])
            info.update({
                'soap_action': soap.get('action'),
                'soap_body_snippet': (soap.get('body') or '')[:400],
                'soap_redacted': redacted[:800],
            })
            # non-blocking forward
            threading.Thread(target=forward_to_collector, args=(info,)).start()
            # optionally replay (lab only)
            if REPLAY_ENABLED:
                replay_http_to_target(src_ip, src_port, dst_ip, dst_port, payload)
        # Accept the packet and let it continue normally
        nf_pkt.accept()
    except Exception as e:
        print("handler err:", e)
        try:
            nf_pkt.accept()
        except Exception:
            pass

def main():
    parser = argparse.ArgumentParser(description="WS-Man NFQUEUE inspector")
    parser.add_argument('--queue', type=int, default=1, help='NFQUEUE number to bind to')
    args = parser.parse_args()

    nfqueue = NetfilterQueue()
    nfqueue.bind(args.queue, handle_nfqueue_pkt)
    print("Listening on NFQUEUE %d. Ctrl-C to stop." % args.queue)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("Stopping.")
    finally:
        nfqueue.unbind()

if __name__ == '__main__':
    main()
