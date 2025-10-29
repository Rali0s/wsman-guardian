#!/usr/bin/env python3
"""
passive_wsman_nfqueue.py  -- Passive WS-Man / SOAP logger using netfilterqueue + scapy

Behavior:
 - Binds to an NFQUEUE and inspects TCP payloads.
 - Detects likely WS-Man/SOAP envelopes (HTTP body containing <Envelope>).
 - Redacts sensitive XML tags (Password, Credential, BinarySecurityToken).
 - Logs JSON lines to a file and prints concise summaries to stdout.
 - DOES NOT forward to any collector, modify packets, or perform replay/injection.
 - Accepts every packet after inspection to preserve normal traffic flow.

Requirements:
  - Python 3.8+
  - pip install netfilterqueue scapy lxml
  - libnetfilter-queue-dev (system package) for netfilterqueue to work

Usage (as root):
  sudo python3 passive_wsman_nfqueue.py --queue 1 --out /var/log/wsman_netlog.jsonl

Example iptables (authorized lab/gateway only):
  sudo iptables -I PREROUTING -t raw -p tcp --dport 5985 -j NFQUEUE --queue-num 1
  sudo iptables -D PREROUTING -t raw -p tcp --dport 5985 -j NFQUEUE --queue-num 1
"""

import argparse
import json
import signal
import sys
from datetime import datetime
from lxml import etree
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP
import logging
import os

# -------------------------
# Configurable defaults
# -------------------------
DEFAULT_OUTFILE = "/var/log/wsman_netlog.jsonl"
DEFAULT_QUEUE = 1
DEFAULT_PORTS = [5985, 5986, 8530, 8531]   # note: HTTPS (5986/8531) cannot be decrypted here
REDACT_TAGS = ('Password','Credential','BinarySecurityToken','Secret')

# -------------------------
# Logging setup
# -------------------------
logger = logging.getLogger("wsman_nfqueue")
logger.setLevel(logging.INFO)
handler_stream = logging.StreamHandler(sys.stdout)
handler_stream.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
logger.addHandler(handler_stream)

# file handler will be added after parsing args to honor custom path

# -------------------------
# XML helpers
# -------------------------
def try_parse_xml(text):
    """Try to parse XML text, return lxml Element or None."""
    try:
        parser = etree.XMLParser(recover=True, remove_comments=True)
        el = etree.fromstring(text.encode('utf-8'), parser=parser)
        return el
    except Exception:
        return None

def find_soap_body_and_action(root):
    """Return (body_string, action_string) or (None, None)"""
    if root is None:
        return (None, None)
    # SOAP 1.1 Envelope namespace
    body = None
    action = None
    # Try common SOAP envelope namespaces and WS-Addressing
    ns_candidates = [
        '{http://schemas.xmlsoap.org/soap/envelope/}Body',
        '{http://www.w3.org/2003/05/soap-envelope}Body'
    ]
    for nc in ns_candidates:
        body_el = root.find('.//' + nc)
        if body_el is not None:
            body = etree.tostring(body_el, pretty_print=True, encoding='utf-8').decode('utf-8')
            break
    # WS-Addressing Action
    action_el = root.find('.//{http://schemas.xmlsoap.org/ws/2004/08/addressing}Action')
    if action_el is None:
        action_el = root.find('.//{http://www.w3.org/2005/08/addressing}Action')
    if action_el is not None and action_el.text:
        action = action_el.text
    return (body, action)

def redact_xml_text(xml_text, redact_tags=REDACT_TAGS):
    """Redact inner text of specified tags (best-effort)."""
    try:
        root = try_parse_xml(xml_text)
        if root is None:
            # fallback simple replace
            s = xml_text
            for t in redact_tags:
                s = s.replace(f'<{t}>', f'<{t}>[REDACTED]')
                s = s.replace(f'</{t}>', f'</{t}>')
            return s
        for tag in redact_tags:
            # try namespace-agnostic find
            for el in root.xpath(f"//*[local-name() = '{tag}']"):
                if el.text:
                    el.text = '[REDACTED]'
        return etree.tostring(root, pretty_print=True, encoding='utf-8').decode('utf-8')
    except Exception:
        return xml_text

# -------------------------
# Packet processing helpers
# -------------------------
def extract_tcp_payload_raw(nf_payload):
    """Return (src, sport, dst, dport, payload_bytes) or None."""
    try:
        raw = nf_payload.get_payload()
        scapy_pkt = IP(raw)
        if TCP in scapy_pkt:
            t = scapy_pkt[TCP]
            payload = bytes(t.payload)
            return (scapy_pkt.src, int(t.sport), scapy_pkt.dst, int(t.dport), payload)
    except Exception as e:
        logger.debug("scapy parse error: %s", e)
    return None

def extract_soap_from_http_bytes(payload_bytes):
    """
    Attempt to extract a SOAP envelope from an HTTP payload.
    Returns dict with keys: xml_text, body_snippet, action  or None.
    """
    if not payload_bytes or len(payload_bytes) == 0:
        return None
    try:
        # Look for header/body divider CRLFCRLF
        if b'\r\n\r\n' in payload_bytes:
            _, body = payload_bytes.split(b'\r\n\r\n', 1)
        else:
            body = payload_bytes
        # decode best-effort
        body_str = body.decode('utf-8', errors='ignore').strip()
        if '<Envelope' in body_str and '<Body' in body_str:
            root = try_parse_xml(body_str)
            body_xml, action = find_soap_body_and_action(root)
            return {
                'xml_text': body_str,
                'body_snippet': (body_xml or body_str)[:2000],
                'action': action
            }
    except Exception as e:
        logger.debug("soap extraction err: %s", e)
    return None

# -------------------------
# NFQUEUE callback
# -------------------------
def make_callback(outfile, watched_ports):
    def _cb(nf_pkt):
        try:
            info = extract_tcp_payload_raw(nf_pkt)
            if not info:
                nf_pkt.accept()
                return
            src, sport, dst, dport, payload = info
            # Quick filter: only examine if either port matches watched_ports
            if sport not in watched_ports and dport not in watched_ports:
                nf_pkt.accept()
                return
            rec = {
                'ts': datetime.utcnow().isoformat() + 'Z',
                'src': f"{src}:{sport}",
                'dst': f"{dst}:{dport}",
                'len': len(payload)
            }
            soap = extract_soap_from_http_bytes(payload)
            if soap:
                redacted = redact_xml_text(soap['xml_text'])
                rec.update({
                    'soap_action': soap.get('action'),
                    'soap_body_snippet': soap.get('body_snippet'),
                    'soap_redacted_snippet': redacted[:4000]
                })
                # Write to file (JSONL)
                try:
                    with open(outfile, 'a', encoding='utf-8') as fh:
                        fh.write(json.dumps(rec) + "\n")
                except Exception as e:
                    logger.error("Failed to write to outfile %s: %s", outfile, e)
                # Pretty console output
                logger.info("WS-Man SOAP observed %s -> %s action=%s len=%d",
                            rec['src'], rec['dst'], rec.get('soap_action'), rec['len'])
            nf_pkt.accept()  # passive: accept and let packet continue
        except Exception as e:
            logger.exception("Unhandled callback error: %s", e)
            try:
                nf_pkt.accept()
            except Exception:
                pass
    return _cb

# -------------------------
# Main / Arg parsing
# -------------------------
def main():
    parser = argparse.ArgumentParser(prog="passive_wsman_nfqueue.py", description="Passive WS-Man NFQUEUE logger")
    parser.add_argument('--queue', '-q', type=int, default=DEFAULT_QUEUE, help="NFQUEUE number")
    parser.add_argument('--out', '-o', default=DEFAULT_OUTFILE, help="Output JSONL file (append)")
    parser.add_argument('--ports', '-p', nargs='+', type=int, default=DEFAULT_PORTS, help="Ports to inspect (space-separated)")
    parser.add_argument('--verbose', '-v', action='store_true', help="Verbose logging (debug)")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    # ensure outfile dir exists
    try:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
    except Exception:
        pass

    # add file handler
    fh = logging.FileHandler(args.out + ".log", encoding='utf-8')
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
    logger.addHandler(fh)

    logger.info("Starting passive WS-Man NFQUEUE logger on queue %d; logging to %s", args.queue, args.out)
    nf = NetfilterQueue()
    try:
        nf.bind(args.queue, make_callback(args.out, set(args.ports)))
    except Exception as e:
        logger.error("Failed to bind NFQUEUE %d: %s", args.queue, e)
        sys.exit(2)

    # graceful shutdown on Ctrl-C
    def _sigint(signum, frame):
        logger.info("Shutting down (signal=%s)...", signum)
        try:
            nf.unbind()
        except Exception:
            pass
        sys.exit(0)
    signal.signal(signal.SIGINT, _sigint)
    signal.signal(signal.SIGTERM, _sigint)

    try:
        nf.run()
    except KeyboardInterrupt:
        _sigint("KeyboardInterrupt", None)
    finally:
        try:
            nf.unbind()
        except Exception:
            pass

if __name__ == "__main__":
    main()
