# TLDR.md

# WS-Man Passive Inspector & Defender

**Passive, defender-focused tooling to observe and analyze WS-Man / CIM (SOAP over HTTP/HTTPS) traffic on network gateways and correlate findings with Windows hosts.** This project is explicitly designed for *defensive* use: it logs and redacts SOAP payloads, produces structured JSON for analysis, and avoids active modification or exploitation. It includes guidance and references for defending against a critical WSUS vulnerability (CVE-2025-59287).

---

## TL;DR — urgent CVE note (CVE-2025-59287)

A critical, unauthenticated remote code execution (RCE) vulnerability affecting Microsoft Windows Server Update Services (WSUS), tracked as **CVE-2025-59287 (CVSS 9.8)**, is being actively exploited in the wild. Microsoft and CISA published out-of-band updates and guidance; if you run WSUS, apply the Microsoft emergency updates immediately or implement temporary mitigations such as disabling the WSUS role or blocking inbound traffic to WSUS ports (TCP 8530/8531) on the host firewall until patched. ([NVD][1]) ([CISA][2]) ([Microsoft Support][3])

---

## Project overview

This repository provides:

* **`passive_wsman_nfqueue.py`** — Passive NFQUEUE-based WS-Man/SOAP logger. Binds to an NFQUEUE, inspects TCP payloads, detects SOAP `<Envelope>`/`<Body>`, redacts common sensitive tags (e.g., `Password`, `Credential`, `BinarySecurityToken`), writes JSONL records and human-readable logs, and *accepts* packets (non-destructive).
* **`wsman_pcap-extract-offline.py`** — Offline extractor using `pyshark` to parse pcap files and extract WS-Man SOAP payloads into JSONL for forensic review.
* **`ps_listener.ps1`** — PowerShell listener to accept JSONL lines, persist them, and assist host-side correlation (`Get-CimSession`, WinRM logs).
* **`stateful_defender.py`** — Prototype logic for detecting "chirp" behavior (rapid, small, repeated WS-Man requests) and example thresholds for triggering analyst review (research template).
* **`ip-tables.sh`** — Example iptables commands to redirect chosen ports to NFQUEUE for authorized lab/gateway inspection.

All scripts are written for defensive analysis. Active/injection/replay helpers (present in some variants) are **disabled by default** and clearly labeled as *lab-only*.

---

## Why this matters (short)

* WS-Man and CIM are used for remote management (WinRM, WMI) and can expose powerful administrative capabilities if misconfigured. Observing SOAP messages helps defenders detect suspicious patterns (e.g., ephemeral/rotating `InstanceId`s, short “chirp” requests used to simulate a persistent channel).
* The **WSUS RCE (CVE-2025-59287)** specifically affects WSUS reporting web services and has had active exploitation and emergency out-of-band patches released by Microsoft; defenders should assume risk until mitigations/patches are applied. ([Unit 42][4]) ([Huntress][5])

---

## Requirements

* Linux gateway (for NFQUEUE mode): `python3` (3.8+), root to bind NFQUEUE and run `iptables`.
* Windows host (optional) for host correlation: PowerShell (elevated).
* Python dependencies (install via `pip`):
  `netfilterqueue`, `scapy`, `lxml` (and optionally `pyshark` + `tshark` for offline pcap parsing).
  See each script header for exact requirements and install notes.

---

## Quickstart (passive live inspection — authorized use only)

> **Authorization reminder:** Only run NFQUEUE/iptables packet inspection on networks and hosts you *own* or have *explicit written permission* to test.

1. Install prerequisites on the gateway and run the passive logger (example):

   ```bash
   sudo pip3 install netfilterqueue scapy lxml
   sudo python3 passive_wsman_nfqueue.py --queue 1 --out /var/log/wsman_netlog.jsonl
   ```
2. (Authorized lab/gateway only) Route flows to NFQUEUE:

   ```bash
   sudo iptables -I PREROUTING -t raw -p tcp --dport 5985 -j NFQUEUE --queue-num 1
   ```

   Remove the rule when finished:

   ```bash
   sudo iptables -D PREROUTING -t raw -p tcp --dport 5985 -j NFQUEUE --queue-num 1
   ```
3. Optionally run `ps_listener.ps1` on the Windows host to persist JSONL and print concise correlation lines:

   ```powershell
   .\ps_listener.ps1 -Port 17000 -OutFile C:\wsman_logs\wsman_netlog.jsonl
   ```

---

## Offline pcap analysis (forensics)

If you already have a pcap, use the offline extractor:

```bash
pip3 install pyshark lxml
python3 wsman_pcap-extract-offline.py capture.pcap --out wsman_extracted.jsonl
```

This will extract SOAP envelopes found in HTTP payloads for ports commonly used by WinRM/WSUS and produce JSONL entries for analysis. Note: HTTPS traffic (5986/8531) cannot be parsed unless you possess TLS key material.

---

## Detection & mitigation checklist

**Immediate (if WSUS present or internet-exposed):**

* **Apply Microsoft's out-of-band security updates** for CVE-2025-59287 immediately. Microsoft published emergency updates on Oct 23–24, 2025 and recommends immediate installation and reboot where applicable. Check the Microsoft Update Guide and KBs relevant to your OS version (examples: KB5070881 / KB5070883 / KB5070882). ([Microsoft Support][3])
* **Temporary mitigation until patched:** disable the WSUS server role or **block inbound traffic on TCP 8530/8531 at the host firewall/boundary** (this prevents remote exploitation but also prevents clients from receiving updates from that WSUS server). ([CISA][2])

**Network & host hardening (recommended):**

* Block **DCOM/RPC** at the boundary and limit exposure of ephemeral RPC ports (TCP 135 and dynamic range 49152–65535).
* Block **WinRM** ports (5985/5986) at network boundaries unless absolutely needed. For required management, restrict to specific management subnets and enforce Kerberos/Mutual TLS.
* Log and alert on **chirp-like patterns** (many small WS-Man requests from same IP over short time windows). Use `stateful_defender.py` as a reference template.
* Enforce host firewall block rules for management ports on DMZ hosts (apply SC-7 / NIST control mapping).

---

## Logging & privacy

* Output format: **JSONL** (one JSON object per line). Fields include `ts`, `src`, `dst`, `len`, `soap_action`, `soap_body_snippet`, and `soap_redacted_snippet`. Redaction is implemented for tags frequently containing secrets. Rotate logs and sanitize PII before sharing.

---

## Limitations

* **TLS decryption**: passive scripts cannot decrypt TLS (5986/8531) without private key or session-key material. If you own the host and can access TLS session logs or keys, offline decryption tools can be used before parsing.
* **No offensive capabilities**: the main scripts are passive and accept packets; active injection/replay capabilities are present only in separate, gated lab-only variants and disabled by default. Do not enable active features on production networks.

---

## Incident response & reporting

If you detect evidence of exploitation or unexpected WSUS/WS-Man behavior, follow your IR process and consider:

* Isolating affected hosts and preserving memory/pcap evidence.
* Applying Microsoft's OOB updates for CVE-2025-59287 and following CISA/Microsoft advisory guidance. ([CISA][2])
* Contacting your vendor/incident response partner (Unit 42, Huntress, etc.) for triage if compromise is suspected. ([Unit 42][4])

---

## Further reading

* Microsoft Update Guide / CVE-2025-59287 (see Microsoft Update Guide and KB articles for your OS). ([Microsoft Support][3])
* CISA Advisory: Out-of-band update guidance and mitigation for CVE-2025-59287. ([CISA][2])
* Vendor writeups and threat reports (Unit 42, Huntress, Tenable, etc.) describing exploitation behavior and IOCs. ([Unit 42][4])

---