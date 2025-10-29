# WS-Man Passive Inspector & Defender — README.md

---
<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/status-defender--first-success" alt="Status: Defensive">
  <img src="https://img.shields.io/badge/coverage-CVE--2025--59287-critical" alt="CVE-2025-59287 Coverage">
</p>

<p align="center">
  <b>wsman-guardian</b> — Passive WS-Man / CIM Inspector • CVE-2025-59287 Aware • MITRE ATT&CK Aligned
</p>

---

**Short description**
A defensive toolkit for inspecting WS-Man / CIM traffic (WS-Man SOAP over HTTP/HTTPS) on Linux gateways and correlating findings with Windows hosts. The tools are passive by default: they log and redact SOAP payloads for forensic analysis and host correlation — they do **not** modify or replay traffic unless explicitly enabled in isolated lab mode.

---

## Red Teaming & ML Cross-Correlation Report

A public-safe summary of our red-team-style workflow and ML research is available at `docs/REDTEAM_REPORT.md`.  
Sensitive artifacts (raw pcaps, model checkpoints containing private training data, and step-by-step offensive procedures) are withheld and available only to vetted partners under NDA.  
For security coordination, see `README.md` or contact `3XCypher@pm.me`.


## Project components (what’s in this repo)

* `passive_wsman_nfqueue.py` — Passive NFQUEUE-based WS-Man/SOAP logger (primary runtime). Binds to an NFQUEUE, inspects TCP payloads for WS-Man SOAP envelopes, redacts sensitive tags, writes JSONL records and human-readable logs. See code and behavior. 
* `wsman_nfqueue.py` — Earlier variant that includes optional forwarding/replay helpers (replay is disabled by default). Use only for lab experiments after reading warnings. 
* `wsman_pcap-extract.py` — Offline pyshark extractor for pcaps: finds HTTP flows on ports like 5985/8530 and extracts SOAP bodies into JSONL for analysis. Useful for post-capture forensic work. 
* `ps_listener.ps1` (PowerShell) — Local TCP listener to receive JSON lines from a network-side extractor and correlate them with host-side evidence (`Get-CimSession`, WinRM/WinEvent logs). Designed to run on the Windows host for triage. 
* `stateful_defender.py` — Prototype logic for stateful "chirp" detection (burst detection / simulated benign-error injection). Example only; shows how stateful counters and thresholds could be used to trigger actions. 
* `ip-tables.sh` — Example iptables rules to route selected traffic to NFQUEUE for authorized lab/gateway inspection. **Do not run on networks without authorization.** 

(Other supporting files / experimental variants may also be present — inspect the repo root for additional helpers.)

---

## Goals & threat model

* **Primary goal:** Provide defenders with a minimally invasive way to observe WS-Man/CIM SOAP traffic (HTTP) and collect structured observables for host/network correlation and triage. 
* **Threat model:** Focused on detecting unauthenticated/stateless CIM/WS-Man abuse (the “chirp pipe” pattern — many small stateless queries to simulate persistence), and giving teams a way to analyze and correlate evidence without performing offensive actions. See theory and mitigation notes. 

---

## Requirements

* Linux gateway (for NFQUEUE mode): `python3` (3.8+|3.12+), root to bind NFQUEUE and run iptables.
* Dependencies (install via pip): `netfilterqueue`, `scapy`, `lxml`, `pyshark` (for offline mode). See each script for exact requirements. 
* Dependencies-OSX (install via pip): `scapy`, `lxml`, `pyshark` (for live mode). See each script for exact requirements - wireshark options ( `brew install wireshark` )
* Windows host (optional) for `ps_listener.p1`: PowerShell (run elevated) and access to relevant event logs for correlation. 

---

## Quickstart — Passive live inspection (authorized use only)

1. **On the Linux gateway** (you control), install prerequisites and run the passive logger:

   ```bash
   sudo pip3 install netfilterqueue scapy lxml
   sudo python3 passive_wsman_nfqueue.py --queue 1 --out /var/log/wsman_netlog.jsonl
   ```

   This starts a passive inspector that accepts packets after logging them. 

2. **Route traffic to NFQUEUE** (lab/gateway only — do not apply on shared/production without permission):

   ```bash
   sudo iptables -I PREROUTING -t raw -p tcp --dport 5985 -j NFQUEUE --queue-num 1
   ```

   Remove when finished:

   ```bash
   sudo iptables -D PREROUTING -t raw -p tcp --dport 5985 -j NFQUEUE --queue-num 1
   ```

   Example rule included. 

3. **On the Windows host (optional):** run `ps_listener.p1` (PowerShell) to accept JSON lines from a collector (if you use the forwarding-enabled variant) and correlate with host logs:

   ```powershell
   # run elevated
   .\ps_listener.ps1 -Port 17000 -OutFile C:\wsman_logs\wsman_netlog.jsonl
   ```

   The listener echoes concise netlog lines and stores JSONL for later merging with host events. 

---

## Offline pcap analysis

For pre-captured pcaps (forensics), use the offline extractor:

```bash
pip3 install pyshark lxml
python3 wsman_pcap-extract-offline.py capture.pcap --out wsman_extracted.jsonl
```

The script decodes HTTP flows for ports typically used by WinRM/WSUS and extracts SOAP envelopes into JSONL for analysis. 

---

## Logging format & redaction

* Output is **JSONL** (one JSON object per line). Key fields include:

  * `ts` — UTC timestamp
  * `src` / `dst` — 5-tuple IP:port shorthand
  * `len` / `length` — payload length
  * `soap_action` — WS-Addressing Action (if found)
  * `soap_body_snippet` / `soap_redacted_snippet` — body snippet; sensitive tags are redacted by default (e.g., `Password`, `Credential`, `BinarySecurityToken`, `Secret`). 

---

## Detection recommendations & defensive playbook

* **Disable unnecessary management services** on DMZ hosts (if WinRM/CIM not required), bind listeners to loopback only where possible. 
* **Block DCOM/WinRM at boundary** (TCP 135 and dynamic RPC range 49152–65535, and WinRM ports 5985/5986) unless explicitly required. 
* **Monitor for “chirp” patterns** — frequent small, unauthenticated WS-Man requests from same source in short windows. Consider stateful detection thresholds like those in `stateful_defender.py` as an engineering starting point. 

---

## Safety, legal & operational notes (read carefully)

* **Authorization required.** Only run NFQUEUE/iptables rules and packet inspection on networks and hosts you own or have explicit written permission to test. Misuse may be illegal. The tooling defaults to passive logging; optional active/injection helpers are disabled by default or are labeled "lab-only". 
* **TLS decryption:** HTTPS/5986/8531 traffic cannot be parsed without TLS keys/session logs. The passive scripts will detect the flow but cannot extract SOAP without keys. 

---

## Extensions & next steps

* Add a `--pcap-dump` option to write matching packets to a pcap for offline analysis (safe, non-intrusive). 
* Hook the JSONL stream into SIEM/ELK for automated correlation and alerting (searchable by `soap_action`, source IP, timestamp).
* Harden logging (rotation, PII scrubbing) before production deployment. 

---

## Example developer notes

* `passive_wsman_nfqueue.py` contains the primary XML detection and redaction logic. It tries to parse SOAP using `lxml`, extracts the `<Body>` and WS-Addressing `<Action>` when present, and writes redacted JSON for analysts. 
* `stateful_defender.py` is a minimal template that demonstrates how to detect bursts/chirps and what a benign-error injection decision might look like — intended as pseudo-code for R&D, not production. 

---

## Licensing & attribution
### Legal Notice

See [NOTICE](NOTICE) and [LICENSE](LICENSE) for terms, attributions, and security disclosures.


---

## Contact / Contributing

* Open issues for bugs, feature requests, and defensive hardening suggestions. When contributing, include tests and justify any active/injection behavior; keep offensive capabilities out of mainline unless gated behind explicit lab flags and documented approvals.

---

## Important references & further reading

* WS-Man / WinRM protocol and SOAP payloads — use official MS docs when crafting detection rules.
* Defensive writeups on unauthenticated WMI/WinRM misuse and the “chirp” pattern in the DMZ. See the project’s design notes and threat analysis included in `deep-nim-sec.py` for deeper context.
<<<<<<< HEAD
=======

---

## ⚖️ License & Legal Notice

This project is licensed under the **[MIT License](LICENSE)** © 2025 *wsman-guardian contributors.*

Use of this software is permitted for **authorized defensive, research, and educational purposes only.**
It must **not** be used for exploitation, unauthorized interception, or offensive security testing without
explicit written consent from the system owner.

See [NOTICE](NOTICE) for attribution, MITRE ATT&CK mappings, and defensive disclosure details regarding **CVE-2025-59287**.

---

<p align="center">
  <sub>Maintained with 🛡️ by the Rali0s/CypherArc team — Stealth by design, defense by intent.</sub>
</p>
>>>>>>> d25cfff (Syncing Repo Data, Docs, MDs, Code)
