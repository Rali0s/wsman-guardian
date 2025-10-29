# MITRE ATT&CK Mapping — WS-Man Passive Inspector & Defender — MITRE.md

This document maps the repository's detection, logging, and mitigation capabilities to MITRE ATT&CK tactics and techniques. It also references the urgent WSUS vulnerability **CVE-2025-59287** and recommended defensive actions.

> **Repository:** `wsman-guardian` (suggested)
>
> **Purpose:** Passive observation and analysis of WS-Man / CIM (SOAP over HTTP/HTTPS) traffic for defensive detection, host-network correlation, and incident triage. No offensive capabilities in mainline; lab-only features must be explicitly gated.

---

## High-level MITRE mapping

| ATT&CK Tactic | Technique (Name) | Technique ID | How this repo helps detect / mitigate |
|---|---:|:---:|---|
| Initial Access | Exploit Public-Facing Application | **T1190** | CVE-2025-59287 (WSUS RCE) is an exploitation of a public-facing web service. `passive_wsman_nfqueue.py` and offline extractors allow defenders to detect suspicious WSUS/WS-Man HTTP flows for rapid triage; README and playbooks recommend immediate host firewall blocking of 8530/8531 and applying vendor OOB updates. |
| Execution / Lateral Movement | Windows Management Instrumentation (WMI) | **T1047** | WMI/CIM traffic and ephemeral CIM sessions are detectable by parsing SOAP envelopes and correlating with host `Get-CimSession` / WinRM logs. The tools extract SOAP `<Body>` and `InstanceId` patterns to look for WMI usage and “chirp” patterns. |
| Lateral Movement / Remote Services | Remote Services (WinRM/WS-Man) | **T1021** | WinRM/WS-Man is an implementation of remote services used for remote command execution. The NFQUEUE logger inspects WinRM ports (5985/5986) and logs SOAP actions and bodies to help detect misuse. |
| Command and Control / Application Layer | Application Layer Protocol: Web Protocols | **T1071.001** | WS-Man runs over HTTP/HTTPS; the extractor pulls HTTP bodies and SOAP envelopes for analysis, which aids detection of C2 or management misuse over web protocols. |
| Execution | Command and Scripting Interpreter — PowerShell | **T1059.001** | PowerShell is commonly used via WinRM/WMI for remote execution. The repo’s correlation steps (PowerShell listener, host-side log queries) help detect PowerShell usage originating from remote management protocols. |
| Discovery / Defense Evasion | Network Service Discovery / Evasion patterns | *various* | Detection of ephemeral/rotating InstanceIds and short repeated requests (“chirps”) aids identification of covert management channels and attempts to evade detection. Stateful detection example is provided in `stateful_defender.py`. |

---

## CVE-2025-59287 (WSUS RCE) — mapping & immediate actions

- **Technique:** Exploit Public-Facing Application — **T1190**  
- **Why relevant:** WSUS is a web service (ports 8530/8531). CVE-2025-59287 is a high-severity unauthenticated RCE (CVSS 9.8) targeting WSUS components; exploited systems can be entirely compromised via network access to these services.  
- **Defender actions (documented in repository):**
  - Apply vendor OOB updates immediately (Microsoft KBs / Update Guide) — this is the definitive fix.
  - As an emergency mitigation, **block TCP 8530/8531 at the host firewall** or disable the WSUS role until patched. (This repo documents and scripts host-firewall checks and advises blocking in README/PS scripts.)
  - Capture relevant traffic and logs (use the passive extractor or offline pcap analysis) to preserve IOCs and support IR.

---

## Detection guidance (log sources & indicators)

- **Network:**  
  - HTTP flows on ports **5985**, **8530** (and other management ports) containing SOAP `<Envelope>`/`<Body>` elements. The extractor extracts `soap_action` and `soap_body_snippet` for correlation.  
  - Short, frequent HTTP/SOAP requests from same source IP with rotating `InstanceId` values — “chirp” pattern.
- **Host (Windows):**  
  - WinRM Operational log (`Microsoft-Windows-WinRM/Operational`) — events showing remote session creation/requests (useful event IDs include WinRM activity and authentication events).  
  - `Get-CimSession` history and `Get-WinEvent` queries for WinRM/WMI logs. The PowerShell listener script shows examples for correlating network timestamps to host logs.  
- **Other forensic artifacts:** HTTP server logs on WSUS (requests to reporting/service endpoints), IIS logs if WSUS fronted by IIS, and hotfix/patch inventory (presence/absence of KBs that fix CVE-2025-59287).

---

## Recommended mitigations (mapping to controls)

- **Patch management / Immediate fix:** Apply Microsoft OOB patches for CVE-2025-59287. (Vendor advisory & CISA/MSRC guidance.) — relates to remediation of **T1190** exposures.  
- **Network segmentation & boundary controls:** Block unnecessary management ports at perimeter and host (135, 5985/5986, 8530/8531, dynamic RPC 49152–65535) — enforce **least privilege** for management channels.  
- **Strong auth & encryption:** Enforce Kerberos / mutual TLS for WinRM; disable anonymous/basic auth and disallow unencrypted WinRM traffic.  
- **Enhanced logging:** Centralize SOAP/WinRM logs into SIEM; alert on chirp patterns, new WSUS endpoints, or sudden increases in WS-Man requests.  
- **Forensics & containment:** If exploitation suspected, isolate host(s), preserve memory and pcap evidence, and apply IR playbook.

---

## How this repo supports the mapping

- `passive_wsman_nfqueue.py` and `wsman_pcap-extract-offline.py` extract SOAP envelopes and actions (helpful for detecting T1047, T1021/T1071 and identifying potential T1190 exploitation attempts).  
- `ps_listener.ps1` provides host-side correlation with `Get-CimSession` and WinRM logs to prove linkage between network-observed SOAP traffic and host activity.  
- `stateful_defender.py` is a starting template for detecting chirp patterns (helps surface evasion techniques and covert channels).  
- All active/injection features are disabled by default; the repo is intended to remain defensive-first.

---

## Notes & references

- Add repository-specific KB references and advisories to README (e.g., Microsoft KB numbers that apply to your supported platforms for CVE-2025-59287).  
- Keep the MITRE mapping updated as new research/techniques are discovered.

---

## Contribution & Review

- Document in PRs which ATT&CK techniques your change impacts (add or update `MITRE_MAPPING.md` accordingly).  
- Changes that affect detection thresholds, log formats, or parsing should include test vectors and sample JSONL outputs (sanitized of secrets) to validate detection.

