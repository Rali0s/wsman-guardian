# Security Policy

## 🛡️ Overview

**Project:** wsman-guardian  
**Purpose:** Passive WS-Man / PS1 Inspector Kit • Defensive-Only Toolkit  
**License:** MIT  
**Repository:** https://github.com/Rali0s/wsman-guardian  

The `wsman-guardian` project is designed exclusively for **authorized defensive, research, and educational use**.  
It does not contain, endorse, or distribute offensive or exploit code.  
This repository exists to improve **visibility, detection, and mitigation** of threats such as **CVE-2025-59287 (WSUS RCE)** and similar network management-plane vulnerabilities.

---

## 🧩 Supported Versions

| Version | Supported | Notes |
|----------|------------|-------|
| `main` (active branch) | ✅ | Receives regular defensive updates |
| Tagged releases | ✅ | Security fixes and documentation updates backported as feasible |
| Legacy branches | ❌ | Not maintained; upgrade to latest release |

---

## 🚨 Reporting a Vulnerability

If you believe you have found a security issue or vulnerability:

1. **Do NOT open a public GitHub issue.**
2. Email the maintainers privately at: 3XCypher@pm.me


3. Include:
- A short summary of the issue and its potential impact.
- Steps to reproduce (if applicable).
- Whether it affects the repository’s code, documentation, or deployment scripts.
- Your contact information for coordinated disclosure.

4. The maintainers will acknowledge receipt within **3 business days** and provide a status update or next steps.

> All disclosures are handled under a coordinated and responsible disclosure model.

---

## 🔒 Scope of Security Testing

### In Scope
- The repository’s own code (Python, PowerShell, shell scripts).
- Configuration and logging behavior that could expose sensitive data.
- False-positive or privacy leaks during traffic capture.

### Out of Scope
- Live attacks, replay testing, or exploitation attempts against third-party systems.
- Unauthorized network interception or packet modification.

> **Reminder:** Use only on systems and networks you own or have explicit written authorization to inspect.

---

## ⚙️ CVE-2025-59287 — Reference & Defensive Alignment

- **CVE ID:** CVE-2025-59287  
- **Severity:** Critical (CVSS 9.8)  
- **Type:** Unauthenticated Remote Code Execution in WSUS (Windows Server Update Services)  
- **Status:** Active exploitation observed (Microsoft OOB fix released October 2025)

### Defensive Measures Documented Here
- Guidance to **apply Microsoft OOB updates (KB5070881 / KB5070883 / KB5070882)** immediately.
- Recommendation to **block inbound TCP 8530 / 8531** at host and perimeter firewalls until patched.
- Passive inspection modules (`passive_wsman_nfqueue.py`, `wsman_nfqueue.py`) to help identify suspicious WSUS / WS-Man HTTP traffic without exploitation.
- MITRE ATT&CK mappings for defensive analysts (see `MITRE_MAPPING.md`).

For authoritative remediation details, see:
- Microsoft Security Response Center (MSRC) advisory for CVE-2025-59287  
- CISA and vendor advisories for current guidance

---

## 🧭 Coordinated Disclosure Workflow

1. Reporter submits private email to `3XCypher@pm.me`.  
2. Maintainers validate and triage the issue (defensive/non-defensive impact).  
3. If applicable, a GitHub Security Advisory (GHSA) draft is created privately with the reporter.  
4. Fix merged and released with proper attribution (if consented).  
5. Advisory published publicly once a patch or mitigation is available.

---

## 🔐 Responsible Usage Reminder

By using this code, you agree to:
- Operate it only within authorized environments.  
- Comply with all local and international laws governing network monitoring and interception.  
- Retain full responsibility for how this software is deployed.

The maintainers and contributors assume **no liability** for misuse or unauthorized activity.

---

## 📫 Contact

- **Maintainer:** CypherArc Team  
- **Security Contact:** [3XCypher@pm.me](3XCypher@pm.me)  
- **GitHub Issues:** Use for feature requests and non-sensitive bugs only  
- **Repository:** [https://github.com/Rali0s/wsman-guardian](https://github.com/Rali0s/wsman-guardian)

---

_Last updated: October 2025_


