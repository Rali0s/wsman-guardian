# CONTRIBUTING.md

# Contributing to WS-Man Passive Inspector & Defender

Thank you for your interest in contributing. This project is defender-first: contributions should improve detection, logging, analysis, and safe deployment. Follow the guidelines below to make high-quality, responsible contributions.

## Code of conduct

Be professional, constructive, and inclusive. Report abusive behavior to the maintainers. This repository follows the standard Contributor Covenant; add a `CODE_OF_CONDUCT.md` if you want to adopt it formally.

## Getting started

1. Fork the repository and create a feature branch:
   `git checkout -b feature/my-change`
2. Write tests (where applicable) and update documentation. Keep changes small and focused.
3. Submit a Pull Request with a clear description of the change and rationale.

## What we accept

* Improvements to **detection, logging, parsing, and correlation** (passive defensive features).
* Enhancements that **reduce false positives** and improve redaction/sanitization.
* Documentation, playbooks, and integration connectors (SIEM parsers, ELK mappings).
* Unit tests and smoke tests for parsing logic.

## What we do NOT accept

* Code that adds active exploitation, unauthorized scanning, or covert/intrusive attack tools.
* Code that reintroduces offensive/injection/replay features without a clear lab-only gating mechanism, documentation, and maintainers’ approval. (If you propose lab-only tools, make them opt-in with explicit flags and ensure they are disabled by default.)
* Contributions that put user data or PII at risk without consent or mitigation steps.

## Security & responsible disclosure

If you discover a security vulnerability in this repository or related tooling, **do not post it publicly**. Instead:

* Create a private issue and tag the maintainers, or email the maintainer contact (add maintainer email in repo settings).
* If the issue involves third-party vulnerabilities (for example, a new exploit vector against WSUS), follow coordinated disclosure practices and notify affected vendors (e.g., Microsoft) and national CERT/Cyber agencies as needed. Reference established advisories (e.g., CISA guidance) when applicable. Note: CVE-2025-59287 is an example of a high-severity vulnerability that required immediate mitigation and vendor patching—follow vendor advisories and official KBs. ([CISA][2])

## Testing & CI

* Include unit tests for XML parsing, redaction, and JSON output.
* Where possible, provide small sample pcaps or synthetic inputs for test suites (ensure samples contain **no real credentials or PII**).
* CI should run linting and tests on commits and PRs.

## Documentation

* Update `README.md` for any public-facing changes.
* Add `CHANGELOG.md` entries when behavior changes materially (especially for detection thresholds or logging formats).
* Document any optional active features in `LAB.md` (clearly marked as lab-only) and include consent/authorization checklists.

## Release policy

* Tag releases (semantic versioning recommended).
* Announce major changes and breaking updates in release notes, especially if logging format (JSONL fields) changes.

## Legal & authorization reminders (must-read)

* **You must have explicit written authorization** to capture, inspect, or modify network traffic for any production or third-party systems. Running NFQUEUE/iptables and parsing network traffic may be illegal or violate policy if you do not own or have permission. The project's maintainers are not liable for misuse.
* Contributions that provide attack-capability code must include a clear gating mechanism and an approvals checklist.

## Contact & maintainers

* Open issues for bugs and feature requests.
* For security reports, follow the Security & responsible disclosure steps above.
* Maintainers: add maintainer contact info in repository settings or the top of this file.

---

## Final notes

* If you contributed code that touches WSUS detection or remediation, include references to vendor KBs and advisories (e.g., Microsoft KBs and CISA advisory for CVE-2025-59287) in PR descriptions to make reviewer triage faster. ([Microsoft Support][3])

---

[1]: https://nvd.nist.gov/vuln/detail/CVE-2025-59287?utm_source=chatgpt.com "CVE-2025-59287 Detail - NVD"
[2]: https://www.cisa.gov/news-events/alerts/2025/10/24/microsoft-releases-out-band-security-update-mitigate-windows-server-update-service-vulnerability-cve?utm_source=chatgpt.com "Microsoft Releases Out-of-Band Security Update to ..."
[3]: https://support.microsoft.com/en-us/topic/october-23-2025-kb5070881-os-build-26100-6905-out-of-band-8e7ac742-6785-4677-87e4-b73dd8ac0122?utm_source=chatgpt.com "October 23, 2025—KB5070881 (OS Build 26100.6905) Out ..."
[4]: https://unit42.paloaltonetworks.com/microsoft-cve-2025-59287/?utm_source=chatgpt.com "Microsoft WSUS Remote Code Execution (CVE-2025 ..."
[5]: https://www.huntress.com/blog/exploitation-of-windows-server-update-services-remote-code-execution-vulnerability?utm_source=chatgpt.com "Exploitation of Windows Server Update Services Remote ..."
