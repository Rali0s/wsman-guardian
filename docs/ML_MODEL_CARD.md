# ML Model Card — `deep-nim-sec-v1_v3` (gemini-v1-vertex-family)

**Model name / version**

* `gemini-v1-vertex-family-2025-10` ( or internal training family )
* Private reference name: **`deep-nim-sec-v1_v3`**

**Short description / purpose**
A research and defender-focused reasoning model fine-tuned to assist in *protocol workflow analysis* and *detection support* for management-plane protocols (WS-Man, WinRM, WMI, WSUS monitoring workflows). The model is intended for exploratory threat modeling, analyst-assist reasoning (MITRE mapping, indicator synthesis), and generating safe, testable detection hypotheses — **not** offensive tooling.

---

## Use cases (approved)

* Generate structured detection hypotheses (e.g., candidate SOAP/WS-Man indicators).
* Map observed network/host artifacts to MITRE ATT&CK techniques and suggested defensive mitigations.
* Produce human-reviewable detection rule drafts and SIEM query templates.
* Synthesize test-case descriptions for lab validation (synthetic pcaps, parsing golden files).

**Disallowed uses**

* Generating exploit code, step-by-step intrusions, or any actions intended to compromise third-party systems.
* Running against production systems to craft or execute payloads.
* Use without explicit, documented authorization.

---

## Training data (high-level)

**Summary:** The model was trained and fine-tuned on a mixture of *vendor documentation*, *synthetic protocol traces*, and *sanitized lab captures*. Sensitive raw artifacts and proprietary corpora are **REDACTED** and not included in public artifacts.

* Vendor docs: public Microsoft PowerShell / .NET CIM and WinRM/WS-Man docs (publicly available).
* Synthetic data: generated SOAP envelopes, parameterized InstanceId rotations, controlled chirp-pattern traces.
* Lab traces: sanitized WS-Man/WSUS HTTP examples with secrets and PII removed.
* Note: No private customer data or unconsented personal data was used.

---

## Checkpoint provenance

* Checkpoint: **Not Publicly Available Yet**.
* Provenance note: Private checkpoint(s) produced during Vertex AI training; sanitized derivative artifacts and model-card outputs are prepared for public access and review. Model weights and full checkpoints are currently withheld and **may** be released only under controlled access with provenance metadata and usage agreements.

---

## Evaluation

* Evaluation methodology: internal test harnesses running synthetic detection scenarios and sanitized lab traces; cross-evaluation against rule-based baselines.
* Public metrics: **REDACTED** (internal).
* Observed behavior: model provides useful hypothesis generation for analysts but requires human verification and rule hardening prior to deployment.
* False positives / False negatives: **REDACTED** — see Limitations & Risks.

---

## Limitations & Risks

* **Hallucination risk: HIGH.** The model can produce plausible-sounding but incorrect protocol behavior or IOCs. Always validate against primary sources and raw captures.
* **Overfitting risk: HIGH.** Fine-tuning on synthetic patterns can bias the model toward lab artifacts and miss real-world variability.
* **Not authoritative.** Outputs are assistive, not definitive — treat them as analyst suggestions requiring human verification.
* **No TLS decryption.** The model has no capacity to decrypt TLS content; it reasons on metadata, known plaintext patterns, and provided sanitized traces only.
* **Model drift & staleness.** Protocols and vendor behavior change; retrain/fine-tune periodically with fresh, sanctioned datasets.

---

## Safety mitigations & guardrails

* **Access control:** Model checkpoints are kept private; any interactive use requires authenticated access and role-based controls.
* **Prompting policy:** Provide explicit "defensive-only" prefix in prompts (e.g., `DEFENSIVE_ONLY:`) and implement automated detection in serving layer to reject requests that attempt to elicit exploit code.
* **Human-in-the-loop:** All outputs intended for operational use must be reviewed by a trained analyst before being converted into detection rules or operational actions.
* **Usage logging & audit:** Record all prompts and model outputs for auditing, red-team / blue-team validation, and incident forensics.
* **Redaction:** Model outputs that reference sensitive fields (passwords, tokens, private keys) must be redacted or sanitized before storage or sharing.

---

## Recommended evaluation & validation checklist (for adopters)

1. Test with sanitized, representative pcaps from your environment; compare model hypotheses to ground-truth parses.
2. Measure FP/FN on your telemetry and tune thresholds or post-processing rules.
3. Use the model to *augment* — not replace — deterministic parsing (e.g., lxml-based SOAP extraction) and host-event correlation.
4. Run adversarial tests to detect hallucination patterns and overfitting to synthetic traces.

---

## Deployment guidance (defensive-only)

* **Environment:** deploy within an isolated analyst workspace or secure sandbox with logging.
* **Rate limits:** enforce request throttles and operator approval flows for batch generation.
* **Prompt templates:** provide curated, short templates that emphasize detection goals and disallow exploitation suggestions. Example:

  ```
  DEFENSIVE_ONLY: Given the following sanitized SOAP snippet, list 3 indicators that would be useful for SIEM rules and propose a safe regex or http-inspector signature for detection. Do not provide exploit code or instructions.
  ```
* **Human review:** every generated detection signature must pass unit tests against labeled benign and malicious corpora before promotion.

---

## Provenance & reproducibility notes

* Training platform: **Vertex AI (Google Cloud)** for Gemini family fine-tuning.
* Fine-tuning recipe and hyperparameters: internal (sanitized summary available upon request to vetted partners).
* Model artifacts: private checkpoint(s) stored in controlled buckets; public derivatives will be documented with reproducible pipelines when released.

---

## Contact & citation

* Maintainer / Contact: **Rali0s / 3XCypher**
* Citation (preferred):

  ```
  Rali0s/3XCypher. (2025). deep-nim-sec-v1_v3 (gemini-v1-vertex-finetune-2025-10). wsman-guardian project.
  ```
* For security or provenance requests, contact: `3XCypher@pm.me` (see README.md)

---

## Ethics & responsible use statement

This model was created for defensive security research, analyst augmentation, and incident response support. It must **never** be used to design, test, or execute offensive actions against systems without explicit authorization. Misuse may violate laws and ethical guidelines.

---

*Document last updated: 2025-10-29*