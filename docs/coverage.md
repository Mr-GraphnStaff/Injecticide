# What the scanner covers

This table shows, by threat type, what Injecticide's static scanner detects. It
covers the source tree at release 0.16.0 preparation (base commit 1b039ed plus
the 0.16.0 labels). Plain-English names for every finding id are in
`skill_sandbox/rules/finding-labels.json`.

Status meanings:

- **Detected**: a detector targets this threat and has regression tests. Even so,
  a clean result does not prove the threat is absent.
- **Partial**: some forms are detected. The gaps column lists forms that are not.
- **Not detected**: nothing in the scanner looks for this.

Every detector is static. The scanner never runs uploaded code, never contacts
uploaded URLs and never calls a model. Detectors run on one file's text at a
time, so content split across several files is not joined.

| Threat | Status | Module / finding ids | Concrete gaps |
| --- | --- | --- | --- |
| Prompt injection / instruction override | Partial | `scan_rules.py`, `contextual_rules.py`, `speech_acts.py`; `prompt_override`, `tool_escape`, `workflow_manipulation` | Uses English keyword patterns (for example "ignore/override/bypass" followed by "previous/prior/system"). Not detected: paraphrases without those words, other languages, instructions split across files or rows, and instructions in image pixels. |
| Disclosure requests (system prompt, secrets) | Partial | `system_exfiltration`, `secret_exfiltration`; topic-only mentions go to `sensitive_topic` / `sensitive_keywords` | Same keyword limits as above. A request finding means text *asks* for disclosure. It does not mean a secret is present. |
| Hardcoded secrets | Partial | `secret_detection.py`; `hardcoded_secret`, `literal_credential_declaration` | Covers the listed vendor key formats, PEM keys, connection strings, JWTs and high-entropy credential assignments. Not detected: secrets split across lines or files, secrets in binaries, secrets behind more than one base64 layer or other encodings, and unlisted formats. Whether a key still works is never checked. |
| PII / PHI | Partial | `sensitive_data.py`; `pii_email_address`, `pii_phone_number`, `pii_ssn`, `pii_date_of_birth`, `pii_account_identifier`, `phi_medical_record_number`, `phi_patient_record` | Pattern-based, with US formats for SSNs. Not detected: names, home addresses, non-US national IDs, free-text health details without an identifier, and data in images or binaries. |
| Contact directories | Not detected at base; 0.16.0 work in progress | `contact_directory` (labelled; detector owned by the database-assets work) | Until that detector lands, a staff directory shows up only as individual `pii_email_address` / `pii_phone_number` findings in sampled rows. |
| Disguised executables | Partial | `package_threats.py`, `asset_inspection.py`; `executable_packaged_as_document`, `code_in_text_artifact`, `declared_execution_target`, `asset_signature_mismatch`; planned `embedded_executable_blob` | Detects source code under document names and image/font names whose contents don't match. Not detected: compiled programs (PE, ELF, Mach-O) under arbitrary names, which are only reported as binary content not inspected. |
| Code execution / subprocess | Partial | `code_security.py`, `scan_rules.py`, `script_launchers.py`; `dynamic_exec`, `subprocess_spawn`, `declared_tool_execution`, `declared_process_launch`, `dangerous_file_ops`, `self_modifying_skill`, `dynamic_import_construction` | Regex patterns run over any text file. Only Python is parsed into an AST; other languages get patterns only. Not detected: indirection deeper than the recognised patterns, and anything only visible at run time. |
| Network and exfiltration flows | Partial | `code_security.py`, `package_effects.py`; `network_calls`, `url_fetch`, `credential_source_to_network_payload` | Credential-to-network flow is tracked inside a single Python function only. Not detected: flows across functions or files, flows in other languages, DNS or covert channels, and destinations (never contacted). |
| Dependency install | Partial | `runtime_dependency_install`, `declared_process_launch`; `script_launchers.py` (PEP 723 / launcher parsing) | Declarations are found but packages are never resolved. Not detected: known-vulnerable, typosquatted or hallucinated package names. |
| Unicode deception | Partial | `unicode_deception` | Matches bidirectional controls (U+202A–U+202E, U+2066–U+2069), zero-width characters (U+200B–U+200D) and U+FEFF. Not detected: look-alike (homoglyph/confusable) characters and Unicode tag characters (U+E0000 block). |
| Encoded payloads | Partial | `text_projections.py`; `base64_usage` | One base64 layer is decoded and re-scanned as data. Not detected: nested layers, hex, URL-encoding, ROT13, compression inside text, and payloads split across lines or files. |
| Nested archives | Detected (bounded) | `nested_archives.py` | ZIP-in-ZIP is expanded within shared file, byte and depth budgets. Anything past a budget, and unsupported compression methods, are listed as not inspected and are not scanned. Non-ZIP archives (tar, 7z, rar) are not expanded. |
| Database contents | Partial | `artifact_text.py` (SQLite rows sampled within budgets); 0.16.0 adds `database_profile`, `database_not_cleared`, `opaque_database` | At base, only a bounded sample of TEXT values is read. BLOBs are counted, not inspected. Rows past the budget, triggers, views and freelist pages are not scanned. Other database formats are not opened. |
| Binary / media | Partial | `asset_inspection.py`; `png_*`, `font_*`, `asset_signature_mismatch`; Office text in `artifact_text.py` | PNG structure and text metadata, sfnt font tables and names, and DOCX/XLSX/PPTX text are covered; SVG is XML text and gets the text detectors. Not detected: image pixels (including text drawn in images), JPEG/GIF/WebP structure, PDF content, audio and video, and font programs. |
| MCP transport | Partial | `finding_enrichment.py`, `package_threats.py`; `insecure_mcp_transport`, `unverified_mcp_server`, `insecure_component_transport` | Flags http addresses and hosts missing from Injecticide's known-host list. Servers are never contacted. Not detected: weak authorization, tool-description poisoning on the live server, or a trusted host that has been compromised. |
| Supply chain / provenance | Partial | `package_review.py`, `review_evidence.py`, `governance.py` (GOV-01..05 in `package_checks.json`) | Hashes are computed, and signatures are verified only against trust anchors an administrator has configured. Not detected: upstream compromise of a correctly signed package, and package reputation. |
| Enterprise automation claims | Partial | `autonomous_authoritative_write`, `bulk_enterprise_modification`, `cross_system_automation`, `workflow_manipulation` | English keyword patterns only. Whether the access actually exists is not checked. |
| Runtime behaviour | **Not detected** | none | Nothing is executed or emulated. Behaviour that appears only at run time is not seen: downloaded second stages, time bombs, environment-dependent branches and model-driven actions. |
| Multi-file split secrets or instructions | **Not detected** | none | Detectors read each file on its own. A key or instruction split across files (or across database rows) is not reassembled. |

## Standing review question

What does this table say is not detected, and is that still acceptable for this release?
