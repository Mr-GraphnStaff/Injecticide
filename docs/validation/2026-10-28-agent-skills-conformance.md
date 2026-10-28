# Agent Skills conformance — 0.10.0

The portable baseline is the official Agent Skills specification, retrieved on
October 28, 2026. Its reviewed byte fingerprint is
`9a67de89132948b2300b8dc87b93817971d47f9be89b644444965881a8dfde16`.
This fingerprint identifies a snapshot, not an upstream release number.

## Requirements and evidence

The machine-readable requirements matrix is
`skill_sandbox/rules/skill_standards.json`. Each row identifies its specification
section, mandatory/recommendation/status level, implementation state and test
reference. Reports retain per-requirement status, applicability and source
evidence rather than treating the matrix as a certificate.

| Area | Measured behavior | Paired evidence |
| --- | --- | --- |
| Entrypoint | Exact `SKILL.md`; complete missing/case-mismatched entrypoint fails; incomplete inventory remains unknown | `test_missing_entrypoint_and_name_directory_match_have_different_evidence`, `test_case_sensitive_entrypoint_and_unavailable_content_never_false_pass` |
| YAML and identity | Mapping, required name/description, lengths and name syntax; directory match only when the actual parent is known | `test_true_syntax_and_ambiguous_mapping_errors_fail_measured_frontmatter`, `test_no_body_minimal_spec_example_and_unicode_name_are_not_invented_failures` |
| Optional fields | Compatibility is 1–500 characters when present; metadata string map; experimental allowed-tools string | `test_compatibility_optional_field_explicit_one_to_five_hundred_boundary`, `test_optional_portable_field_types_are_measured` |
| Extensions and recommendations | Unknown/vendor keys do not invent a mandatory baseline failure; body/line guidance is separate; no estimated token-count pass | `test_vendor_extensions_do_not_invalidate_portable_base`, `test_recommendations_are_not_mandatory_format_failures_or_estimated_tokens` |
| Limits | Parser/inventory/report limits remain explicit, never a complete format pass | `test_parser_limits_are_not_portable_invalidity`, `test_row_and_skill_budgets_never_report_complete_pass`, `tests/test_standards_review.py` |
| Launchers | Recognized documented subset resolves actual local target; package names/options/arguments do not become guessed script paths | `tests/test_script_launchers.py`, `tests/test_package_graph.py` |
| Inline dependencies | Bounded PEP 723 declarations; malformed, unavailable-parser and budget cases unknown; dependencies never installed | `test_pep723_static_inventory_has_exact_block_line_and_no_runtime_claim`, `test_metadata_duplicate_unclosed_string_mention_and_unavailable_parsers` |
| Whole scan | Generic mandatory failure/unknown informs readiness and execution recommendation; credentials redacted from report and map | `tests/test_standards_integration.py`, `tests/test_standards_elena_review.py`, `tests/test_standards_review.py` |
| Reports | Five separate assessment axes; sources, limits, unknowns and full Markdown evidence; keyboard/reflow/hostile-label coverage | `tests/browser/skill_standards.cjs` |

Test names without a path above are in `tests/test_skill_standards.py` unless
they concern launchers/inline metadata (`tests/test_script_launchers.py`).
The matrix's runtime, security coverage and vendor acceptance rows are explicitly
unassessed. Trigger accuracy, output quality, script behavior and actual tool
permission enforcement require separate runtime evaluation.

## Source changes

`python tools/check_skill_standards_sources.py --output NEW_FILE.json` explicitly
compares the fixed reviewed primary-source catalog. It accepts no uploaded
package URLs, uses allowlisted HTTPS hosts, refuses redirects, caps each response
at 2 MiB and never overwrites existing output. Exit codes: 0 unchanged snapshots,
1 changed sources needing review, 2 unavailable/unverified or omitted sources.
Scanning itself makes no source-check network requests. No source change
automatically activates rules.

The release comparison found changed bytes on the OWASP landing page and uv CLI
page; both remain flagged, with the originally reviewed pins preserved. A byte
change alone establishes no semantic incompatibility. The core specification,
authoring/client/vendor references, PEP 723, uv script guidance and OWASP detail
taxonomy matched their pins. Launcher references are recorded individually in
`standards_sources.json`; semantic claims cover only the documented parser subset.

OWASP Agentic Skills Top 10 is an incubator advisory taxonomy. Reported detector
relevance is authored by Injecticide reviewers and establishes neither OWASP
certification nor verified exploitability or complete coverage.

## Release acceptance

Independent reviews and exact candidate/pipeline/live evidence are recorded in
the software-team review receipts and the companion 0.10.0 deployment record.
Authored synthetic fixtures verify specified behavior; they do not establish
general accuracy across all vendors or all real-world skill packages.
