# Vendor requirements validation — October 26, 2026

Candidate: 0.6.0, unreleased. No deployment, commit, push or human release acceptance
was performed. Work was verified in the existing `codex/scan-results-layout`
checkout. Existing unrelated research-plan, validation and architecture changes
were preserved.

## Automated validation

- Full Python suite: `python -m pytest -q tests` — **327 passed, no skips**.
- Final focused checks after coverage-status and reason-message corrections:
  `python -m pytest -q tests/test_vendor_requirements.py` — **15 passed**.
- Browser: `node tests/browser/skill_scan_lifecycle.cjs` — **PASS**, including
  the unknown vendor panel, a documented vendor-limit failure headline, expanded
  measured results and Markdown evidence export. Existing cancellation, stale
  responses, pagination and 12 large repeated-scan checks still pass. The focused
  panel screenshot was inspected in the synthetic browser fixture; this is not
  production UI validation.
- `git diff --check` passed.

The official `mcp==2.3.0` SDK and missing runtime modules were loaded from a
temporary test directory. No global Python package changes were made. Early
dependency-isolation attempts failed or skipped MCP coverage; the successful
full-suite result above included the MCP tests with no skips.

## Live evidence

All six profiles initially retrieved their official documentation and matched
reviewed fingerprints: OpenAI plugin skills, OpenAI submission-time MCP skill
import, Claude Code, Claude custom skill uploads, Gemini CLI and Copilot CLI.
Only the four selected platform families received new requirement profiles.

The explicit end-to-end probe starts a loopback Research MCP HTTP service,
scans a harmless local fixture through the actual web scan helper, and makes
public documentation requests through the research service. No model completion,
vendor upload, customer data or credential is used. The first end-to-end run
confirmed live reviewed documents for all six profiles and detected the intended
Claude upload failure: 201 description characters against a documented 200.

A repeat run confirmed four profiles and returned **unknown** for Copilot and
OpenAI MCP import when live verification did not complete. The client returned
no substituted cached pass. This is a real availability limitation, not a claim
that these vendors no longer support the feature. Machine-readable evidence
preserves this repeat outcome alongside the initial successful direct checks.

Tests also cover changed content, HTML presentation-only changes, stale/failed/
disabled sources, valid 304 revalidation, concurrent checks, ambiguous targets,
metadata boundaries, MCP import size/count scope, incomplete inventory, the MCP
tool, bounded HTTP input and sending only a product identifier.

## Reproduce

Install the repository and Research MCP requirements in an isolated Python
environment, then run:

```powershell
python -m pytest -q tests
python tests/vendor_requirements_probe.py --output-dir tmp/vendor-requirements-probe
```

The second command intentionally performs live public-document retrieval.
It records successful and unknown outcomes without silently updating baselines.
The current reviewed constraints and product scope are documented in
[vendor requirements](../vendor-requirements.md). Detailed observed evidence is
in [the JSON record](2026-10-26-vendor-requirements.json).

Unknown package sizes, asset/file-type allowlists, generated artifacts and tenant
policies remain unknown. Passing individual documented metadata or file-size
checks is not an overall compatibility or security certification. Production
build/container validation and human release acceptance remain pending.
