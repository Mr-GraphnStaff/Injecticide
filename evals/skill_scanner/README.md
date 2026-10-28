# External skill evaluation inputs

This directory records public-source identities, licensing and label authority.
It is separate from `tests/fixtures/scanner_evaluation`, whose expectations were
authored while developing Injecticide. No external payload bodies have been
acquired by this assignment as of the initial lock files.

`skillfortify-claude.lock.json` selects all 180 Claude Markdown artifacts from
SkillFortifyBench at `eb9d5a9cbfa13b82ec3392d26dbae82fc6454b39`. Upstream labels
are deterministic generator labels, not independently adjudicated real-world
ground truth. The repository's MIT license must accompany any acquired copies.
The native filenames and bytes are preserved: this is a native Markdown view,
not a claim these single files are complete multi-file Agent Skills packages.
The actual pinned upstream notice is retained at
`third_party/SkillFortifyBench-MIT.txt` for the derived manifest metadata; the
copied notice does not change Injecticide's own license.

**Do not acquire or inspect these payload bodies before the coordinator freezes
the engine and runner.** SkillFortifyBench is SRC012 in MaliciousSkillBench's
source-disjoint test partition. Once exposed, this source cannot later be
described as unseen in that protocol. An explicit freeze ID records the caller's
attestation, not a cryptographic or independent guarantee of secrecy.

`anthropic-benign.sources.json` records three complete, pinned example skill
trees with individually verified Apache-2.0 licenses. Source files have not been
acquired yet. The publisher's legitimate purpose is a **benign assumption**, not
security ground truth: use these packages to inspect review burden, never to
inflate a human-adjudicated benign denominator. Preserve all scripts, references
and licenses when materializing them. The source-available document skills are
excluded; there is no repository-wide Apache-2.0 assumption.

## Offline runner

```powershell
python tools/skill_eval.py run evals/skill_scanner/skillfortify-claude.lock.json --split holdout --freeze-id ENGINE_AND_RUNNER_FREEZE_ID --output NEW_RESULT.json --artifacts NEW_ARTIFACT_DIRECTORY
python tools/skill_eval.py compare FIRST.json SECOND.json --output NEW_COMPARISON.json
```

Acquisition is a separate explicit step. The runner never downloads, installs,
imports or executes sample code. Every materialized file needs its original
SHA-256; raw single-file and reproducible whole-package ZIP views remain distinct.
Existing output files are not overwritten. Materialized artifacts should remain
outside normal source/release staging unless their license notices and intended
publication have been reviewed.

Both `security_block` and `security_review` thresholds are declared before
evaluation. PII presence, format errors and non-governance capability observations
do not automatically count as maliciousness signals. Missing/partial negative
coverage abstains; errors remain in the original class denominator. The output
reports unresolved bounds, category strata, exact artifact hashes, engine/runner
fingerprints and label origin. A complete scan with no selected signal is only
a negative result under that declared threshold, not a safety certification.

External scanner results require an explicit adapter producing the same run
schema: actual scanner/version contexts, declared profile mappings, all case IDs,
unchanged label authorities, input views and exact artifact SHA-256 values.
`compare` rejects missing cases and different inputs. Hash fields are claims from
the adapter; they do not authenticate the scanner or prove the adapter ran it.
No comparator has been executed merely by adding this ingestion contract.

## Recorded exposure and first diagnostic

The coordinator later authorized acquisition after freezing the engines and
runner. The original sealed manifests above remain unchanged. Freeze/exposure
receipts and a disclosed post-exposure scoring-adapter correction are recorded
in the release scratch evidence; aggregate v1/v2 results and their hashes are in
`docs/research/2026-10-28-skill-analysis-leadership/lena-evaluation-results.json`.
Both 0.10.0 and 0.11.0 produced identical selected security signals on the fixed
180-case native Markdown population. The low positive-signal recall and many
partial-coverage abstentions prohibit a superiority or general accuracy claim.
This corpus is now exposed and must not be called unseen in subsequent tuning.

Coverage scoring policy version 2 recognizes only the actual top-level
`complete_supported_content` status from `coverage_report`. Other complete-like,
partial or absent values abstain without an eligible positive. Comparisons
reject differing coverage policies; never compare amended scoring on one engine
with original scoring on the other. Original receipts are retained, and the
correction did not change engines, case bytes, labels or signal thresholds.
