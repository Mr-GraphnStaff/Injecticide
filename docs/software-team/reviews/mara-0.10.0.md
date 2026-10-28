# Mara — independent backend and integration QA, 0.10.0

Reviewer: Mara, reporting to Avery. Actual host: Windows, checkout on the Pi
network share. This pass reviews code authored by Ishan, Elena and Avery. Mara's
standards UI, earlier diagram UI and PNG helper are excluded from independent
approval here; those need a separate reviewer.

## Candidate verdict

**Complete with stated limitations: backend QA passes within the reviewed
scope.** The three reproduced findings below were corrected by their owners and
independently retested. Final bounded suite: **202 passed**. This is not release,
deployment or production acceptance, and it does not independently approve
Mara's UI implementation.

## Requirements and observations

- Portable mandatory checks must identify the constraints actually measured.
  Vendor acceptance, authoring recommendations, security taxonomy relevance and
  runtime evaluation remain separate. No complete-compliance claim is supported.
- Uploaded code, launchers and PEP 723 dependencies remain data. Syntax
  recognition does not establish installation, runtime behavior or safe execution.
- Root integration attaches standards assessment before governance/readiness
  decisions and common redaction, then builds the diagram from sanitized
  evidence. For the explicit generic profile, failed or unassessed mandatory
  portable checks require further analysis; this does not assert acceptance by
  any vendor. Existing stronger block decisions are preserved. The sandbox Dockerfile
  includes both new modules and the existing rules-directory copy includes the
  source catalogs. No workflow, authentication or paid-service activation was
  part of this reviewed slice.
- The source-check CLI uses fixed reviewed HTTPS hosts, refuses redirects,
  caps received bytes and distinguishes changed/unavailable sources. It does
  not rewrite catalog hashes or activate downloaded rules. Its comparison is
  byte-based, not a semantic compatibility decision.

## Findings corrected and independently retested

1. **P2 — arbitrary nested resource directories become invented skills.**
   A valid `demo/SKILL.md` plus `demo/assets/skills/training/data.csv` reports
   missing `demo/assets/skills/training/SKILL.md` and overall `fail`. The primary
   specification explicitly permits arbitrary additional directories. A folder
   named `skills` inside an existing skill is insufficient evidence of a new
   skill collection. **Closed:** directory-name collection hints are now
   non-mandatory, unassessed observations outside recognized skill roots. The
   valid nested-resource fixture passes without an invented missing skill.
2. **P2 — incomplete inventory becomes a proven missing entrypoint.**
   `skills/demo/references/note.md` with `coverage.status=partial` reports
   missing `skills/demo/SKILL.md` as `fail`. Partial archive inventory cannot
   establish absence; that result must remain `not_assessed`. The paired complete
   inventory can still fail when the user explicitly selects a portable skill
   archive. **Closed:** complete and partial paired fixtures now return fail
   and not assessed respectively.
3. **P2 — raw manifest command edge retains a placeholder source line.**
   A pretty-printed `package.json` command on line 3 produces an execution edge
   with `line=1` and no accuracy qualifier. The diagram correctly downgrades the
   citation to file-only, but exported raw graph consumers lack that qualifier.
   **Closed:** raw manifest references and capability observations now expose
   null physical line numbers; exported consumers are no longer given a
   fabricated exact line. A null line or an explicit file-only qualifier both
   satisfy the regression's evidence requirement.

## Checks actually performed

- Read the final-candidate implementations of `standards_assessment.py`,
  `package_formats.py`, `script_launchers.py`, changed graph parsing, root
  attachment/redaction ordering, the source catalogs, source-check CLI and
  sandbox Dockerfile. Authors were still finalizing their slices at review start.
- Existing focused suite: **86 passed** across standards, launchers, source
  comparisons, redaction and Dockerfile contracts.
- Added independent `tests/test_standards_review.py`. Initial four cases:
  **2 passed, 2 failed**, reproducing the two portable classification defects.
  The passing complete-inventory control and whole-report integration case
  establish the positive behavior within those authored fixtures.
- The integration case scans an actual synthetic skill archive, resolves its
  documented `uv` script, inventories PEP 723 declarations, keeps security/vendor/
  runtime axes unassessed and verifies a synthetic credential is absent from the
  complete serialized report. Uploaded Python contains a deliberate exception;
  it is never imported or executed by this static scan.
- Added a fifth independent assertion for raw manifest citation accuracy.
- Final incremental review included the shared launcher integration in
  `package_threats.py`, legacy interpreter preservation, root governance guard,
  path-list redaction and manifest file-only citations. Final independently
  executed suite: **202 passed in 65.82 seconds**, covering
  `test_standards_review`, `test_skill_standards`, `test_script_launchers`,
  `test_standards_source_check`, `test_evidence_redaction`,
  `test_skill_sandbox_dockerfile`, `test_package_graph`,
  `test_package_analysis` and `test_process_diagram`.
- Independently retrieved the official portable specification and computed
  SHA-256 `9a67de89132948b2300b8dc87b93817971d47f9be89b644444965881a8dfde16`
  over 7,608 response bytes, matching the pinned catalog snapshot. The official
  text confirms Unicode lowercase naming, optional compatibility length,
  unrestricted Markdown body, arbitrary extra directories and authoring guidance.
- Read the official PEP 723 specification for block syntax, top-level comments,
  duplicate-block errors and dependency/version-syntax scope. Reviewed root's
  separate source-comparison artifact as supplied evidence, not as an independent
  live rerun of all sources.

Primary sources: [Agent Skills specification](https://agentskills.io/specification.md),
[PEP 723](https://peps.python.org/pep-0723/).

## Reviewed source fingerprints

SHA-256 of reviewed backend source at final retest:

| File | SHA-256 |
| --- | --- |
| standards_assessment.py | BFC3BDBECE8D2D9FDB64109016086909E52F5F6F11F1894724AC9C00B7FE532E |
| package_formats.py | F15D2EF06DDBE8343E83F2D9FC2A81558F7C8B2D2E8C8273267DE6B9227922A5 |
| script_launchers.py | 4F812F8DC1DA7FDB9A19C27E1E94D5516829DECF4CA925A9E64891349630B6B5 |
| package_graph.py | F72F8062F7663468703073156ACEC626B2036848AE480972947E7BB76DC1907E |
| package_threats.py | DF713DAADBB07AAEA4D50F819437775C7F827D638A99B034B082D67D5006E24F |
| package_analysis.py | 16A4399791C628FCE186DD3A3CEC925560442FBE92F21A9AFD9DE722CD203E2C |
| evidence_redaction.py | 288F839B7699C6AE7947F94B9EE8AA4DCA4F58B7281E4B0217240B5C50759FEE |

Root may add reviewed launcher source pins after this pass. Those catalog-only
additions are outside the frozen source fingerprints above and require their
own recorded source evidence.

## Limits

Authored fixtures do not establish representative scanner accuracy. This pass
does not test real uploaded skills on a vendor runtime, install declared
dependencies, build the Linux container or establish deployment/live acceptance.
PEP 723 semantic validation remains explicitly unknown if the optional installed
parser is unavailable. UI/accessibility review, complete project CI, container
build and live deployment acceptance remain separate work. Reopen this review
for functional changes to the fingerprinted backend files.
