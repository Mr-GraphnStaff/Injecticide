# Elena independent effects, evaluation runner and token-footprint review

October 28, 2026. Elena Voss, AI Security Architect reporting to Morgan Hale;
Avery coordinates and David leads. Actual Windows checkout:
`Y:/projects/Injecticide`, branch `codex/skill-effect-analysis-0-11`.
Role identities are fictional; commands and reproduced findings are actual.

This review covers Ishan's package effects engine, Avery's whole-report
reconciliation and token footprint, and the evaluation runner corrected by Mara.
Elena authored `improvement_plan.py` and its tests; those are expressly excluded
from this independent review. Other agents must review that slice. Earlier
launcher and diagram authorship is also excluded from independent approval.

## Findings corrected and independently retested

- Credential-dependent `int`, `len` and `bool` calls initially became proved
  source-free values, potentially suppressing an older finding. The corrected
  engine retains dependence or explicit uncertainty. Regression:
  `tests/test_package_effects_review.py:142`.
- Assigning `requests.post = print` initially left a stale known network sink.
  API attribute mutation now invalidates the known identity and exposes an
  unknown boundary. Regression: `tests/test_package_effects_review.py:152`.
- Selecting a known public dictionary member initially inherited an unrelated
  secret member. It no longer produces a proved secret payload solely from
  the sibling value. Regression: `tests/test_package_effects_review.py:158`.
- A dotted external import, `import urllib.request`, did not resolve using
  Python's actual binding semantics. A helper-mediated flow now retains the
  correct `urllib.request.urlopen` sink. Regression:
  `tests/test_package_effects_review.py:163`.
- `PurePath(...).read_bytes()` initially produced a known credential-file
  source even though PurePath has no I/O methods. Pure and concrete path kinds
  are now distinct (`skill_sandbox/package_effects.py:372`); both concrete Path
  reads and `open(PurePath(...)).read()` remain positive controls. Regression:
  `tests/test_package_effects_review.py:175`. Primary reference:
  <https://docs.python.org/3.12/library/pathlib.html#pure-paths>.
- The runner initially excluded `sensitive_data` credential-flow findings and
  admitted missing policy flags as eligible. Its explicit security threshold
  now includes credential flows, requires both policy flags to be boolean true,
  excludes PII/PHI presence, and abstains on relevant missing policy metadata
  (`tools/skill_eval.py:97`, `tools/skill_eval.py:108`). An independent eligible
  positive still wins over unrelated ambiguity. Regressions:
  `tests/test_skill_eval_review.py:32`, `:42`, `:53`, `:61`.
- The token footprint excluded a nested skill's own supporting files because
  an ancestor skill was treated as a descendant ownership boundary. Avery's
  correction limits exclusions to descendant roots in the same archive
  (`skill_sandbox/token_footprint.py:87`). Parent and child counts now agree
  with their actual files. Regression: `tests/test_token_footprint_review.py:5`.

## Additional independent challenges

The 23 effect test executions cover cross-file physical citations, source and
argument traces, context isolation, unused parameters, function rebinding,
local modules shadowing external package names, nested-archive containment,
recursion, decorators, starred arguments, positional-only arguments, unknown
guards, literal dead branches, whole-report legacy reconciliation, and secret
redaction including artifact names. Sources are parsed, never executed.

The footprint review checks exact extracted character/UTF-8 byte/physical-line
counts and sibling/archive ownership. Exact token counts remain null; the
mostly-ASCII four-character proxy is explicitly illustrative, excludes unsuitable
language/encoded content and does not claim runtime or billing usage. Existing
file/character/skill limits are explicit. No token hunger grade was inferred.

The runner source and contract tests were inspected without acquiring external
corpus payload bodies. Manifest input hashes, threshold identity, caller-declared
freeze identity, abstention denominators and comparative population checks were
reviewed. These tests do not authenticate a freeze or certify corpus labels.

## Actual commands and outcome

Executed independently:

```text
python -m pytest -q tests/test_improvement_plan.py tests/test_token_footprint_review.py tests/test_token_footprint.py tests/test_package_effects_review.py tests/test_skill_eval_review.py tests/test_skill_eval.py tests/test_package_effects.py
89 passed in 19.47s
```

That run includes ten author tests for the plan; they are useful verification,
not independent approval. After a narrow plan-only citation addition:

```text
python -m pytest -q tests/test_improvement_plan.py
11 passed in 7.04s
```

The independent-only closure run (excluding the plan) also passed:

```text
python -m pytest -q tests/test_package_effects_review.py tests/test_skill_eval_review.py tests/test_token_footprint_review.py
31 passed in 16.35s
```

After Avery identified an authored-plan citation-contract defect (legacy origin
paths are credential operands, whereas package origins name artifacts), Elena
corrected that module and added opposing regressions. The later combined run of
12 plan author tests plus these 31 independent tests passed 43 in 13.85 seconds.
A whole-scan synthetic assertion additionally verified the plan's artifact hash,
retained credential finding, manual questions and secret-valued path redaction.
Those plan checks remain author verification, pending another agent's review.

No remaining blocker was reproduced in the independently inspected engine,
runner or footprint scope. This is a bounded static semantic review, not a
general detection-accuracy result, maliciousness determination, runtime safety
certification, browser accessibility acceptance, deployment acceptance or proof
of industry leadership. No uploaded-code execution, package installation, paid
provider call, production mutation, commit or deployment was performed here.
Natural-language command-argument semantics and unmodeled languages remain
outside this engine's supported scope. The research memo records mechanisms,
source pins, reuse limits and a falsifiable follow-on experiment separately.

## Post-exposure evaluation-adapter amendment: version 2

After the first external evaluation, Avery reported a mismatch between the
runner's assumed top-level coverage value (`complete`) and the actual owning
scanner contract (`complete_supported_content`,
`skill_sandbox/package_evidence.py:106`). This is a scoring-adapter defect, not
a new detector result. The original runner and its outputs must remain distinct
from amended results. No external corpus payload bodies were inspected by this
review, and no detector or signal threshold was adjusted here.

Mara's amended runner accepts only the owning contract's exact complete value;
`complete`, unknown/future values, partial and absent status continue to abstain
when no eligible positive exists. It reports `coverage_policy.version = "2"`
and preserves explicit policy-metadata abstentions and the original denominator
formulas (`tools/skill_eval.py:27`, `:191`, `:209`). The amended comparator
rejects unequal declared coverage policies (`tools/skill_eval.py:230`); an
independent opposing-policy regression verifies this. Engine comparisons must
use both runs rescored under the same independently reviewed adapter, with
unchanged input hashes and declared thresholds. Comparing v1 against v2 would
confound this protocol correction with an engine change.

Independent new cases include actual harmless authored prose through the actual
scanner, five rejected status values, unchanged lower/upper-bound denominators,
and complete coverage with missing security policy metadata. An author-added
actual-SKILL regression initially supplied malformed plain-text bytes and
correctly received partial coverage; Mara corrected its local fixture to valid
frontmatter and updated its manifest hash. No engine correction was needed.

Actual final command:

```text
python -m pytest -q tests/test_skill_eval.py tests/test_skill_eval_review.py
41 passed in 15.07s
```

Reviewed runner SHA-256:
`7615d8d22f973570302de05ba5f8ef859bb8875461b150d57fb3b0b9bef1d822`.
No remaining blocker in this narrow adapter correction. This review does not
certify external labels or results, and the post-exposure timing must be
disclosed in the evaluation record.
