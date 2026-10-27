# Local scanner evaluation and report comparison

These tools provide reproducible regression evidence. They do not establish
independent benchmark accuracy, safety certification or superiority over another
auditor. No corporate skill package is included in this corpus.

## Run the authored synthetic evaluation

From the repository root:

```powershell
python tools/scanner_evaluation.py evaluate --output evaluation.json
```

The manifest is `tests/fixtures/scanner_evaluation/manifest.json`. It records
manual authorship and expected signal/coverage contracts, not independently
human-labeled ground truth or a held-out sample. ZIPs are generated in memory
with fixed timestamps so package hashes can be reproduced. No package files
are extracted by the evaluation tool, and no uploaded scripts or LLM requests
are run. The scanner can run its reviewed bundled metadata-only format
validators; the evaluation tool never retrieves executable validator code.

The cases cover enterprise directory contacts in two files, benign code stored
behind a documentation extension, quoted attack examples versus active attack
instructions, multilingual benign material, malformed configuration, text-limit
boundaries, and creator chunk-reading/EOF marker inputs. Multilingual benign
coverage does not establish detection of non-English attacks.

The JSON output separates:

- Expected/observed finding IDs and per-rule expected-present/absent counts.
- Missing signals in inspected cases from signals not evaluable because coverage
  is partial. A canary after the supported text limit is an incomplete case,
  not a successful negative detection.
- Authored benign cases with block findings and their review-finding burden.
  A legitimate packaged script can have review findings without being malware.
- Coverage status and unverified vendor/runtime status from detection results.

Only explicitly labeled expectations contribute to per-rule expected-absence
counts. Other findings are observations, not automatically false positives.
`matched` means the authored assertions matched, not that the package is safe or
that every detector covered every byte. `incomplete` preserves uninspected
expected signals. `mismatch` flags failed contracts and returns exit code 1.

Exit codes: 0 means no mismatched contracts (incomplete cases can remain), 1 means
one or more contract mismatches, and 2 means invalid CLI/input. Consumers must
check `incomplete_cases` separately rather than interpreting exit code 0 as full
coverage. The JSON manifest is the auditable definition of the expected cases.

## Compare exports of the same package

```powershell
python tools/scanner_evaluation.py compare first.json second.json --output comparison.json
```

Both inputs must use the Injecticide-compatible JSON report structure and
include the same valid `governance_evidence.artifact_sha256`. Missing or different
hashes are rejected. External auditor reports need an explicit conversion that
preserves their actual evidence and unknowns; the tool does not invent hashes
from filenames or claim arbitrary text reports are compatible. Matching digest
claims are not authenticated authorship or proof that a report is truthful.

The comparison aligns file paths and rule IDs, retaining source-line locations
when supplied. Samples and observation text are not copied to the comparison.
It reports matched signals, location/disposition differences, absence following
explicit complete detector coverage, content known not to have been inspected,
and unknown inspection. A legacy `text_analyzed` label by itself leaves absence
unknown. Missing location data cannot establish occurrence-level agreement.

Known scanner/catalog/runtime differences are contextual annotations, not proof
of the cause of a discrepancy. An explicitly verified creator mitigation is
reported separately and never suppresses a differing security finding. Neither
input is appointed ground truth. Even matching results do not establish that
both scanners are correct.

The CLI reads bounded local UTF-8 JSON, rejects duplicate JSON keys, writes only
the requested output, and never submits reports or packages to another service.
Report paths can themselves contain private information; keep exports under the
same handling rules as their source reports.

## What a defensible external benchmark still needs

Extend this regression corpus with consented/public packages and verified attack
cases, independent labeling and adjudication, held-out attack families, documented
sampling, and results stratified by format, language, attack type and inspection
coverage. Publish sample counts, false-block rate, per-rule precision/recall,
review burden, abstention/unknown rates, runtime, memory, exact revisions and
corpus hashes. A small authored regression suite cannot supply those claims.
