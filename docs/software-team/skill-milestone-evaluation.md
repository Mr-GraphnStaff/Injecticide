# Skill inspection milestone evaluation

Lena owns this evaluation, separately from the inspection implementation. Actual
runtime: Windows Python 3.12 against the Injecticide checkout on the network share.
The fixtures are newly QA-authored synthetic packages. Their labels express
authored intent; they have not received independent human labeling and are not
a held-out or representative production corpus. This is milestone regression
evidence, not a world-class or market-accuracy certification.

## Outcome contract

- ZIP and renamed `.skill` archives receive equivalent inspection.
- Instruction overrides in direct, linked and nested references receive
  actionable findings with package locations.
- Encoded instructions and scripts that read a sensitive path and transfer its
  content are evaluated across package contents, not only the main document.
- Public-research, credential-education and pure formatting controls do not
  receive actionable high-risk security findings. A clearly quoted attack example is
  educational content; documentation context must not become a blanket trust
  exemption.
- Unsafe archive members, unknown assets and exhausted text budgets stay visible
  as incomplete inspection. Resource protection is preserved.
- The benchmark records missed hostile cases even when coverage is incomplete.
  Coverage is reported alongside detection, never used to erase misses.
- External model comparisons are prepared offline with identical deterministic
  artifact hashes and bounded literal text views. No provider execution or
  superiority is claimed by exporting inputs or importing someone else's report.

Scenario categories are supported by the primary
[OWASP prompt injection prevention guidance](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html),
including direct and indirect instructions, encoded content and code/document
surfaces. The exact fixtures are authored tests, not reports of real incidents.
All network addresses in hostile examples use `.invalid`; fixture code is never
executed.

## First executed baseline

Executed October 27, 2026, before the milestone detection fixes:

```powershell
python tools/skill_milestone_benchmark.py run --output tmp/skill-milestone-baseline.json
python -m pytest tests/test_skill_milestone.py -q
```

The 12 packages contain four benign controls, six hostile scenarios and two
coverage challenges. At the explicit decision threshold of at least one block
finding, the first baseline detected four of six hostile scenarios and blocked
one of four benign controls: precision 0.8, recall 0.6667, false-alarm rate 0.25
on these authored cases only. No provider baseline was run.

The independent outcome tests initially produced 25 passes and three failures:

| Case | Expected outcome | Observed initial outcome |
| --- | --- | --- |
| Base64 reference accompanied by instructions to decode and follow it | Actionable detection | No block finding |
| Python script reading `~/.ssh/id_rsa` into an HTTP POST | Actionable detection | No block finding |
| Explicitly quoted fenced prompt-injection teaching example | No block finding | `prompt_override` block finding |

These labels remain unchanged. Fixes require rerunning the same deterministic
artifacts; this record preserves the failed baseline instead of replacing it.
Later verification results belong in the section below.

## Reproducible commands

```powershell
python tools/skill_milestone_benchmark.py run --output tmp/skill-milestone-current.json
python tools/skill_milestone_benchmark.py export tmp/skill-provider-baseline
python tools/skill_milestone_benchmark.py provider path/to/provider-response.json
python tools/skill_milestone_benchmark.py compare tmp/skill-milestone-current.json path/to/provider-response.json
```

`export` creates a new directory and refuses to overwrite an existing directory.
It writes the actual ZIP bytes and `requests.json`, with opaque case identifiers
and no answer labels. Text is supplied literally, with file boundaries, original
and supplied lengths, a shared 200,000-character budget, explicit omissions and
a text-view hash. Binary inspection requires supplying the original artifact to
a provider that supports it. The scanner receives the full package; a model
given only the text projection has a different inspection scope. That difference
is retained in comparison output.

External responses must state provider/model/version, input scope, the original
artifact SHA-256 and, for text projection, the matching view hash. `detected`
requires evidence pointing to an actual package member. Unknown and duplicate
case IDs, duplicate JSON keys, mismatched hashes and malformed evidence are
rejected. Missing responses count as abstentions. Hash binding establishes input
identity, not that the named provider actually executed a review or read the
whole input. Descriptions are not accepted as proof that a finding is correct.

The comparison recomputes both sets of authored-case metrics from individual
decisions and known labels rather than trusting supplied aggregate scores.
Each measured scan retains its reported engine metadata, including its source
hash when supplied; comparison carries that provenance without treating an
imported report as independent execution proof. Missing metadata is explicit.
Coverage-challenge packages are kept outside precision/recall denominators.
No automated comparison declares general superiority.

## Subsequent verification

After integration, `python -m pytest tests/test_skill_milestone.py -q` passed all
30 checks. The same 12 deterministic packages were rescanned into
`tmp/skill-milestone-current.json`: all six hostile scenarios produced actionable
security detection, all four benign controls remained below that threshold, and
the two coverage challenges retained their explicit incomplete assessment.

The current detection threshold counts a block-tier finding **or** an actionable
high-severity finding explicitly counted for governance. This distinction permits
a credential-source-to-network-payload finding to require review without claiming
proven malicious intent through a block tier. Ordinary network/file capabilities
and structural anomalies do not qualify. Block findings, review burden and
informational counts remain separately reported. The first recorded baseline
above used block tier only; it is preserved with that threshold explicitly
identified, rather than being silently reinterpreted.

Independent QA also reproduced and reported two graph defects: a malformed
scheme-relative URL raised an uncaught exception, and an inner archive reference
could resolve across its container boundary. The graph owner corrected both;
Lena reran the original reproducers and observed an explicit malformed-reference
partial result and an outside-package relationship respectively. Independent
Python dataflow probes detected direct and aliased credential payload transfers
while keeping ordinary public-file transfers, authentication headers and
overwritten credential values free of that finding. This does not prove general
language or control-flow coverage.

Lena independently ran the five implementation suites for assets, nested
archives, package relationships, Python credential value flow and decoded text:
82 checks passed. An additional assembled-package probe placed an instruction
override and a synthetic credential declaration in PNG metadata: the scanner
reported the override with `asset_metadata` provenance, retained the original
asset hash, and did not reflect the synthetic credential literal anywhere in the
returned JSON. A font extraction counter initially overstated records visited
after an early metadata-budget stop; the author fixed it and the independently
executed asset suite includes its regression.

The offline provider bundle was actually exported to
`tmp/skill-provider-baseline`, with 12 artifacts and answer-blind requests.
Its status is prepared, not executed against any provider.

## Independent browser verification

Lena extended `tests/browser/scanner_evidence_0_7.cjs` against Avery's final UI
changes and executed it using headless Microsoft Edge and locally available
pinned React/Babel fixtures. The harness passed, with no page errors. Its API
responses are synthetic and separate from the executed Python-engine checks.

Observed checks cover the inspection-stage summary, relationship disclosure by
keyboard, 13 relationship rows paged ten at a time, keyboard pagination, page
reset on section selection, asset-structure evidence, nested archive provenance,
and detailed Markdown export containing the new graph/asset/archive fields.
An HTML-shaped uploaded relationship label remained literal JSON text: no image,
SVG or script elements were created and its event handler did not execute. The
raw synthetic upload marker was absent from the exported report. The harness
also retained its prior recovery, stale-response and legacy-report checks;
legacy results without any graph, inspection-stage or asset/archive fields
remained readable.

The page had no document horizontal overflow at 390px and 1440px widths.
Screenshots were written to `tmp/scanner-evidence-0-7-mobile.png` and
`tmp/scanner-evidence-0-7-desktop.png`. This is automated keyboard and responsive
browser evidence, not screen-reader certification, human UAT or a live production
upload. The first added literal-label assertion needed JSON escaping to match
the deliberately JSON-formatted display; no product change was required for it.

Original user ZIP bytes are not in
these fixtures; inspecting the supplied report does not establish a rescan of
that artifact. Live deployment, image OCR/rendered contents, customer-skill
execution and paid-provider comparisons are outside this executed baseline.

## Final integration verification

The final-source complete project suite, with the existing isolated MCP SDK
2.3.0 included on the test process's PYTHONPATH, passed **640 tests, zero failures
and zero skips**, in 190.28 seconds. The exact command was
`python -m pytest tests -q`; it deliberately targets the project's tests and
does not collect third-party temporary dependency test directories.

Both browser harnesses passed. The lifecycle harness exercised 12 repeated
reports with 200 files and 8,000 findings each; visible rows stayed bounded and
post-GC heap measurements stayed about 10.7–10.8 MiB in that synthetic workload.
The container COPY context was reconstructed locally and its standalone scanner
imports and malicious-instruction scan passed. This is packaging/import evidence;
a Docker image was not built or run on this host.

The final 12-package authored benchmark still detects all six hostile scenarios
and produces no actionable-high/block alarms for the four benign controls; two
coverage challenges stay separate. Each case records its scanner engine hash.
The four real public-package observations share that same final engine hash.
The independent security reviewer closed every reproduced finding in the scoped
review. Complete machine-readable evidence is in
`docs/validation/2026-10-27-skill-milestone-0-8.json`.

These results establish the tested static implementation, CLI, local MCP
transport and reporting behavior. They do not establish live deployment, the
original customer ZIP result, runtime safety or representative accuracy. No
model-provider comparison was run and no external spending was authorized.
