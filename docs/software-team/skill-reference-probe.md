# Pinned public skill inspection probe

Elena executed this independent read-only probe on October 27, 2026, using the
Windows Python runtime against the Injecticide checkout. Four complete public
skill directories were downloaded, assembled into deterministic ZIP packages,
and passed to `scan_upload`. **Fetched code was never executed or imported.**
These are unlabeled observations, not assumed benign packages, detection-accuracy
measurements, vendor endorsement, or evidence of safe execution.

## Sources and reproducibility

The current [OpenAI Skills README](https://github.com/openai/skills) states that
that repository is deprecated and directs readers to
[OpenAI Plugins](https://github.com/openai/plugins). This probe therefore uses
current examples from `openai/plugins`, not deprecated `openai/skills` examples.
An official repository location establishes the observed source, not the safety
or original authorship of every example it hosts.

Immutable whole-directory inputs:

- [Anthropic PDF](https://github.com/anthropics/skills/tree/dbd4588f9e1033efb41dad4bef2f7947c8993d44/skills/pdf)
- [Anthropic DOCX](https://github.com/anthropics/skills/tree/dbd4588f9e1033efb41dad4bef2f7947c8993d44/skills/docx)
- [OpenAI plugin creator](https://github.com/openai/plugins/tree/0722921d5542fc593105c27bd52630babd8b8c2a/.agents/skills/plugin-creator)
- [OpenAI repository security-scan example](https://github.com/openai/plugins/tree/0722921d5542fc593105c27bd52630babd8b8c2a/plugins/codex-security/skills/security-scan)

Local evidence is retained in `tmp/skill-reference-probe/`: `probe.py`, pinned
repository tree responses, the four deterministic ZIPs, original downloaded
files, individual raw reports, and `manifest.json`. The manifest records every
immutable raw URL, Git blob SHA-1, downloaded SHA-256, size, package hash, elapsed
time and scanner metadata. Every downloaded blob's Git object hash was checked
against the pinned tree. These third-party sources stay outside production code.

The script enforces four selected skills, at most 100 files per skill, bounded
individual responses, regular file types and an aggregate 8 MiB download budget.
Its recorded download was 3,475,528 bytes, including tree metadata. Earlier
exploratory tree requests consumed approximately 2.24 MiB more; combined observed
API/raw downloads remained below 8 MiB. No credentials were supplied, package
dependencies installed, provider called, or deployment changed.

## First observed results

Engine source SHA-256:
`cbc8d2614441226e54ea87657413e98b56ef243a1d76da0ca6179f996dea882e`.
This identifies the scanner snapshot used by these raw reports; later fixes must
be rescanned rather than attributed retroactively to the first reports.

| Skill directory | Files | Source bytes | Scan seconds | Block / review / info findings | Overall coverage |
| --- | ---: | ---: | ---: | --- | --- |
| Anthropic PDF | 12 | 58,692 | 0.599058 | 1 / 11 / 0 | Partial |
| Anthropic DOCX | 61 | 1,128,695 | 4.333379 | 0 / 11 / 1 | Partial |
| OpenAI plugin creator | 4 | 25,715 | 0.446975 | 0 / 1 / 0 | Partial |
| OpenAI security-scan example | 4 | 28,741 | 0.426801 | 0 / 3 / 0 | Complete supported content |

All 81 files (1,241,843 source bytes) received text analysis. Partial coverage
reflects bounded/unsupported deeper code analysis and embedded-code limits,
rather than silently missing package files. No file received a safety label.
Findings above count detector records, not independently confirmed defects.
Latency is one local run per package, not a throughput or production benchmark.

Package SHA-256 values:

| Package | SHA-256 |
| --- | --- |
| Anthropic PDF | `857d58ef5c764e61ae8b35554684f67f423aa4e13940a2b7fee9282e22857f8d` |
| Anthropic DOCX | `9bfc9e0cd2c71f0db190452027f69766783b1955d7915cc87acce96ac9069160` |
| OpenAI plugin creator | `cadb8f834d74c33d426a0c671bb84f71804d268a122fd76cd26167cc9b2ab227` |
| OpenAI security-scan example | `036d8f057b81c97e58f46148d7c2f6cf6e3612a62baa699bc87aa405fae3376f` |

## Problems exposed by actual packages

1. **Cross-example credential false positive.** The PDF skill's
   [qpdf examples](https://github.com/anthropics/skills/blob/dbd4588f9e1033efb41dad4bef2f7947c8993d44/skills/pdf/SKILL.md#L213)
   contain a rotation command using `output.pdf`, a blank line, then an unrelated
   `# Remove password` example supplying a password to qpdf's decryption option.
   The inherited active-context-window builder combined adjacent scan units
   across a blank-delimited example boundary. This bound `output` from the
   rotation command to the later password topic and emitted `secret_exfiltration`
   at block tier. That evidence does not request disclosure of the password.
   The exact raw sample and full source are retained and the defect was sent to
   Avery. Correction preserves multiline directive detection while preventing
   context windows from crossing paragraph, heading or fence boundaries; no
   publisher-name exemption.

2. **Natural filename references exceeded the initial graph syntax.** PDF `SKILL.md`
   refers in plain prose to `FORMS.md` and `REFERENCE.md`; actual files are
   lowercase `forms.md` and `reference.md`. The initial graph followed Markdown
   links, inline-code resource names and recognized commands, so its only
   reachable entrypoint in this package was `SKILL.md`. All other files were still
   scanned. This exposes a relationship-discovery limitation and possible
   case-sensitive portability issue; it is not evidence that the scanner failed
   to inventory or scan those files. Subsequent correction adds bare prose paths
   and explicit `case_mismatch` observations. Case-insensitive guesses must not
   silently establish exact references or runtime behavior.

Missing graph edges also include generated example inputs/outputs such as
`field_values.json`; a missing reference alone does not establish a packaging
defect. Review counts have not been independently labeled as true or false
positives across these packages.

## Limits and follow-through

This probe exercises actual external package layouts and substantive script/XML
content, beyond the small authored regression corpus. It does not establish
general detection rates, external-model superiority, deep program semantics,
image OCR, customer-package behavior, live MCP deployment, or runtime execution
safety. The selected examples are convenience samples, not representative
sampling. The supplied enterprise ZIP remains unavailable as original bytes.

## Frozen-source offline rescan

After the contextual false-positive correction, graph extension, list-continuation
handling, strict local audit/example-context review and blockquote-boundary
correction, Elena reran
all four exact archived ZIPs offline. Package hashes were rechecked before each
scan. All four final reports share engine source SHA-256:
`c4a4deda380a1e5a9236a8da2232f3362172f1ee803232fa21ec1eb49c2d24fc`.

| Skill directory | Scan seconds | Block / review / info findings | Text files analyzed | Graph case mismatches |
| --- | ---: | --- | ---: | ---: |
| Anthropic PDF | 1.042572 | 0 / 10 / 0 | 12 / 12 | 7 |
| Anthropic DOCX | 3.929626 | 0 / 11 / 1 | 61 / 61 | 0 |
| OpenAI plugin creator | 0.496497 | 0 / 1 / 0 | 4 / 4 | 0 |
| OpenAI security-scan example | 0.375364 | 0 / 3 / 0 | 4 / 4 | 0 |

The demonstrated PDF false block is absent. Its seven explicit case-mismatch
observations preserve the distinction between a filename mentioned in prose and
an exact resolvable path. Existing scripts/references remain independently
scanned. The first three packages retain partial deeper-analysis coverage; the
security-scan package reports complete supported content. Zero blocks is not a
safety conclusion, and the remaining review findings have not all been labeled.

Final raw evidence uses `*-after-report.json` and `after-manifest.json` alongside
the original reports. The preceding completed rescan at engine fingerprint
`b44ffb8474c4bb0344a0bf857ca6d3562b00060c9999d6aae4a914887fcff583`
is preserved as `preceding-b44-*-after-report.json` and
`preceding-b44-after-manifest.json`. The later preceding rescan at fingerprint
`b22316991b4d85c571a506f2a91486160fdb4691d32c6db955913f3e19e32b0a`
is preserved under `preceding-b223-*-after-report.json` and
`preceding-b223-after-manifest.json`. Both had the same finding counts but are
not used as final-source evidence. `rescan.py` reuses the ZIPs without any downloads. An
intermediate rescan overlapped ongoing source changes and had inconsistent
engine fingerprints; its evidence is separately preserved under
`transition-*-after-report.json` and `transition-after-manifest.json` and is not
used for the final table. Single-run elapsed times, including local concurrent
test load, do not establish comparative performance.
