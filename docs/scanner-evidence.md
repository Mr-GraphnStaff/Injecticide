# Scanner evidence contracts (0.7.0)

The scanner reports observations, coverage, compatibility and policy separately.
No uploaded executable code is run by a static scan. A matching pattern or valid
creator tag is not a safety certificate or proof of malicious intent.

## Inspection and creator mitigation

Files and inventory rows expose `analysis_coverage` by extraction, text-pattern,
embedded-code and output-display stage. Measured supplied ranges and known
cutoffs are separate from unmeasured inspection counts, which remain null.
`complete_input` means a stage received its full supported input; it does not
assert that every character was exhaustively evaluated by every detector.

`creator_mitigation` recognizes two local reading conventions: a header/frontmatter
`read_pattern: chunked-reference` declaration, and a large-file REVIEW TAG comment
or top-level JSON `_review_tag`. Matching EOF evidence is verified against complete
original text, outside code fences. Markdown/script EOF names must match the file;
JSON requires a final top-level `_end_of_file` marker. Duplicate/malformed JSON,
forged/fenced markers, omitted EOF and parser limits cannot receive verified
status. These conventions are not universal vendor requirements.

Verified markers set `large_file_tagged_chunked_reference: true` and satisfy the
named creator convention only. Incomplete scanner coverage remains incomplete;
actual target-model reading limits remain unknown unless independently evidenced.
Claimed but unverified markers produce `unverifiable_chunk_marker` at review tier.
Verification uses a bounded header probe and at most 2 MiB of claimed text; it
never removes the existing 1 MiB text detector input limit or Office/XML limits.

## Compatibility and official reference checks

An explicitly selected generic target applies the bundled portable profile.
Named product targets retain semantic metadata mismatches as unverified advice;
measurable parsing errors remain structural errors. Only the separate current,
unchanged vendor evidence path can apply its documented product constraints.
Unknown compatibility is not an approval or rejection.

`official_validator_results` runs reviewed OpenAI and Anthropic skill-creator
Python checks locally on complete, bounded, unique-key/anchor-free frontmatter.
Source commits, hashes, scope and diagnostics accompany results. Upstream files
are unmodified and licensed in `skill_sandbox/vendor_validators`. Source hash
verification precedes loading; uploaded modules are never imported. Their
results are format-only reference evidence and do not change governance.

Other products without a reviewed bundled executable validator report
`unavailable`, not pass. In particular this release does not install Node or the
GitHub publishing CLI into the isolated Python sandbox to run Gemini/Copilot
checks. Research collection of those official tools continues, but collecting
their source is separate from running them. Product acceptance and tenant policy
are not certified by the Python reference validators either.

## Reporting and recovery

Contact addresses/phone numbers remain observations. Their presence alone does
not establish regulated-data processing, unauthorized disclosure or trusted
ownership. Other sensitive identifiers, credentials and actual security signals
retain their controls. Creator mitigation never suppresses those signals.

The UI presents separate evidence states and preserves the selected local File
after failed/aborted requests for an explicit retry. It never automatically
retransmits an upload. Success, replacement or explicit clearing releases it.
API scan responses carry `X-Scan-Request-ID`; success exports `scan_request_id`
and elapsed analysis time. Sanitized errors identify validation/admission/upload/
sandbox/analysis stages without echoing exception messages or request payloads.
Transport failures without a response cannot provide a server request ID and
are not assigned an invented cause.

Reflected credential literals and credential-bearing URL/header values are
redacted after detection and policy computation. Trusted rule IDs, hashes and
decisions remain intact. This is report hygiene, not a complete secret-discovery
guarantee; intentional contact-presence evidence remains visible.

See [local evaluation and report comparison](scanner-evaluation.md) for
reproducible authored regression cases and hash-bound disagreement analysis.
These tools do not establish independently measured general accuracy.
