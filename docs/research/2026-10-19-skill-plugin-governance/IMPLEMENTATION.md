# Package threat analysis 0.2.0 candidate

The reviewed 24-check scope is implemented together on `codex/package-threat-analysis`.
The machine-readable implementation registry is `skill_sandbox/rules/package_checks.json`.
Every scan returns all 24 outcomes, source IDs, scanner/catalog versions, fingerprints,
coverage, capabilities and readiness. A completed static check is not a safety verdict.

## Format and content inspection

Common Agent Skills and portable Agent Plugins 1.0 use shared deterministic adapters.
Portable JSON schemas are pinned locally with SHA-256 provenance; uploaded schema URLs
are never fetched. Legacy/native Claude Code, Codex, Cursor, Gemini, OpenClaw and MCPB
manifests are identified. Copilot, Kiro and Devin/Cascade directory indicators and
portable extension namespaces identify candidate runtimes. Format does not establish
publisher identity. Native adapters inspect documented identity/security fields; they
do not claim complete parity with every vendor CLI's conformance validator.

The scanner inventories nested skills, instructions, hooks, MCP/LSP launch declarations,
dependencies, permissions and literal credential declarations. It resolves supported
literal package references, interpreter invocations, and copy/rename/decode-to-code
patterns without executing them. Dynamic shell expressions and opaque runtime values
are outside static resolution. Code-like `.py.md` content receives execution review;
the name `references` does not downgrade that evidence. Fenced examples alone are
documented code evidence, not proof of malicious execution.

The supplied `apply_notes.py.md` example is a regression fixture. The scanner reads
the Python inside nested triple/four-backtick fences, links the literal `sed` extraction
to the generated `apply_notes.py` interpreter invocation, and scans the embedded source
as code. It reports `executable_packaged_as_document` separately from malware findings.
Useful slide-note functionality does not remove the potential bypass of a `.py` upload
restriction. The scanner has not queried or verified this user's Zscaler policy and
does not automatically change a corporate gateway configuration. Its policy signal
requires organizational review and is never downgraded to harmless documentation.

The detector is not Python-specific. It records declared fenced-source languages and
mixed executable suffixes across JavaScript/TypeScript, shell, PowerShell, Ruby, Perl,
PHP, Lua, batch, R and other recognized source languages. Interpreter, shebang and
selected raw syntax indicators also work with unknown document extensions such as
`.me`. Supported literal extraction/copy/rename paths link a document to its generated
executable target. These are measurable static indicators, not full language parsers
or proof of author intent. Arbitrary transforms, unknown languages and runtime-generated
code can escape static recognition; hitting analysis budgets makes coverage partial.

Every archive entry is represented, including rejected traversal, links and duplicate
paths. PNG/font files are inventory-only. Executable binaries are unassessed. Office
and SQLite use bounded text projections and make coverage partial. File counts, original
file byte sizes and mandatory-component coverage are separate. Original-file byte size
does not mean every byte was inspected. Findings and component report budgets are explicit.

## API and browser

POST `/api/skills/scan` and sandbox `/scan` accept multipart `file`, `target_runtime`
(default `auto`) and optional `governance_evidence` JSON. GET `/api/skills/profiles`
lists runtime choices. Both API paths use the same scanner. One scan per worker is
admitted; concurrent requests receive 429. Work runs off the async event loop.

The browser retains one current file/report, cancels replaced requests, releases file
references after submission, and paginates findings and package evidence. Changing the
runtime/evidence clears the previous result. Partial coverage cannot display a clean
headline. Detailed Markdown export includes the complete inventory and analysis.

## Configured evidence and evaluations

Absent configuration is an explicit `not_assessed`/`not_verified` result, never a pass.
Optional metadata is advisory; missing enterprise metadata is not a base-spec violation.

OMS verification uses administrator-configured absolute `INJECTICIDE_OMS_VERIFIER`
and `INJECTICIDE_OMS_TRUST_ANCHOR` paths. Install/pin the trusted verifier outside the
upload path. The scanner runs NVIDIA's documented `verify certificate DIRECTORY
--signature FILE --certificate-chain TRUST` interface with no shell, no unsigned-file
exception, and a 10-second timeout. Mount the executable/dependencies/certificate read-only
into the scanner if enabling it. No verifier or publisher anchor is installed by default.
Tests mock the trusted process interface; no real publisher signature was verified here.
Signature integrity does not establish behavioral safety.

Review, source-control, evaluation and tenant-policy evidence can be authenticated using
an Injecticide HMAC-SHA256 envelope. Configure `INJECTICIDE_EVIDENCE_KEYS` to an absolute
read-only JSON file mapping trusted issuer names to at least 32-byte random keys encoded
as hex. Keep signing keys outside uploaded material and browser code. Shared HMAC keys
authenticate the configured issuer boundary; this is not public-key nonrepudiation or
a vendor's native attestation format. The service does not query vendor tenants.

Envelope shape in `governance_evidence`:

```json
{"envelope":{"issuer":"review-service","payload":{"artifact_sha256":"EXACT_UPLOAD_HASH","issued_at":"2026-10-19T12:00:00Z","expires_at":"2026-10-20T12:00:00Z","controls":{"independent_review":{"status":"pass"},"tenant_access":{"status":"pass"}}},"signature":"HEX_HMAC_SHA256"}}
```

Sign `review_evidence.canonical_payload(payload)` using the configured issuer key.
Untrusted, tampered, expired, future-dated and wrong-artifact evidence is rejected.
Unsigned hash-bound claims remain declared/unverified. Evidence authenticates an issuer's
assertion, not the correctness of their work, and does not suppress static findings.

Explicit isolated evaluations are available to operators through:

```text
python -m skill_sandbox.package_review evaluate PACKAGE.zip
```

Set `INJECTICIDE_EVALUATION_RUNNER` to a trusted absolute executable path. The operator
must provide container/VM isolation, authorization and resource controls; the static
scanner does not certify that external environment. The runner receives `--artifact`,
`--sha256`, `--output`, has a 120-second deadline, and must emit at most 128 KiB JSON.
Output is `{"status":"pass","cases":[{"kind":"positive_trigger","passed":true},...]}`.
Required case kinds are `positive_trigger`, `negative_trigger`, `coexistence`, and
`bounded_workflow`. Cases need boolean results; failure is preserved. The output remains
an untrusted claim until a configured reviewer signs a current hash-bound envelope.
No evaluation runner is invoked by an HTTP upload. No dynamic evaluation of the
user's strategy-deck package has been performed because that package was not supplied.

## Controlled maintenance and acceptance

```text
python -m skill_sandbox.package_review validate-update docs/research/2026-10-19-skill-plugin-governance
python -m pytest -q
node tests/browser/skill_scan_lifecycle.cjs
```

The first command validates unique check/source IDs, source mappings, HTTPS/review-date
metadata and pinned schema fingerprints. It does not download research, activate rules
or prove research accuracy. Review source changes, update attributed fixtures/adapters,
run the regression corpus, increment versions/changelog, obtain human PR acceptance,
then use the existing approved container release process. Existing baseline catalog
review dates are preserved and can correctly report stale independently of new adapters.
There is no installed scheduled watcher or automatic rule activation.

The research folder is evidence for this candidate. Other untracked architecture material
and recovery files are unrelated and must remain outside its commit scope.
