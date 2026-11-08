# Organisation AI policy (`injecticide-org-policy/v1`)

An organisation AI policy lets a scan answer a second question next to the
scanner's own verdict: *what do our rules say about this skill?* You write the
policy once, as JSON, and supply it with each scan. Injecticide checks it,
evaluates it against the finished scan result and reports the outcome in
`result["policy_evaluation"]`.

- The policy is optional. Without one, `policy_evaluation.status` is `none`.
- An invalid policy never fails the scan. The scan completes and
  `policy_evaluation.status` is `invalid`, with errors that say what to fix.
- The policy result sits **beside** the scanner verdict. It never removes,
  hides or downgrades scanner evidence. The separate organization-policy-applied
  report accounts for company exceptions, approval requirements and full stops.
  Legacy `decision` and finding annotations are rule-match summaries, not the
  company disposition.
- This is a static check of a package. It is not runtime enforcement, legal
  advice or a compliance certificate.

A ready-to-edit template is in [`org-policy-template.json`](org-policy-template.json).
It uses a fictional organisation. Replace every value with your own.

## Supplying a policy

| Where | How |
|---|---|
| Web API | `POST /api/skills/scan`, multipart form field `org_policy` (JSON text). |
| Sandbox service | `POST /scan`, form field `org_policy` (the web API forwards it). |
| Python | `scan_upload(data, filename, target_runtime, governance_evidence, org_policy)` or `org_policy=...`; text or an already-parsed object. |

The SHA-256 in the result is computed over the exact text you supplied (or over
canonical JSON when a Python object is passed), so a report can be tied to the
policy version that produced it.

## Format

```json
{
  "schema": "injecticide-org-policy/v1",
  "organization": "Example Widgets Ltd (fictional)",
  "policy_name": "Acceptable use of AI skills",
  "compiled_date": "2026-11-01",
  "sources": [{"id": "AIUP", "title": "Example Widgets AI Use Policy", "version": "2.1"}],
  "rules": [{
    "id": "R1", "title": "No credentials stored in skills",
    "source": "AIUP", "section": "4.2",
    "requirement": "Skills must not contain passwords, API keys or tokens.",
    "when": {"finding": "hardcoded_secret"},
    "effect": "block", "enforcement": "mandatory",
    "approver": "Information Security",
    "rationale": "Credentials in a shared skill can be copied by anyone who receives it."
  }],
  "not_statically_checkable": [{"source": "AIUP", "section": "7.1",
    "requirement": "Users review AI output before sending it to customers.",
    "reason": "Run-time behaviour, not package content."}],
  "verification_notes": ["Rules checked against the source text by the policy owner."]
}
```

### Top-level fields

| Field | Required | Meaning |
|---|---|---|
| `schema` | yes | Exactly `injecticide-org-policy/v1`. |
| `organization` | yes | Organisation name shown in reports (max 200 characters). |
| `policy_name` | yes | Short policy name (max 200 characters). |
| `compiled_date` | yes | Date the JSON was compiled, `YYYY-MM-DD`. |
| `sources` | yes | Non-empty list of source documents: `id` and `title` required; `version`, `date`, `owner`, `url`, `notes` optional. |
| `rules` | yes | Non-empty list of rules (max 200). |
| `not_statically_checkable` | no | Requirements a static scan cannot check. Strings, or objects with `requirement` and optional `source`, `section`, `reason`. Reported back unchanged so nobody assumes they were checked. |
| `verification_notes` | no | Strings: how the policy was compiled and checked. |

Any key that starts with `_` (for example `"_comment"`) is a comment and is
ignored everywhere, including inside conditions. Any other unknown key is an
error, so a misspelt field never silently does nothing.

### Rule fields

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Unique rule id: letters, digits, `.`, `_`, `-` (max 64). |
| `title` | yes | Short name. |
| `source` | yes | A `sources[].id`. |
| `section` | no | Section or clause in the source document. |
| `requirement` | yes | The requirement, in the source's words. |
| `when` | yes | A condition (below). |
| `effect` | yes | `block`, `require_approval`, `warn` or `allow`. |
| `enforcement` | yes | `mandatory` or `advisory`. |
| `approver` | for `require_approval` | Who approves. |
| `rationale` | no | Why the rule exists. |

### Effects and enforcement

| Effect | Meaning when the rule triggers |
|---|---|
| `block` | The organisation does not permit the skill as it stands. |
| `require_approval` | The named `approver` must approve before use. |
| `warn` | Show the issue; no approval needed. |
| `allow` | The organisation explicitly accepts what the rule matches. Matching findings get `policy_disposition: "allowed_by_policy"` and `policy_rule: "<rule id>"`. They stay in the report with their original tier and severity, and the scanner's verdict is unchanged. |

**Advisory rules cannot block.** A triggered `block` rule with
`enforcement: "advisory"` is reported with `effect: "block"` and
`effective_effect: "advisory_block"`. It is counted in
`effect_summary.advisory_block`, not in `effect_summary.block`, and the overall
`decision` treats it as a warning. Use `mandatory` for rules that must stop a
skill.

## Conditions

A condition is an object with exactly one key. Combine conditions with `all`
and `any`. Conditions nest at most 6 levels and a rule may contain at most 64
condition parts; lists hold at most 100 values. A string or a list is accepted
wherever a list of values is shown; a list matches if **any** value matches.

| Condition | Value | Triggers when |
|---|---|---|
| `finding` | finding id(s), or `{"ids": [...], "include_info": true}` | The scan has an **actionable** finding (tier `review` or `block`) with one of the ids. Informational findings (tier `info`) only count with `include_info: true`. Format findings from `package_analysis.format_findings` also count: severity `error` as actionable, `warning` as informational. |
| `capability` | capability name(s) | The skill shows the capability, from `governance_profile.policy_capabilities` or `behavioral_summary.required_capabilities`. Valid names: `code_execution`, `credential_handling`, `enterprise_access`, `file_write`, `network`, `read_only`, `regulated_data`, `state_persistence`, `html_generation`, `external_content_embedding`, `auto_open`. |
| `data_class` | data class name(s) | A database column was classified with the class (`files[i].database_profile` tables → columns → `data_classes`), or a finding implies it: `contact_directory` → `business_contact_email`, `pii_ssn` → `ssn`, `pii_date_of_birth` → `date_of_birth`, `phi_*` → `health`, `hardcoded_secret`/`literal_credential_declaration` → `credential`. Any tier counts here, because presence of data is the question. Valid classes: `business_contact_email`, `work_phone`, `person_name`, `job_title`, `department`, `manager_reference`, `employee_id`, `personal_email`, `ssn`, `date_of_birth`, `home_address`, `financial`, `health`, `credential`, `free_text`. |
| `external_origin` | host pattern(s), or `{"outside": [patterns]}` | The package references a web host (from `package_analysis.relationship_graph.external_references` and, when present, web systems in `process_diagram.overview.external_systems`) that matches a pattern; with `outside`, a host that matches **none** of the patterns (an allow-list). Patterns are exact host names, or `*.domain` to match any subdomain of `domain` (`*.example.test` matches `api.example.test`, not `example.test` itself). No other wildcard is supported. |
| `connector_mentioned` | connector name(s) | The name appears (case-insensitive substring) in a SKILL.md frontmatter `compatibility` or `allowed-tools` value, or in a tool/MCP system label in the architecture overview. |
| `frontmatter_missing` | field name(s) | A SKILL.md lacks the field both at the top level and under `metadata`. A package with no SKILL.md is missing every field. |
| `risk_at_least` | `low`, `medium` or `high` | `risk_classification.overall_risk` is at least this level. |
| `coverage` | `partial` or `opaque` | `opaque`: a database could not be read (`database_profile.coverage.status` is `opaque`, or an `opaque_database` finding). `partial`: any database is partial or opaque, a `database_not_cleared`/`opaque_database` finding exists, or the scan's own `coverage.status` is `partial`. |
| `all` | list of conditions | Every listed condition triggers. |
| `any` | list of conditions | At least one listed condition triggers. |

Keys from other report sections (database profile, overview) are optional. If
they are missing, the conditions that read them simply do not trigger.

### Finding ids

`finding` accepts every id the scanner can emit. The list is discovered from the
rule catalogs (`skill_sandbox/rules/*.json`) and the scanner source, so a new
detector is accepted as soon as it ships. Commonly used ids:

| Id | What it means |
|---|---|
| `hardcoded_secret` | A credential value (key, token, password) is **present** in a file. |
| `secret_exfiltration` | Text **asks** the model to disclose or send secrets. Not secret presence. |
| `prompt_override`, `system_exfiltration`, `tool_escape` | Instructions that try to override the model, reveal its system prompt or escape tool limits. |
| `pii_email_address`, `pii_phone_number`, `pii_ssn`, `pii_date_of_birth`, `pii_account_identifier` | Personal data patterns. |
| `phi_medical_record_number`, `phi_patient_record` | Health data patterns. |
| `contact_directory` | Business contact directory in a database (informational up to 200 records). |
| `executable_packaged_as_document`, `declared_execution_target`, `code_in_text_artifact` | A script stored with a document extension, declared as run, or code in a text file. |
| `subprocess_spawn`, `dynamic_exec`, `runtime_dependency_install`, `filesystem_access`, `dangerous_file_ops`, `home_write` | Running commands, dynamic code, installs and file changes. |
| `network_calls`, `url_fetch`, `insecure_mcp_transport`, `unverified_mcp_server` | Network access and connectors. |
| `database_not_cleared`, `opaque_database`, `embedded_executable_blob` | Database coverage gaps and executable content inside a database. |

## Worked examples

**Block secrets, but only warn for test fixtures you have reviewed** (two rules;
both report, the block decides):

```json
{"id": "R1", "title": "No stored credentials", "source": "AIUP", "requirement": "No credentials in skills.",
 "when": {"finding": "hardcoded_secret"}, "effect": "block", "enforcement": "mandatory"}
```

**Approval for any personal data, in text or in a database:**

```json
{"id": "R2", "title": "Personal data review", "source": "DPS", "requirement": "DPO approves personal data.",
 "when": {"any": [{"data_class": ["personal_email", "ssn", "home_address", "health"]},
                  {"finding": ["pii_ssn", "pii_date_of_birth"]}]},
 "effect": "require_approval", "enforcement": "mandatory", "approver": "Data Protection Officer"}
```

**Only approved destinations** (allow-list):

```json
{"id": "R3", "title": "Approved destinations only", "source": "AIUP", "requirement": "Use approved services.",
 "when": {"external_origin": {"outside": ["*.examplewidgets.test", "api.approved-vendor.test"]}},
 "effect": "warn", "enforcement": "advisory"}
```

**Scripts that run need review, unless the database is unreadable, which blocks:**

```json
{"id": "R4", "title": "Executable skills reviewed", "source": "AIUP", "requirement": "Engineering reviews code.",
 "when": {"all": [{"capability": "code_execution"}, {"risk_at_least": "medium"}]},
 "effect": "require_approval", "enforcement": "mandatory", "approver": "Engineering review board"},
{"id": "R5", "title": "Unreadable data", "source": "DPS", "requirement": "All data must be inspectable.",
 "when": {"coverage": "opaque"}, "effect": "block", "enforcement": "mandatory"}
```

**Accept an internal staff directory** (findings stay visible, marked allowed):

```json
{"id": "R6", "title": "Staff directory permitted", "source": "DPS", "requirement": "Staff contact data allowed.",
 "when": {"finding": {"ids": ["contact_directory"], "include_info": true}},
 "effect": "allow", "enforcement": "mandatory"}
```

## The result: `policy_evaluation`

```json
{"schema": "injecticide-policy-results/v1",
 "status": "none | applied | invalid",
 "policy": {"name": "...", "organization": "...", "sha256": "...", "compiled_date": "..."},
 "errors": [{"path": "rules[2].when.finding", "message": "...", "suggestion": "hardcoded_secret"}],
 "warnings": [{"path": "...", "message": "...", "suggestion": "..."}],
 "rules": [{"id": "R1", "title": "...", "effect": "block", "enforcement": "mandatory", "approver": "...",
            "triggered": true, "effective_effect": "block",
            "evidence": [{"path": "skill/config.py", "finding_id": "hardcoded_secret", "count": 1}],
            "source": "AIUP", "section": "4.2", "requirement": "...", "rationale": "..."}],
 "not_statically_checkable": [...], "verification_notes": [...],
 "effect_summary": {"block": 1, "require_approval": 0, "warn": 0, "allow": 0, "advisory_block": 0},
 "decision": "block | require_approval | warn | allow | no_rule_triggered | not_evaluated"}
```

Evidence rows for conditions that are not findings carry `finding_id: null`
and a `signal` such as `external_origin:api.vendor.test`,
`data_class:personal_email`, `frontmatter_missing:owner` or
`database_coverage:partial`. Evidence never contains sample text or secret
values. At most 50 evidence rows are listed per rule (`evidence_omitted` gives
the rest).

## Drafting a policy from your documents with an LLM

You can ask an LLM to draft the JSON from your organisation's AI, security and
data-protection documents, then validate it by running a scan. Review every
rule against the source yourself: the model can misread a requirement.

> You are converting an organisation's written policies into an Injecticide
> organisation AI policy (schema `injecticide-org-policy/v1`). Read the attached
> documents. Output one JSON object only, no commentary.
>
> 1. Fill `organization`, `policy_name`, today's date as `compiled_date`
>    (YYYY-MM-DD), and one `sources` entry per document (`id`, `title`,
>    `version` if stated).
> 2. For each requirement that can be checked by statically scanning a skill
>    package, write one rule with `id`, `title`, `source`, `section`,
>    `requirement` (quote the document), `when`, `effect`, `enforcement`,
>    `approver` (required for `require_approval`) and `rationale`.
> 3. Use only these conditions: `finding`, `capability`, `data_class`,
>    `external_origin`, `connector_mentioned`, `frontmatter_missing`,
>    `risk_at_least`, `coverage`, `all`, `any`, with the values listed in
>    docs/org-policy.md. Use `hardcoded_secret` for secrets stored in files;
>    `secret_exfiltration` only for instructions that ask to disclose secrets.
>    Do not invent finding ids, capabilities or data classes.
> 4. Use `enforcement: "mandatory"` only where the document says must / shall /
>    is prohibited; use `advisory` for should / recommended. Advisory rules
>    cannot block.
> 5. Put every requirement that a static scan cannot check (user behaviour,
>    training, run-time monitoring, contracts) in `not_statically_checkable`
>    with `source`, `section`, `requirement` and `reason`.
> 6. In `verification_notes`, list anything you were unsure about. Do not
>    guess; leave a requirement out of `rules` rather than invent a condition.

## Validation errors

Errors name the JSON path, say what is wrong and, where possible, suggest the
closest valid value (`suggestion`). Examples:

| Message | Fix |
|---|---|
| `Rule R3: unknown finding 'secret_in_file'; did you mean 'hardcoded_secret'?` | Use the suggested id. |
| `Rule R2: unknown condition 'findings'; did you mean 'finding'?` | Rename the key. |
| `Rule R1: unknown effect "blok"; did you mean 'block'?` | Use `block`, `require_approval`, `warn` or `allow`. |
| `Rule R4: a condition must have exactly one key (found 2); combine conditions with 'all' or 'any'.` | Wrap them in `all` or `any`. |
| `Rule R5: 'https://api.example.test/x' must be a host name ... not a URL.` | Use `api.example.test` (the suggestion). |
| `Rule R5: '*.ex*ample.test' is not a valid host pattern. Only a leading '*.' wildcard is supported` | Use exact hosts or one leading `*.`. |
| `Rule R6: source 'S9' is not listed in 'sources'` | Add the source or fix the id. |
| `Rule R7: a require_approval rule must name its approver.` | Add `approver`. |
| `Policy: unknown field 'extra'; fields starting with '_' are ignored and can hold comments.` | Remove it or prefix with `_`. |
| `Policy: not valid JSON at line 4, column 12: ...` | Fix the JSON syntax. |
| `Policy: could not be read within the parser limits (...)` | Policy over 128 KiB, nested deeper than 24 levels, duplicate keys or `NaN`. |

**Warning** (the policy still applies): using `secret_exfiltration` without
`hardcoded_secret`. `secret_exfiltration` means an instruction asking the model
to disclose or send secrets; it does not fire for a secret that is merely stored
in a file. Use `hardcoded_secret` for that.

## Safety bounds

- Size: 128 KiB of JSON, at most 24 levels and 10,000 nodes (the shared bounded
  parser), at most 200 rules, 100 sources and 64 condition parts per rule.
- No policy value is compiled as a regular expression, evaluated or imported.
  Matching is exact ids, case-folded substrings (connectors) and a single
  leading `*.` host wildcard.
- Duplicate JSON keys and non-standard numbers (`NaN`, `Infinity`) are rejected.

## Supplied governance evidence: `evidence_input`

Separately from the policy, any `governance_evidence` supplied with a scan is
reported in `result["evidence_input"]` instead of being dropped silently:

| `status` | Meaning |
|---|---|
| `none` | No evidence supplied. |
| `applied` | Hash-bound recognised controls, or an authenticated evidence envelope, were used. |
| `ignored` | Evidence was supplied but none of it could be used. `reasons` say why: no `artifact_sha256`, hash mismatch, no recognised keys, and any unknown keys by name. |
| `rejected` | The evidence was not a JSON object, or its envelope failed authentication and nothing else applied. |


## Organization-policy-applied report (0.16.1)

The scanner verdict stays unchanged. `policy_evaluation.organization_report`
contains a separate `organization_disposition`: `allow`, `require_approval` or
`block`. The report states that its result is **per supplied policy (unverified)**.
An uploaded policy, its named approver and its verification notes are declarations;
JSON validation and a content hash do not authenticate company authority.

The web interface provides **Export organization policy report (.md)** alongside
the executive/summary and detailed exports whenever a policy was supplied,
including when it was rejected. An older scan with no policy-applied report must
be scanned again; legacy allowance annotations are not inferred approval.
The JSON export retains the same policy-applied evidence.

A mandatory block cannot be cancelled by an exception. Mandatory approval remains
required even if a matching finding has an exception. An exception affects only
its matched finding targets; unrelated findings retain their scanner defaults.
Advisory rules do not alter the company disposition. Policy authority remains
unverified even when every technical check succeeds.

An effective exception uses `effect: "allow"`, `enforcement: "mandatory"`, a
nonempty `rationale` and a named `approver`. It may include `expires: "YYYY-MM-DD"`;
the expiry date is inclusive, evaluated against the current UTC calendar date.
A missing rationale/approver or an expired exception is reported as not applied;
legacy policies remain valid. A malformed expiry rejects the whole policy.

Full-stop categories require a condition that explicitly requires their exact
finding identifier. A capability or wildcard-style alternative cannot implicitly
accept a full stop. Coverage acceptance must explicitly match the identified
partial/opaque gap; it does not make unread content read or waive another gap.
Without explicit coverage acceptance the company result cannot be `allow`.
These are product exception controls, not assertions that a particular company
has authorized an exception or appointed the declared approver.

The report includes the original technical verdict, deciding rules, applied and
rejected exceptions with reasons and approvers, residual findings, full stops,
coverage gaps and acceptances, policy identity/date/hash/source declarations,
validation errors, limitations and the requirements needing human/runtime checks.
An invalid policy is rejected entirely and visibly falls back to scanner defaults;
no valid-looking subset of its rules is applied.
