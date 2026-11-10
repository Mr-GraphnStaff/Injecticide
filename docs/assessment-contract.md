# Shared assessment contract (proposed 1.0)

This contract is for review by Injecticide and the independent auditor before
changing finding meanings. Organizational policy is supplied separately. These
are product requirements, not a claim of certified standards conformance.

Each assessment records the package SHA-256 and declared version, scanner/rule
versions, declared provenance, internal self-review or external adoption context,
intended runtime, and inspected scope. A declaration is not verified provenance.
Unknown context stays unknown; it does not silently become external or trusted.

Each finding separates:
- observed content and location;
- a documented format requirement or organizational policy violation;
- suspected capability, intent or risk;
- demonstrated behavior, only when an actual runtime test supplies evidence.

Include detector/category, file and location, supporting evidence, confidence,
source/version/hash for any governing requirement, and inspection limitations.
Static text cannot establish that code executed, data left the system or a model
obeyed an instruction. Wrapper filenames and defensive examples need this same
distinction. Preserve observable facts when an exception changes policy treatment.

Organizational policies and approvals retain their supplied source, scope, expiry
and verification status. An undocumented verbal exception is unknown, including
an asserted web-filter workaround. Internal authorship alone grants no exception.
Audit context can change the adoption decision without changing the observed bytes.

Assess both tools against the same hash-bound examples in
[assessment-contract-cases.md](assessment-contract-cases.md). Expected outcomes
remain proposed until independently reviewed. Runtime cases must identify prompt,
model/version/settings, available tools, observed result and the tested boundary.

Record disagreements as evidence, policy, interpretation or incomplete-testing
differences. Resolve them against evidence; agreement itself is not an accuracy
metric. Map output schemas without forcing the tools to share implementation.
Retrieved standards changes enter the existing qualification/release path;
capturing a changed page does not establish scanner conformance or activation.
