# Changelog

## 0.4.0 - 2026-10-20

- Add the DAF-TECH AI architecture playground with movable, keyboard-accessible
  components spanning models, agents, gateways, edge controls, MCP, tools and data.
- Support directed connections, trust/data/control properties, undo/redo, local
  saving and versioned JSON import/export without executing mapped services.
- Generate bounded deterministic test plans with exact component/connection
  references, map hashes, evidence requirements and distinct OWASP source families.
- Keep control declarations unverified and all suggestions explicitly not run;
  retain the built-in scenario explorer as a separate route.


## 0.3.3 - 2026-10-20

- Share the DAF-TECH header, sphere, signature, navigation and footer across the
  overview, testing/scanning and architecture pages; fix the broken console logo.
- Apply consistent teal surfaces and readable controls to workspaces and reports,
  with responsive layouts and a clear route to static package scanning.
- Replace repeated architecture edge endpoints with an ordered component path,
  preserving actual loops and discontinuities; clarify modeled analysis limits.
- Add useful console start guidance and clear stale overview anchors on navigation.

## 0.3.2 - 2026-10-20

- Keep JSON context within individual values; retain declared evaluation inputs
  as reviewable evidence rather than treating test prompts as executed actions.
- Distinguish automatically offered workflow steps from automatic execution, and
  bind secret-disclosure verbs to credential targets instead of earlier topics.
- Require skill-write evidence for self-modification; timing phrases and a skill
  directory mention alone no longer qualify.
- Keep reference contact data in the same Sensitive Data category as other files;
  remove the unsupported internal-contact inference based on path/domain alone.
- Preserve side-effect approval, sandbox and partial-coverage controls.

## 0.3.1 - 2026-10-20

- Apply the Better CaptionKeep v6 DAF-TECH sphere and teal visual identity, with
  the Injecticide signature "Another DAF-TECH Product".

- Update the front page to describe prompt testing, package scanning, modeled
  architecture analysis and research collection without unsupported hardening
  or compliance claims; show the actual package release in the version badge.
- Publish an attributed, bounded research news feed from collected vendor releases
  and observed changes to official guidance, with collector health and freshness.
- Connect the web app to the research service through a read-only projection,
  with bounded requests, cached last-good data and explicit unavailable states.

## 0.3.0 - 2026-10-20

- Add an independent research MCP container with recurring, bounded discovery
  of approved OWASP/NIST and vendor skill, plugin and project documentation.
- Persist source fingerprints, retained snapshots, change cursors, freshness
  and failed-fetch state; expose queries and queued source refresh through MCP.
- Collect public GitHub release API data for agent runtimes and security tools;
  expose structured release records with API rate-limit backoff and provenance.
- Restrict collection to configured public HTTPS scopes, respect robots.txt,
  and keep research data separate from production scanner rules and credentials.
- Research ingestion does not activate detectors or certify compliance.

## 0.2.1 - 2026-10-19

- Allow SQLite archive members up to 32 MiB in any package directory, identified
  by their SQLite header. Keep ordinary files at 5 MiB and raise the total
  decompressed package budget to 64 MiB; database text sampling stays bounded.
- Limit SQLite text fields to 4,096 characters inside SQL before loading rows
  into Python, preserving the existing table, row and output budgets.
- Rotate Injecticide container logs at 10 MiB, retaining three files per container.

## 0.2.0 - 2026-10-19

### Skill and plugin threat analysis

- Added shared skill/plugin/runtime adapters, pinned portable schemas, component and execution-reference analysis, and code stored as Markdown detection.
- Added per-file coverage, fingerprints, partial-scan readiness, governance evidence, optional locally configured OMS verification, and explicit runtime evaluation gaps.
- Added source/version freshness reporting and controlled candidate update validation; no research changes activate themselves.
- Unified the web fallback and sandbox scanner and bounded upload, parsing, scan concurrency and report rendering.
- Added source-attributed benign package fixtures and cross-format, evidence, API and browser regression checks.
- Enabled production host memory control and made deployment fail before stopping the stack when Docker cannot enforce memory limits.


- Raised the skill-bundle upload ceiling from 10 MiB to 32 MiB while retaining
  the 25 MiB unpacked-archive, per-file, and file-count safety limits.
- Added browser-side size validation and a regression test for skill bundles
  that legitimately exceed the former upload ceiling.
- Aligned the Nginx request-body ceiling with the 32 MiB skill-file limit,
  including room for multipart form overhead.

## 0.1.1 - 2026-09-26

- Added Azure Pipelines validation and approval-gated Raspberry Pi deployment.
- Added a restricted, root-owned deployment wrapper with commit validation,
  health checks, persistent report storage, and automatic rollback.
- Added container health checks and immutable per-commit image tags.
- Declared Starlette's `httpx2` test-client dependency for reproducible CI.
- Made Pi deployments stop the existing stack and rebuild Injecticide images
  without cache while leaving unrelated Docker workloads untouched.

## 0.1.0 - 2026-04-22

- Added a separate Architecture Analysis surface for modeled MCP and agent workflow trust-boundary review.
- Added architecture profile loading, deterministic scenario traces, and path-based findings for grouped tool execution.
- Added API endpoints for architecture profile discovery and scenario analysis.
