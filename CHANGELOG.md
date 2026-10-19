# Changelog

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
