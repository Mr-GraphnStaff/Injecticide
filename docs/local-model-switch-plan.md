# Local model first cut: prepared scanner switch

Status: ENABLED AND VERIFIED on November 8, 2026 after David explicitly confirmed activation. The existing Injecticide web scan endpoint returned completed local-model analysis in 19.44 seconds, with the recorded model digest and the normal policy/readiness fields preserved. Existing services were healthy after the switch.

## Applied change and rollback

The activation recreated only service `skill_sandbox` in Compose project `injecticide`, using the tested image `injecticide-skill-sandbox:local-llm-preview` and the opt-in settings in `deploy/local-model.override.yml`. It connected the existing `injecticide-local-llm` container to private network `injecticide_skill-sandbox-net` under its matching alias. The web, research, nginx, Bridge and other services were not replaced. The prior scanner image `injecticide-skill-sandbox:555ce2dcaa79` remains available.

Before the switch, save a rollback override with the exact current image, and check that it still matches the recorded existing version. Save the preview override alongside the runtime receipt under `/mnt/nvme/injecticide-llm`. Bring up only `skill_sandbox` with no dependency updates, no image pulls and no builds, and wait for health. If health or the live web scan check fails, restore the exact old scanner image immediately.

Live verification uploaded an inert documentation fixture through the existing local web API. The local analysis status was `completed`, with zero observations and the pinned model identity. The response preserved policy and readiness fields. The runtime receipt at `/mnt/nvme/injecticide-llm/setup-receipt.json` now records `integration.enabled: true`, the active image, module hash, rollback/override paths and the verified model result. The model connection is active for normal scans in this dev lane.

## Already verified

- Ollama 0.40.15 responds on loopback port 11434.
- Native ARM64 archive verified against upstream SHA-256 `7f699ead5cdb4ae1ed89b888b148a238af188708800871e1889ab9dcee95f247`.
- Runtime and models stored on the main drive under `/mnt/nvme/injecticide-llm`.
- Server cloud mode disabled and verified using `/api/status`.
- Qwen3.5-2B local manifest digest `0689d44085e06d165161a8a9a1731344278cfb5aade63a3c3dbdb48ab54b130a`; actual package is 1.9B Q8_0, 2,683,396,812 bytes including bundled assets.
- Cold minimal JSON response: 16.57 seconds. Initial small package examples: about 12–34 seconds; not a representative performance benchmark.
- Enabled web integration: 19.44 seconds, completed local analysis; cloud inference remains disabled.
- Focused tests: 51 passed, 2 optional MCP-package tests skipped.
- Adapter source and preview image module hash matched: `028065ad107f40aeab7861b42f50db600a7f9683e0a7bb3581f140b4eb6859a2`.

## Known first-cut limitations

An initial analysis prompt produced a false positive on benign protective instructions. After a prompt revision, that development example produced no observation. The suspicious development example produced a model observation whose quoted evidence did not match exactly; it was rejected and reported as partial. These are development smoke checks, not held-out accuracy results. The model has not been fine-tuned. Do not publish detection efficacy claims from this evidence.

The first cut exposes status in existing report warnings and evidence in the JSON `local_analysis` section. A dedicated UI presentation, broad corpus evaluation and training are follow-up work. The normal static scanner and organization policy remain independent of these advisory observations.
