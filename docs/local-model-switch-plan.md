> Superseded by 0.17.0 on November 9, 2026. Scan-time model analysis is retired,
> including its raw-text library API. The isolated daily worker receives only
> allowlisted technical categories and public research. The historical preview
> notes below are not activation instructions. See
> [the current privacy boundary](../research_mcp/README.md#scheduled-local-research-and-privacy-boundary-0170).

# Local model first cut: prepared scanner switch

Status: ENABLED AND VERIFIED on November 8, 2026 after David explicitly confirmed activation. The existing Injecticide web scan endpoint returned completed local-model analysis in 19.44 seconds, with the recorded model digest and the normal policy/readiness fields preserved. Existing services were healthy after the switch.

## Cloudflare-safe background scan deployment

Current dev web image: `injecticide-web:local-ai-jobs`; scanner remains `injecticide-skill-sandbox:local-ai-ui-budget3`. Apply `/mnt/nvme/injecticide-llm/local-ai-jobs.compose.yml` after the existing base and scanner overrides. The previous `local-ai-ui-budget3.compose.yml` and image remain available for rollback. This change replaces only the web container and does not change the certificate gate, WAF, DNS or model settings.

The live public scan at 2026-11-09T00:06:21Z returned Cloudflare 524 (ray `a5789230efb2b16e`), while the scanner finished later. LAN-only qualification had missed that edge timeout. The UI now starts a background job and polls through short requests; the old synchronous API default is retained for compatibility. Browser waiting is bounded at 360 seconds; internal model/API/proxy limits stay 90/225/240 seconds.

Qualification passed: 33 focused tests, independent review, Brave recovery/cancellation tests, a generated inert public HTTPS scan (receipt 749 ms, completed result, longest poll 234 ms, unauthenticated 403), and the actual private ZIP in Brave (receipt 0.14 s, completed 136.7 s, JSON/Markdown exports, unchanged originals). Public qualification used the installed Windows certificate without exporting its key; private package uploads remained on the LAN.

Earlier test-harness timings included saving large private evidence over SMB. The updated real-file test records completion before evidence writes; use its 136.7-second measurement for this scan. Model coverage and detection accuracy are unchanged by the transport fix.

## Working dev UI update

David explicitly authorized routine reversible Injecticide development and deployment, with him as the only current user. The November 8 UI update replaces the web and scanner dev images with `injecticide-web:local-ai-ui-budget2` and `injecticide-skill-sandbox:local-ai-ui-budget3`. It adds the visible local-LLM choice, readable evidence and Markdown export sections, and removes Close App. The scanner memory limit is 768 MiB with no swap allowance after a real package caused an OOM kill at 256 MiB.

A real ZIP scan with the model disabled completed HTTP 200. The enabled scan revealed that the old 120-second API timeout did not cover static scanning plus a measured 37.1-second model call. The API read limit is now 225 seconds, nginx 240 seconds and browser 255 seconds. The model client now has an 85-second network timeout and a 90-second process deadline after a real SKILL.md call hit the previous 40-second network limit. The timeout-chain regression test includes the model deadline; 26 focused tests passed and an independent source review approved this delta. All five real-file Brave checks passed, including JSON/Markdown exports and unchanged originals. SKILL.md with local AI took 70.3 seconds; large ZIP browser wall times ranged 86.7–239.3 seconds, and the identical-byte .skill format check took 126.9 seconds. Large-package latency remains a dev limitation. Local AI returned partial coverage, not a clean whole-package verdict. Public authenticated browser access was not verified; actual uploads stayed on the private Pi LAN address.

The applied runtime override is `/mnt/nvme/injecticide-llm/local-ai-ui-budget3.compose.yml`, layered after the base Compose file and `sandbox-local-llm.compose.yml`. The previous web/scanner override is retained in `local-ai-ui.compose.yml`; earlier image rollback is in `local-ai-ui.rollback.yml`. The previous nginx bytes are retained in `nginx-before-local-ai-budget.conf`. Restore both the appropriate override and nginx configuration if rolling back; validate nginx configuration, reload it and wait for container health. No model port is newly exposed.

## Initial scanner-only activation and rollback

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

The UI now shows local analysis directly, with JSON at `result.local_analysis` in the versioned download envelope and corresponding Markdown sections. Broad corpus evaluation and training remain follow-up work. The normal static scanner and organization policy remain independent of these advisory observations.

Runtime verification must import the module used by the actual entry point: standalone scanner loads `/app/local_analysis.py`, while the web package copy is `/app/skill_sandbox/local_analysis.py`. The active scanner module hash is `f46530f7a388137c9c5490d05d54dbc265ccc876e90f4550ccc828c928ff4a637`. Verify the active import and deadlines after deployment; checking a duplicate unused module is insufficient.
