# Local model analysis: first cut

The optional local analyzer adds `local_analysis` to the shared web/CLI/MCP scan report. This is model-generated advisory evidence; technical findings and organization policy remain authoritative independent sections. It is not a trained Injecticide model, malware certification, or a new safety verdict.

## Runtime

Initial candidate: Qwen3.5-2B (Apache-2.0) through Ollama. Model storage belongs on the Pi main drive, not in Git or its SD-card root filesystem. Pin the actual runtime archive SHA-256, base-image digest and model digest in the deployment receipt. The native ARM64 runtime is stored on the main drive and mounted into an existing cached base image to avoid large runtime-image extraction on the SD card. Do not enable cloud models or automatic fallback. The proposed 8GB-Pi settings are one request at a time, two CPU threads, 4096 context and at most 384 output tokens, with a 45-second request timeout. Measure latency and memory before changing limits.

Trusted operator settings:

- `INJECTICIDE_LOCAL_LLM_ENABLED=1` enables the adapter.
- `INJECTICIDE_LOCAL_LLM_URL=http://injecticide-local-llm:11434` for the attached local Docker network; default is loopback.
- `INJECTICIDE_LOCAL_MODEL=qwen3.5:2b` selects the initial model.

Set `OLLAMA_NO_CLOUD=1` on the model server. Before sending source content, the client verifies server cloud disablement and local GGUF model metadata. Cloud model names are rejected. These settings are not accepted from uploaded packages. `deploy/local-model.override.yml` supplies the opt-in scanner settings; the separately provisioned model container must join the scanner private network under alias `injecticide-local-llm`. The service has no execution tools. Source text is untrusted model input; prompt instructions alone are not proof of injection resistance. Existing credential redaction is applied to returned evidence. Package text is sent only to the configured local service; no raw prompt logging is added by this adapter.

## Report contract and limits

The versioned section records model name, input selection digest, completion/error/partial state, selected/clipped file counts, runtime and evidence-backed observations. Exact excerpts must occur in the supplied file and selected text. Fabricated paths/excerpts are rejected. Category/severity/shape are validated; clipped/incomplete/invalid responses are not successful clean scans. `completed` means the bounded model call completed, never that the package is safe. An empty list is not an approval. An error leaves static evidence intact and is explicitly reported in the model section. No company exceptions are learned or silently applied by the model.

The first cut selects at most 3000 serialized UTF-8 bytes including JSON escaping and metadata. It does not implement whole-package semantic comprehension or reliable cross-file analysis outside that selection. Returned interpretation can still be wrong even when its excerpt is real. Report/schema JSON is available; a dedicated UI presentation and representative accuracy evaluation remain release work.

## Training later

1. Record a baseline on a frozen evaluation split using the unmodified model.
2. Curate permitted examples with independently reviewed labels, benign hard negatives and exact evidence. Scanned uploads do not automatically enter training.
3. Train a versioned LoRA adapter on suitable workstation hardware; do not assume 8GB VRAM guarantees every context/batch setting fits.
4. Export/merge and convert the tuned model into a format supported by the pinned inference runtime; do not assume a standalone LoRA adapter can be loaded directly by Ollama. Preserve both base and adapter provenance.
5. Compare with the unchanged base on held-out package families and report false alarms, misses, malformed outputs, time and memory. Keep tuning material separate.
6. Publish an adapter/model only after dataset permission review, base-license/notice packaging, model card, reproducible evaluation, distribution format and rollback are ready. The analysis feature can be released before trained weights.

## Publishing gates

Feature: live local inference, scanner integration, negative-path tests, visible coverage/failure state, model/runtime provenance, representative accuracy and latency evidence, documentation and normal release approval. Trained model: the additional training/evaluation/data-rights gates above. No public performance or safety guarantee follows from installing the base model.

Sources: https://huggingface.co/Qwen/Qwen3.5-2B ; https://docs.ollama.com/api/chat ; https://huggingface.co/docs/peft/en/conceptual_guides/lora .
