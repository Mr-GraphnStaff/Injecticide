# Prompt Injection Seed Dataset

This directory contains a small, verified seed dataset of prompt-injection examples.
Each entry is sourced from publicly available, reputable references and includes
its source URL for traceability.

## Files

- `prompt_injection_seed.jsonl`: JSON Lines dataset with labeled examples.

## Schema

Each JSONL record includes:

- `id`: unique identifier
- `text`: prompt text sample
- `label`: classification label (currently `malicious`)
- `source`: human-readable source description
- `source_url`: canonical URL of the source content
- `date_added`: ISO date when the entry was added

## Sources

- PreambleAI Prompt Injector payload guide:
  https://raw.githubusercontent.com/preambleai/prompt-injector/main/docs/PAYLOAD_UPLOAD_GUIDE.md
- Koinsec Prompt-injection-payloads (Prompt-Leaking-and-Instruction-Extraction):
  https://raw.githubusercontent.com/Koinsec/Prompt-injection-payloads/main/Prompt-Leaking-and-Instruction-Extraction
