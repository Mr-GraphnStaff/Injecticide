# Injecticide

Injecticide is a GPLv3-licensed prompt injection stress-testing toolkit
designed for cloud LLM endpoints. It generates attack payloads, executes
them against configurable API targets, and analyzes responses for
vulnerabilities, leaks, and guardrail failures.

## Features (current)
- Payload generation (override tests, extraction probes)
- Policy-violation probes for safety guardrails
- HTTP executor for cloud endpoints
- Response analyzer for leakage indicators
- Flat and simple Python structure

## Running against Anthropic (Claude)
1. Export your API key:
   ```bash
   export ANTHROPIC_API_KEY="sk-ant-..."
   ```
2. Run baseline payloads:
   ```bash
   python main.py anthropic --mode baseline
   ```
3. Probe for policy-violation handling (asks the model to surface its
   safety rules):
   ```bash
   python main.py anthropic --mode policy-violations
   ```
4. Execute the structured red-team suite:
   ```bash
   python main.py anthropic --mode suite
   ```

Use `--model` to override the default `claude-3-opus-20240229` target.

## License

Injecticide is released under the GNU GPLv3.
See the LICENSE file for your rights and obligations.

## Contributing

See CONTRIBUTING.md for guidelines.
