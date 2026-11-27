# Plugin anatomy in scan reports

A plugin is a package of extensions with a shared identity. Its files can supply
instructions, handlers, server connections and programs. Recognizing SKILL.md
files alone does not explain those different roles.

Injecticide's **Plugin anatomy** section describes the supplied package using a
Claude Code component profile reviewed on November 27, 2026. It appears in the
report overview, detailed Markdown export and full JSON export. Each component
links to the file that supplies its declaration or content.

| Part | Default evidence | Role |
| --- | --- | --- |
| Identity | `.claude-plugin/plugin.json` | Declared name and version; not publisher authentication |
| Skills | `skills/<name>/SKILL.md` | Instructions selected for tasks or invoked explicitly |
| Commands | `commands/*.md` | Older command instruction format |
| Subagents | `agents/*.md` | Instructions for delegated agents |
| Hooks | `hooks/hooks.json` | Handlers associated with lifecycle events |
| MCP | `.mcp.json` | Local tool-server processes or declared remote endpoints |
| LSP | `.lsp.json` | Language-server processes |
| Output styles | `output-styles/` | Instructions that shape responses |
| Workflows | `workflows/*.js` | Workflow code; behavior is not established by inventory |
| Monitors | `monitors/monitors.json` | Declared background processes and their triggers |
| Themes | `themes/` | Appearance configuration |
| Executables | `bin/` | Potential commands made available to the host |
| Evaluations | `evals/` | Material for a separate evaluation run |
| Channels and configuration | Manifest fields | Server bindings and requested configuration fields |

The manifest is optional. A `.plugin` upload or an explicit Claude Code target
can produce a **layout candidate** from conventional folders or a root SKILL.md.
That inference does not establish the installed name, marketplace provenance or
host acceptance. Other recognized vendor manifests have separate ownership.

## Reading discovery states

- **Observed** means the file or inline declaration was supplied.
- **Ignored default** means a manifest path replaces that default in this profile.
- **Superseded declaration** identifies an earlier server definition replaced by
  a later definition of the same name.
- **Unresolved** means a declared path, configuration shape or required content
  could not be assessed. External bundles are never fetched.

Custom skill locations augment default skill discovery. Commands, agents,
output styles, workflows, themes and monitors can replace defaults. Hook and
server declarations combine with default configuration files. Evaluation paths
follow their separate documented directory rule, including first-entry array
selection. Marketplace overrides and installed runtime settings are not available
from an isolated upload, so the report cannot prove what a host loaded.

Resolved custom hook/server configurations join the existing package inspection.
Declared instruction files and prompt/agent hook sources are assessed as active
instruction surfaces even under a folder called `references`. This is based on
their declarations, not trust in the folder name. Ignored packaged files still
receive static inspection.

## Limits and sensitive data

The display retains at most 500 component rows across 32 plugin roots. A display
omission does not cap active-instruction analysis. Actual discovery truncations,
malformed declarations and unresolved inputs have separate partial coverage.
Nested plugins and nested archive contents have separate ownership boundaries;
paths cannot escape into another component package through traversal.

Anatomy does not include raw commands, inline prompts, environment/header values,
configuration defaults or remote bundle URLs. Configuration names, declared types
and sensitivity flags are reported. The normal report redactor still applies.

No plugin is installed, no component starts and no evaluation runs during this
inventory. Claude Code, Claude.ai and Cowork support differ. In particular, the
reviewed documentation says Claude.ai/Cowork do not install top-level `bin/`
plugins; the report provides this compatibility note without claiming a tested
installation outcome.

## Primary references

- [Claude Code manifest reference](https://code.claude.com/docs/en/plugins/manifest-reference)
- [Claude Code component reference](https://code.claude.com/docs/en/plugins/components)
- [Claude Code loading reference](https://code.claude.com/docs/en/plugins/loading)

The owner-supplied field guide informed the questions to investigate. Its claims
and example commands were treated as reference material, not agent instructions
or independent proof of runtime behavior.
