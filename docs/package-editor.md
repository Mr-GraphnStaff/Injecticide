# Review, edit and repackage a skill

After a successful scan of a single-skill `.skill` or `.zip` archive, open
**Review and edit a package copy**. Inspect a file, review the original and draft, and
explicitly accept an edit or removal. The original upload is preserved.

Select a destination profile and the download extension. The input extension
preselects `.skill` or `.zip`; the caller can override it. Both outputs use ZIP
internally. Destination requirements are checked separately from the extension.
The first inspection checks archive structure; destination metadata validation
runs during rebuilding. Its errors must be fixed before export.

The server creates an immutable candidate, reopens it, and rescans its actual
bytes through the existing scanner with local-model processing disabled. Download
requires matching archive and direct-member hashes, complete required-component
coverage and successful supported inspection stages. Missing reports, truncation,
database row limits and nested-container inspection failures prevent release.
Remaining findings and explicitly limited binary/structural inspection require
acknowledgement before downloading. This does not certify runtime safety.

## Privacy and access

Uploaded bytes, exact evidence, edited text and data values are not sent to any
LLM, including a local model. Advice comes from reviewed local templates; the
existing asynchronous research/correction boundary remains separate. The editor
does not execute uploaded scripts, installers or commands.

Artifacts are held in bounded process memory for up to ten minutes, with at most
two completed jobs retained. Earlier jobs may expire sooner. Each browser editor
session holds a random capability secret, supplied only in a request header.
Status and download require that same secret. Refreshing the page loses access;
service restart also clears jobs. Existing deployment access controls still apply.

## Supported scope and limits

- One root skill directory containing exactly `SKILL.md`; no plugin or extension conversion.
- Text edits up to 128 KiB per file; previews total 512 KiB, with `SKILL.md`
  prioritized. A file without its original preview is read-only.
- Binary assets can be explicitly removed. Office assets receive bounded
  container inspection and are preserved byte-for-byte; Office semantics,
  macros and runtime behavior are not certified.
- Traversal, ambiguous/colliding paths, links, encrypted or multipart archives,
  ZIP64 and unsupported nested containers are rejected. Central-directory and
  expanded-content budgets are enforced before allocation.
- Rebuilding uses canonical entry order, timestamps and nonprivileged permissions (0755 for existing executable files,
  0644 otherwise), with stored
  ZIP entries. The result can be larger than the compressed original.
- Literal supported Markdown references to removed files are checked. Arbitrary
  script/configuration dependencies are not proved correct.
- Existing publisher signatures may become invalid after editing. Re-signing
  requires the publisher's own process; the editor does not manufacture trust.
- Format checks, security findings, inspection limitations and installation
  verification are distinct. Native vendor installation is not automatically tested.

## Destination evidence

Profiles are based on official documentation reviewed November 10, 2026:

- [Agent Skills specification](https://agentskills.io/specification)
- [Claude custom skills](https://support.claude.com/en/articles/12512198-how-to-create-custom-skills)
- [Claude API requirements](https://platform.claude.com/docs/en/build-with-claude/skills-guide)
- [Claude Code skills](https://code.claude.com/docs/en/skills)
- [OpenAI API requirements](https://developers.openai.com/api/docs/guides/tools-skills)
- [ChatGPT and Codex skills](https://learn.chatgpt.com/docs/build-skills)
- [Gemini CLI packaging](https://geminicli.com/docs/cli/creating-skills/)
- [Gemini CLI installation](https://geminicli.com/docs/cli/using-agent-skills/)

Claude's help article specifies a 200-character description while its API
documentation permits 1,024. The Claude.ai profile reports this discrepancy.
Unknown product limits remain unverified; local safety caps may be stricter.


## Operation status and Office scope

The editor reports the actual server stage and elapsed time. Stop waiting stops browser polling; it does not cancel server processing. Drafts and accepted edits remain available after a failure or stopped wait.

Office inspection covers ElementTree-exposed XML text/tails and attributes in XML, relationships, VML and SVG, including supported embedded OOXML. It does not certify rendering, OCR, opaque binary execution, XML comments/processing instructions/namespace declarations, or unreferenced ZIP bytes. Shared limits are 2,000 members, 50 MiB expanded bytes, 1,024 XML parts, 5 MiB XML bytes, 1 MiB projected text and ten seconds of cooperative Office work; an individual Office input/member is limited to 8 MiB, and each XML part to 1 MiB. Parser errors and actual work-limit exhaustion stay blocked.

Optional code/decoding refinements can report bounded partial analysis after raw extraction and text-pattern input inspection complete. Every reported limitation remains visible and requires explicit acknowledgement for that artifact before download. A completed copy is not certified safe to execute or install.

Incomplete database inspection remains a download blocker. The failure names the
file and reports rows read versus reported rows; matching row counts alone do not
prove complete database coverage when other unread content remains. This differs
from acknowledged limits of optional refinement or binary runtime analysis.
