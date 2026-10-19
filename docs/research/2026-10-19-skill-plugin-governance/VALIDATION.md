# Validation evidence — October 19, 2026

Candidate: 0.2.0 on `codex/package-threat-analysis`. These checks validate the local
implementation and separately tagged test images; they are not a production deployment.

| Check | Result |
| --- | --- |
| `python -m pytest -q` | 156 passed, including the existing 86-test suite |
| Source/check candidate validation | 35 source records, 24 check mappings and pinned schema fingerprints validated; no activation |
| Edge browser lifecycle and report regression | Passed; real backend package report, policy concern distinct from malware, coverage, evidence pagination, full export, cancellation, stale responses, timeout, unmount |
| Browser repeated report stress | 12 sequential scans; each report 200 files/8,000 synthetic findings; visible files capped at 10, findings at 100 |
| Browser resource observations after GC | 2,511 DOM nodes each iteration; used heap approximately 10.36–10.45 MiB |
| ARM64 sandbox Docker build | Passed; local validation image `sha256:d3372c7d72e98a3548c3286e131258374a900193664413178b2d7bf53b1812c3` |
| ARM64 web Docker build | Passed; local validation image `sha256:4256713c2d4a02ddcf71bef0f65aad0b6c19d17b868255a99eb175c2d16aad55` |
| Sandbox container smoke | Passed under read-only filesystem, temporary `/tmp`, no network, dropped capabilities, no-new-privileges; 24 outcomes, code-as-document policy signals and partial binary coverage |
| Web container smoke | Multipart scan and runtime profiles returned HTTP 200 with 24 outcomes; PowerShell-as-Markdown triggered policy review |
| `git diff --check` | Passed; Git reported only local LF/CRLF normalization notices |

Multi-language regressions cover Python's nested-fence `apply_notes.py.md` example,
JavaScript/TypeScript, shell, PowerShell, Ruby, Perl, PHP, Lua, batch and R declarations;
literal extraction/invocation chains; and selected raw syntax/shebangs under `.me`.
The helpers and uploaded source are analyzed as data, never executed by these scans.
Benign fenced examples without execution/packaging evidence have negative controls.

Evidence regressions cover signature process arguments/success/failure/timeout,
missing verifier configuration, HMAC issuer trust, tampering, expiry, future dates,
artifact mismatch, unsigned claims and authenticated failing evaluations. Verifier and
evaluation process interfaces are mocked in these tests. No real OMS publisher
signature, vendor tenant, or uploaded workflow was validated or executed.

## Host memory controller — repaired before release

The Docker host reported: `Your kernel does not support memory limit capabilities or
the cgroup is not mounted. Limitation discarded.` A build with `--memory 256m` also
failed at cgroup setup; the normal builds and smoke tests above passed. Therefore the
configured Compose memory limit was not enforced during the original candidate validation.
Application upload, archive, parser, report and per-worker scan admission budgets are
implemented, but they do not replace a functioning host memory controller.

Following explicit authorization to fix and deploy, the boot command line was backed
up to `/boot/firmware/cmdline.txt.before-injecticide-memory-20261019` and
`cgroup_enable=memory` was appended to `/boot/firmware/cmdline.txt`. After one reboot,
`/sys/fs/cgroup/cgroup.controllers` includes `memory`; Docker reports `MemoryLimit=true`
and `SwapLimit=true`. A 64 MiB test container reads `memory.max=67108864`. A separate
32 MiB test container attempting a 96 MiB allocation was contained by the kernel:
`OOMKilled=true`, exit 137, configured memory 33554432. The probe was removed afterward.
Existing Injecticide, DNS, tunnel and file-sharing services recovered successfully.

The deployment wrapper now refuses deployment before stopping the stack if Docker
reports memory limits unavailable. This prevents silently accepting ignored limits.
Sources: [Raspberry Pi kernel maintainer explanation](https://github.com/raspberrypi/linux/issues/6980)
and [Docker resource constraints](https://docs.docker.com/engine/containers/resource_constraints/).

The generated validation build context was preserved recoverably in
`tmp/.package-release-context`; it is excluded from default pytest discovery and the
candidate's staged scope. Unrelated architecture documents and recovery material remain
untouched. Human acceptance is still required before release of this major candidate.
