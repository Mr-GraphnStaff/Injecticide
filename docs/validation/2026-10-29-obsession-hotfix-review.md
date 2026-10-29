# Independent review: Obsession 0.14.1 container/health hotfix

Date: 2026-10-29. Reviewer: Lena, separate assurance agent reporting to Avery; David is team lead. Scope: actual sandbox Docker packaging, built-image CI smoke, deploy-command failure propagation, all-service health, verified rollback identity and truthful outcome reporting. No commits, privileged installation, remote mutation, paid provider or private upload was performed by this reviewer.

## Confirmed incident and review gap

The released sandbox image's explicit COPY list omitted `obsession_signatures.py`, which `scan_rules.py` imports. The application could not start in the flat container filesystem. Successful repository tests and a Docker build had not proved that the built sandbox imported or scanned successfully. The earlier independent scoped review also did not boot that built image; that was a material assurance gap.

The deployment function ran as an `if` condition. Depending on Bash `set -e` inside that call chain allowed a failed Compose operation to be followed by successful web-root probes and a false success outcome. Web/research health did not establish scanner availability. The recovery revision must be an actually verified healthy release, not the broken checkout HEAD or a falsely advanced current marker.

## Acceptance requirements

- The packaged filesystem must contain every locally imported module. A reconstruction regression should reproduce the previous missing-module error when the COPY is removed; actual container import/static-scan evidence remains separate.
- CI must run the actual built sandbox image with networking disabled and assert rule-catalog import, one static scan, current version and process/source evidence. A successful build alone cannot qualify.
- Each critical deploy operation must explicitly return failure. Image enumeration errors must not look like an empty successful list. A healthy root page cannot override failed Compose startup or an unhealthy application service.
- Marker-based recovery must use an approved, actually healthy revision. A failed candidate with successful rollback remains a failed candidate deployment; failed rollback must report failure and must not advance success markers.
- Source wrapper changes require separate root-controlled installation/readback before its behavior can be claimed on the Pi. The repository change or CI result does not prove installed-wrapper identity.

## Evidence initially inspected

Read the actual sandbox Dockerfile, wrapper, deployment README, Compose isolation/health definitions, new packaging reconstruction tests and CI smoke script. The Dockerfile now explicitly copies the omitted module. Independent execution of `tests/test_sandbox_image_contents.py` and `tests/test_skill_sandbox_dockerfile.py` produced **4 passed in 4.50 seconds**. The reconstruction uses isolated Python imports and a static scan; its negative control removes the COPY and reproduces `ModuleNotFoundError`. This is not an actual Docker run. No Docker CLI was available in this reviewer's local environment.

The actual-image CI smoke is source-inspected: it uses the newly built image, no network, a read-only filesystem and bounded tmpfs, and asserts import, catalog, scan, version and process evidence. Actual CI/container execution and post-deployment uploaded-scan acceptance must be recorded separately by the coordinator.

Final deploy/failure/rollback checks and the independent scoped verdict will be recorded below after the implementation is stable.

## Final independent scoped result

The final wrapper propagates each critical checkout/config/down/pull/image-removal/build/up failure explicitly. Docker image-list failure is captured before iteration. Application HTTP responses are accepted only with all three application containers running and healthy and Nginx running. The recovery marker is validated as a full SHA in approved master history. The earlier proposed HEAD fallback was removed after review: container health alone does not prove which checkout revision produced those images.

Independent final command: `tmp/obsession-validation-venv/Scripts/python.exe -m pytest tests/test_deploy_failure_propagation.py tests/test_sandbox_image_contents.py tests/test_skill_sandbox_dockerfile.py tests/test_deployment_assets.py -q` — **20 passed in 8.03 seconds**. The Bash failure tests invoke actual deployment functions in their conditional context with external effects stubbed. They cover eight critical failure points, failed image enumeration and an unhealthy sandbox despite successful web probes.

Additional independent probes exercised the actual `main` control flow in temporary directories. Only the root-user precondition was bypassed in the temporary harness, and all external operations were stubbed; production files and privilege policy were not changed. All four scenarios passed:

- Healthy candidate: exit success and both markers advance to the candidate.
- Failed candidate, healthy verified rollback: candidate deployment exits nonzero and both markers identify the recovered healthy revision.
- Failed candidate and failed rollback: exit nonzero, explicit rollback failure, neither marker advances.
- Missing recovery marker: failed candidate gets no inferred checkout-HEAD recovery and no new healthy marker.

Three additional actual-function controls passed: all application/HTTP health succeeds; image-removal failure propagates; the complete successful critical deploy path succeeds. An initial temporary main harness used Windows-translated marker line endings and stopped at SHA validation; it was corrected to Linux LF marker bytes before the four final scenarios. This was a harness issue, not an observed production defect.

`git diff --check` passed with line-ending conversion notices only. Reviewed SHA-256 identities:

| File | SHA-256 |
| --- | --- |
| `deploy/pi/injecticide-deploy` | `c35c296fb7242b880781b5910c8c4c6f0f35a7faeb4aa5b5855a8b96da744d34` |
| `skill_sandbox/Dockerfile` | `e6935b68a2de1255a2e6980c6c44a2841f90a24f290920ddfec97187405dbe3c` |
| `azure-pipelines.yml` | `68fe207f5911631ad0593d337fbc471aaf50b1f3c9e1d2486fdb20b68c00f0ba` |

**Code-review recommendation:** no unresolved blocking defect was observed in the scoped hotfix after these checks. This is not human PR acceptance or live stack acceptance. Required operational evidence remains: exact installed root-owned wrapper readback/hash and backup, actual built-image smoke success, all deployed service states/health and image revisions, and a fresh uploaded static scan through the deployed web API returning the intended scanner version and source/process evidence. The known healthy 0.12.0 recovery identity must be bootstrapped from retained acceptance evidence; a source statement alone does not prove that host marker was installed. Actual rollback on the Pi was not forced or tested by this reviewer.

The installed wrapper, built container and deployed application are separate artifacts. A passing pipeline or repository diff cannot substitute for their final readback and actual scan result. No new paid service, external model call, private upload, privileged installation, commit or remote mutation was performed by this reviewer.
