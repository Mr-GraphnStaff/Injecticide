# Raspberry Pi deployment

Azure Pipelines validates each candidate on a Microsoft-hosted runner. Commits
merged into `master` can then enter the `injecticide-pi-production` environment
and run on the dedicated `injecticide-pi-arm64` agent.

The agent is deliberately not a member of the `docker` group. Its only
privileged deployment action is the root-owned
`/usr/local/sbin/injecticide-deploy` wrapper. The wrapper:

- accepts one full commit SHA;
- fetches only the approved GitHub repository;
- requires the commit to be reachable from `origin/master`;
- stops the existing Injecticide stack, removes its previous application
  images, refreshes Nginx, and rebuilds with `--no-cache --pull`;
- starts the Compose application under the fixed `injecticide` project name;
- checks both the application and reverse-proxy HTTP endpoints; and
- rebuilds the previous commit if the candidate fails.

The production checkout is `/mnt/nvme/deploy/Injecticide`. Runtime reports are
kept outside Git at `/mnt/nvme/injecticide-data/reports` so deployments do not
replace them.

The wrapper and sudoers rule are installed manually as root. Pipeline jobs must
not install or update either file.

From 0.14.1, each critical deployment command explicitly returns failure even
when invoked inside the candidate/rollback conditional. HTTP root responses alone
cannot establish readiness: all three application containers must be running and
healthy, and Nginx running. CI also imports and scans inside the built sandbox
image with network access disabled.

`/mnt/nvme/deploy/injecticide-last-healthy` is a root-owned recovery marker,
written only after full health acceptance. It must identify a full SHA reachable
from the approved master history. An operator bootstraps it from verified release
evidence; checkout HEAD is never assumed to identify healthy running images.
The 0.14.1 repair uses the last independently verified 0.12.0 revision
`bf10a4bb45ccc1152eb3ae2e52498ae21bb93d1c` as its initial recovery target,
because 0.14.0's apparent deployment success did not establish scanner health.

Cache removal is intentionally scoped to Injecticide images. The wrapper does
not run a global Docker cache prune because the Pi also hosts unrelated
services.
## Host memory controller prerequisite

The deployment wrapper checks Docker memory-limit support before stopping the stack.
`docker info --format '{{.MemoryLimit}}'` must return `true`.
On the production Raspberry Pi, memory control was enabled by appending
`cgroup_enable=memory` to `/boot/firmware/cmdline.txt` and rebooting after backing up
the original file. Check cgroup v2's `cgroup.controllers` and the actual container's
`memory.max`; `/proc/cgroups` alone does not establish v2 support. Confirm the sandbox
has a 256 MiB limit after containers are recreated. See the October 19 package-scan
validation record for the bounded allocation test and backup path.
