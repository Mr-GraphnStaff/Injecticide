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
- builds and starts the Compose application under the fixed `injecticide`
  project name;
- checks both the application and reverse-proxy HTTP endpoints; and
- rebuilds the previous commit if the candidate fails.

The production checkout is `/mnt/nvme/deploy/Injecticide`. Runtime reports are
kept outside Git at `/mnt/nvme/injecticide-data/reports` so deployments do not
replace them.

The wrapper and sudoers rule are installed manually as root. Pipeline jobs must
not install or update either file.
