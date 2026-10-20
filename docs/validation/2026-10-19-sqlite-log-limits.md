# SQLite member limits and container log rotation

Validated on 2026-10-19 before deployment.

## Behavior

- Upload limit remains 32 MiB; archive contents have a 64 MiB aggregate budget.
- SQLite members are recognized by their 16-byte SQLite header, in any directory,
  with a 32 MiB per-database cap. Ordinary files retain the 5 MiB cap.
- Existing references/Office allowances, path/link checks, 200-file ceiling and
  extraction byte accounting remain enforced.
- SQLite queries project at most 4,096 characters from each TEXT cell before
  Python receives it; BLOBs are not read into the text projection. Existing
  25-table, 50-row/table, 100,000-character and SQL operation budgets remain.
- Database results are a bounded sample, not certification of omitted records.
- All three Injecticide Compose services use json-file rotation: 10m, three files.
  This changes only the application stack, not Docker daemon defaults.

## Validation

- Full local suite: 171 passed.
- Compose rendering on the Pi confirmed all three effective logging settings.
- A disposable, network-disabled container using the production image with the
  candidate app.py/artifact_text.py mounted read-only enforced memory.max=268435456,
  memory-swap=256m, read-only root, no capabilities, no-new-privileges, 128 PIDs,
  and /tmp tmpfs limited to 100 MiB.
- Synthetic tests scanned a 32 MiB SQLite database of many small rows, one with
  a 24 MiB TEXT field, and two 32 MiB SQLite databases in a 64 MiB archive.
- Peak cgroup memory for those consecutive scans: 200245248 bytes (about 191 MiB).
  cgroup max/oom/oom_kill counters were all zero.
- Earlier baseline testing approached the cap. SQL-side text projection was
  added and retested. A stress-fixture connection-lifetime error was corrected
  before the final resource run; the final fixture explicitly closed its source
  SQLite connection before reading/deleting the source file.

Deployment and live-stack verification are separate from this pre-deployment record.
Rollback uses the existing deployment wrapper and previous approved commit.

References:
- https://docs.docker.com/engine/logging/drivers/json-file/
- https://www.sqlite.org/lang_corefunc.html#substr
