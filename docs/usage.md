# User guide

> [!IMPORTANT]
> This `main` guide documents the next release. The latest published release is **v0.1.4**, which does not include account readiness, sealed staging, `--review`, or `reclaim uv`. Use the [v0.1.4 user guide](https://github.com/FeathBow/degu/blob/v0.1.4/docs/usage.md) with that binary.

## Scan and quota

Start read-only. `scan` shows individual findings, while `scan --summary` groups the same detected bytes and inodes by source.

```sh
degu scan
degu scan --summary
```

A bare `degu scan` checks known cache sources and any persistent `roots` configured for read-only discovery. Positional project roots are additive: `degu scan .` still checks the same known caches and also recursively includes build artifacts under the current project, while `degu scan PATH` does the same for another project tree. `PATH` may be a parent directory holding many projects, such as `~/code`: discovery recurses into every project beneath it. To inspect only project artifacts, run `degu scan --only artifacts .`. Configured roots never authorize cleanup: pass the project root explicitly to `degu clean PATH --dry-run` before its findings can enter a clean plan.

`quota` is independent from discovery. It asks the filesystem for authoritative usage and configured soft and hard limits for the effective user ID. The validated providers currently cover Linux VFS user quota on ext4, and Lustre user quota via the lfs client tool, field-validated live on a Lustre 2.15 client; both the legacy and current lfs column-header formats are parsed, the current format covered by fixtures derived from upstream source. Lustre grace deadlines are derived from lfs countdowns and are accurate to a few seconds; an expired grace period reports no deadline (JSON null). Other Linux filesystems and macOS report unsupported; unavailable and permission-denied providers also fail instead of falling back to filesystem capacity or scan totals.

```sh
degu quota
```

Human findings adapt to the terminal width; normal layouts middle-truncate long paths with the basename preserved, and the details view and JSON keep them in full. Redirected output remains deterministic.

An ellipsis marks omitted path components, and `~` means `$HOME`; shortened human paths are never presented as complete. Human views render terminal controls, invisible Unicode, and backslashes as visible escapes. Use the details view for absolute paths and cleanup rationale, or JSON to preserve exact path data:

```sh
degu scan --details
degu clean --details --dry-run
degu scan --json | jq '.findings[].path'
```

Finding objects in the `findings` and `runtime` arrays of `scan --json`, and the `planned` and `excluded` arrays of `clean --json`, include `recovery`, `ownership`, `confidence`, and the derived `disposition`; `hazard` is present only when known. Consumers must treat unknown enum values as non-cleanable.

A finding's classification lives in nested objects, so automation should key on `disposition.mode`, which is `eligible`, `opt_in`, or `report_only`. A `reason` field is added only for non-eligible findings, and `recovery` carries its own `kind` and `cost`:

```console
$ degu scan --json | jq '.findings[0] | {ecosystem, kind, path, disposition, recovery, ownership, confidence}'
{
  "ecosystem": "pip",
  "kind": "package_cache",
  "path": "/home/researcher/.cache/pip",
  "disposition": {
    "mode": "eligible"
  },
  "recovery": {
    "cost": "cheap",
    "kind": "regenerable"
  },
  "ownership": "standalone",
  "confidence": "verified"
}
```

Select only what degu would clean by default:

```sh
degu scan --json | jq '.findings[] | select(.disposition.mode == "eligible") | .path'
```

A consumer that keys on `disposition.mode` fails safe: if a future field is renamed or missing, the filter matches nothing, so automation cleans nothing rather than the wrong thing.

Scans are complete by default and have no implicit time budget. `--budget` is the only intentional truncation control, and its clock starts immediately before collection.

- **Truncation control.** Once expiry is observed, degu does not start another root, directory, entry, or adapter-owned enumeration unit. Requested project roots are validated before a zero budget can short-circuit collection, so invalid input remains an error.
- **Scheduling order only.** Roots that may yield actionable findings run before roots known to be report-only, but this static scheduling hint never grants cleanup authority. A root reached through an environment-variable redirect keeps an early slot only when a valid CACHEDIR.TAG corroborates it at scheduling time; otherwise it is deferred behind verified actionable roots. That scheduling probe orders work only — cleanup authority re-checks the tag after scanning.
- **Bounded overshoot and safety finalization.** In-flight filesystem operations cannot be safely preempted, so each active worker may finish its current operation before degu observes the deadline. Cooperative overshoot is bounded to those current operations and one candidate batch that an adapter has already returned. Degu completes the claims, protection, and classification checks for that batch because skipping safety finalization is not acceptable; this work does not discover more candidates.

For `scan --json`, each section is `complete`, `incomplete` when one or more paths could not be fully inspected or classified, `truncated` when the deadline expired, or `not_requested` when that section was not selected. A truncated scan is an honest successful report and exits 0. Automation must inspect completeness and treat both `incomplete` and `truncated` sections as lower bounds. In `scan --summary --json`, every source row and total carries the corresponding `lower_bound` boolean.

Missing, unreadable, non-directory, and protected mixed-state project roots fail the command instead of producing an empty successful report. A nested unreadable directory inside a valid root no longer fails the scan: it is recorded as an incomplete region, the section reports `incomplete`, and totals become lower bounds. A broader project root remains usable because protected subtrees are pruned before classification. See the [protected-path and symlink rules](safety.md#protected-paths-and-symlinks) for the exact boundary.

## Clean and recover

Preview the **Ready to clean** plan before staging it in degu's undoable trash:

```sh
degu clean -n
```

The preview does not modify data. Running `degu clean` without `--purge` stages the current **Ready to clean** findings; staged entries later expire under the [seven-day purge policy](safety.md#staging-undo-and-purge).

A successful `clean --json` report includes the findings scan's `completeness`. An incomplete scan may return an empty plan but cannot authorize an incompletely measured item; a truncated scan always fails. A whole-plan clean is rejected before staging when any location could not be fully measured — unreadable directories, probe errors, or unaccounted incompleteness events; deliberate protected exclusions (AI-tool and credential directory prunes) inside a measured cache keep the scan `incomplete` and its totals lower bounds but do not block the plan, because a pre-descent name-based prune cannot change which findings are eligible. A clean narrowed with `--path` proceeds only when every selected location was itself fully measured and every incompletely measured region is provably disjoint from the selection — such a region overlapping the selection could change which findings the selection matches, so it is refused. An ecosystem cache finding that itself contains a protected exclusion stays visible as report-only and is refused individually when selected; a project build-artifact or checkpoint claim that contains one is withheld from the report entirely and surfaces only through the scan's incomplete marker and the clean disclosure count.

After reviewing the plan, run:

```sh
degu clean
```

**Needs review** findings remain excluded, and the output explains why. It highlights the largest review location with its exact path and a copyable `degu clean -dn --review PATH` command. `--review PATH` is only shorthand for the existing `--include-review --path PATH` combination: it opts in one exact location without changing eligibility rules. Run that preview first; its `Next` command preserves the same path and filters for execution. **Not managed** findings cannot enter a clean plan. See [cleanup states and their underlying facts](safety.md#cleanup-states-and-underlying-facts) for the full policy.

Newly staged entries remain reversible and continue to count against your quota. `degu undo` restores them to their original paths without releasing quota; only purging permanently deletes them.

Choose one outcome for the staged data. Do not run both branches for the same clean operation.

Restore the latest clean operation:

```sh
degu undo
```

Or inspect every trash entry, including legacy interrupted claims and entries from earlier clean operations, then permanently delete the fixed reviewed plan:

```sh
degu trash list
degu trash purge
```

A sealed purge interrupted after its durable WAL claim is different: startup marks it `RecoveryRequired`; it does not become a legacy claim that `trash purge` may guess or retry.

For immediate permanent deletion, use `degu clean --purge`. Successfully purged entries cannot be restored. The [staging, undo, and purge policy](safety.md#staging-undo-and-purge) defines the confirmations and fixed-plan guarantees for both purge commands.

## Tool-native reclaim (advanced)

Normal `clean` reports uv caches as **Not managed** because uv owns their internal cleanup rules. For exactly uv 0.12.3, degu can validate and run the tool's fixed ordinary prune while keeping both authority inputs explicit:

```sh
degu reclaim uv -x /absolute/path/to/uv -c /absolute/path/to/uv-cache -n
```

`-x`/`--executable` selects the exact uv binary; `-c`/`--cache-dir` selects its active cache root. The `-n`/`--dry-run` preview creates a private executable snapshot, starts only that snapshot with `-V`, and validates the selected cache namespace. It does not run prune, but the selected binary is not sandboxed.

After reviewing the preview, rerun without `-n` and type `prune`:

```sh
degu reclaim uv -x /absolute/path/to/uv -c /absolute/path/to/uv-cache
```

This action revalidates the held executable and cache namespace immediately before spawning a fixed ordinary `uv cache prune`. It bypasses degu trash, has no exact item or byte preview, and cannot be undone. Degu deliberately does not search `PATH`, infer a cache root, accept another uv version, or provide a one-flag shortcut: shortening those authority inputs would make a different object eligible for deletion. Reviewed automation may use `-y`; mutating JSON requires `-y`.

## Relocate future caches

Direct future cache writes to persistent scratch by replacing `/scratch/$USER` with an absolute scratch path provided by your system. Capture the generated script without masking the command's exit status:

```sh
relocate_script=$(mktemp "${TMPDIR:-/tmp}/degu-relocate.XXXXXX")
degu relocate "/scratch/$USER/degu-cache" > "$relocate_script"
```

`relocate` prints configuration; it does not move existing data or edit your shell profile. After the command succeeds, review the file before loading it:

```sh
cat "$relocate_script"
. "$relocate_script" && rm -f "$relocate_script"
```

Add the reviewed export lines to your shell profile to direct future logins to the same cache paths. Existing data stays in place.

By default, `degu relocate TARGET` performs no filesystem mutation. To initialize the proposed cache roots before receiving the script, opt in with `--init`:

```sh
relocate_script=$(mktemp "${TMPDIR:-/tmp}/degu-relocate.XXXXXX")
degu relocate --init "/scratch/$USER/degu-cache" > "$relocate_script"
```

`--init` creates only the exact cache roots named by cache-specific relocation exports, with mode `0700`, and writes a standard `CACHEDIR.TAG` with mode `0600` in each root. It does not tag the target base, initialize mixed-state homes such as `HF_HOME` or `CARGO_HOME`, move existing cache contents, or edit shell profiles. A pre-existing cache root is accepted only when it is already safely owned and carries a valid, safely owned `CACHEDIR.TAG`; an untagged pre-existing directory is rejected even when empty.

The target's parent must already exist; `--init` does not create missing ancestor directories, so create the parent yourself first (for example `mkdir -m 700 -p /scratch/$USER`). degu resolves the target one component at a time and requires every directory it descends into — each lexical ancestor and each directory a followed symlink resolves through — to be a namespace that grants no foreign mutation authority, so no other user can rename a component or re-point a symlink to redirect the target. A namespace qualifies when it is owned by you or root and is not group- or other-writable unless it is sticky (as `/tmp` is); under a sticky parent each traversed entry must additionally be owned by you or root. Intermediate symlinks are permitted only when degu can authenticate both the symlink's own binding and its complete resolved target chain this way, which admits root-managed system links (`/var`, `/tmp`) and admin- or user-managed scratch links while refusing anything reachable through a group-writable, non-sticky directory.

`--init` guarantees ownership and modes only at initialization time. Cache tools you run later create their own descendants under your ambient umask, so with `umask 002` or `007` a tool that requests broad permissions typically leaves group-writable descendants (`0775`/`0770`). degu's scan and clean stay conservative about group-writable trees, so such a populated cache is reported but not eligible for cleaning until a scoped cooperative-group trust policy lands. `--init` does not by itself make a group-writable relocated cache cleanable.

Initialization is transactional over the filesystem: degu validates the full relocation plan before creating anything, and on any failure through the final target-binding re-check it prints no sourceable exports and removes only entries created by that invocation whose recorded identities still match — a rollback failure is reported with every known residual path. Once every root is initialized and the target still resolves to the initialized directory, the transaction commits; if writing the report or script then fails, the completed roots are left in place, since they already form a valid, idempotent state that a re-run reports as already initialized. With `--init --json`, the otherwise unchanged relocation report also includes an `initialization` object listing the newly created and already initialized cache-root paths.

Use `degu <command> --help`, `degu man <command>`, or the corresponding shipped page for the complete command-line reference. Nested pages use the full command path, such as `degu man trash purge`.
