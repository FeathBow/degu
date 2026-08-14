# Operational safety

> [!IMPORTANT]
> This `main` safety model documents the next release. The latest published release is **v0.1.4**, which does not implement the sealed-staging, readiness, or tool-native reclaim boundaries below. Use the [v0.1.4 safety model](https://github.com/FeathBow/degu/blob/v0.1.4/docs/safety.md) with that binary.

This document defines degu's runtime discovery, cleaning, staging, and purge semantics. It is distinct from the project [security policy](../SECURITY.md), which explains how to report vulnerabilities privately.

## Cleanup states and underlying facts

degu never deletes a finding in place. Human output starts with the action available to the user:

- **Ready to clean** findings are cleaned by default. These are cheap-to-regenerate caches such as pip.
- **Needs review** findings are regenerable but costly or carry a declared deletion hazard. Compile caches cost rebuild time, model caches cost download transfer, and removing Conda package caches can break environments installed with softlinks. Review the reported reason, rationale, and exact path with the displayed `degu clean -dn --review PATH` command. This is shorthand for `--details --dry-run --include-review --path PATH`; it does not broaden authority.
- **Not managed** findings are informational and are never staged or purged. They include user assets such as conda environments and training checkpoints, shared-memory segments, tool-coordinated caches, protected mixed-state directories, trees containing entries owned by another UID or group/world-writable directories, and caches known only from `CACHEDIR.TAG` when recovery and ownership are unknown.

Every finding also carries independent machine facts: recovery and ownership may be known or unknown, regeneration may be cheap or costly, locations may be verified or unverified, and deletion may carry hazards. JSON derives the stable `eligible`, `opt_in`, or `report_only` disposition from those facts while human output uses the action-oriented names above.

A regenerable cache relocated with a tool's own environment variable, such as `PIP_CACHE_DIR` or `HF_HUB_CACHE`, appears as **Not managed** (`report_only` in JSON) unless a valid `CACHEDIR.TAG` corroborates the location. Without that evidence, degu uses the redirected path verbatim and marks its location unverified.

Two related location forms remain verified:

- Standard user bases where degu computes a fixed ecosystem cache subdirectory, including `XDG_CACHE_HOME` and the first usable Python temporary-directory candidate used by PyTorch Inductor.
- A relocated cache carrying a valid `CACHEDIR.TAG` at its top level.

`XDG_CACHE_HOME` is a cache base by specification, so a fixed ecosystem subdirectory beneath it is trusted structurally and stays verified without a `CACHEDIR.TAG`; this keeps the sanctioned `XDG_CACHE_HOME=/scratch/$USER/cache` relocation cleanable. `XDG_DATA_HOME` holds user data rather than cache, so degu derives no eligible finding from it: its only `XDG_DATA_HOME` consumers, the podman and rootless docker container stores, are always **Not managed**.

Cache subdirectories derived from `HF_HOME` and `CARGO_HOME` remain unverified unless their exact roots carry valid `CACHEDIR.TAG` files. The variables still select mixed-state tool homes that can also hold tokens or installed binaries, so `degu relocate` points cache-only variables such as `HF_HUB_CACHE` at scratch and never proposes moving either mixed-state home.

`degu relocate --init` uses the same structural authority split: it initializes only exact roots declared by adapters as cache relocations and never acts on relocation refusals such as `HF_HOME` or `CARGO_HOME`. The target base itself is never tagged. Default `degu relocate TARGET` remains read-only and only prints the proposed shell configuration.

Initialization opens directories and tags with descriptor-relative, no-follow operations, rechecks type, effective-user ownership, mode, and device/inode identity after creation, and rejects symlinks and non-regular tags without reading through them. The target's whole ancestry is resolved one component at a time on held descriptors, and every directory the resolution descends into — each lexical ancestor and each directory a followed symlink resolves through — must be a namespace that grants no foreign mutation authority: owned by the effective user or root, and not group- or other-writable unless it is sticky (as `/tmp` is), with an additional effective-user/root owner check on each entry traversed under a sticky parent. Intermediate symlinks are permitted only when degu can authenticate both the symlink's own binding and its complete resolved target chain against that policy — admitting root-managed system links (`/var`, `/tmp`) and admin- or user-managed scratch links while refusing anything reachable through a group-writable, non-sticky directory — so a co-tenant cannot rename a component or re-point a symlink to substitute the target. Before printing any export degu re-runs the full resolution and confirms the target still names the directory it initialized. New target bases and cache roots are forced to mode `0700`; new tags are forced to `0600`, independent of umask. Existing target bases and cache roots must be real effective-user-owned directories without group or world write bits, and existing tags must be safe effective-user-owned regular files whose first line is the standard signature (a trailing CR is tolerated, matching the scan-time tag check); a root that also holds a `pyvenv.cfg` is refused as a virtualenv, matching the scanner's veto.

`--init` establishes safe ownership and modes only at initialization time. Because cache tools later create descendants under the caller's umask, a cache populated under `umask 002`/`007` can gain group-writable subdirectories, and degu then keeps such a tree **Not managed** (`report_only`) even after `--init` — the same conservative treatment any group- or world-writable tree receives. Making a group-writable relocated cache cleanable requires an explicit, scoped cooperative-group trust policy, which is tracked separately; `--init` alone does not grant it.

The full set of relocation subdirectories is component-validated and preflighted before mutation. If a later initialization step or the final target-binding revalidation fails, rollback works in reverse through held parent descriptors and removes only this invocation's identity-matched tags and empty directories. Identity changes, non-empty directories, and other rollback failures are left in place and reported as residue rather than risking deletion of a replacement or pre-existing object. Once initialization and that revalidation both succeed the transaction is committed and rollback is released; a failure while writing the report or script afterward therefore leaves the completed, valid roots in place (a re-run reports them already initialized), and a closed output pipe still exits successfully by convention.

## Sealed-staging account readiness

`degu doctor` is the single user-facing check that the current account's fixed
anchor is ready for sealed staging. It checks only the anchor, not an activated
store, WAL, or recovery state. It derives that anchor only from the platform and current effective UID,
then applies the same existing-only, descriptor-relative, no-follow
owner/mode/ACL/backend/identity/binding/lock/durability validation used by the
activation core. The check creates or writes no degu anchor, store, record, or
lifecycle state. Validation briefly takes the protocol's existing nonblocking
lock and calls durability sync on the already-provisioned anchor and parent. It
does not consult HOME, XDG variables, configuration, environment overrides, or
a caller-provided path.

The result is `ready`, `missing`, `unsafe`, `unsupported`, or `uncertain`.
Anything except `ready` fails closed and prints administrator remediation.
Missing does not mean first activation and never permits a HOME or legacy
fallback. Unsafe entries are not automatically chmodded, replaced, or repaired;
inspection uncertainty is not compressed into missing or ready. Root and a
malicious same-EUID process remain outside the Unix trust boundary.

The unprivileged installers install binaries only and merely suggest running
`degu doctor`. They do not invoke sudo, inspect `SUDO_UID`, or create an
activation anchor. For a never-activated numeric UID, an administrator uses a
separately verified binary from an administrator-owned absolute path to run
`degu admin setup --uid <UID> --initial` with real EUID 0. The command
derives the only path from platform plus UID, creates with
descriptor-relative/no-follow operations, and never repairs an existing object.

Mutating clean, undo, purge, and expiry sessions derive the same current-EUID
anchor and use it as the only whole-store activation/discovery authority. A
supported record-empty anchor activates the canonical current state-store
locator. Once activation evidence exists, the recorded exact locator wins over
HOME/XDG drift; a lost, replaced, corrupt, unsafe, missing, busy, or uncertain
anchor/store blocks mutation and never creates a substitute store. The sole
legacy escape is `UnsupportedNeverActivated`: the anchor was authenticated and
record-empty, and the desired store backend was positively classified outside
the certified set. That legacy session retains the exact anchor lock for its
full lifetime, so another process with different XDG state cannot activate a
store concurrently. Activated sessions instead retain and replay the exact WAL
lease for the full mutation session.

A WAL-associated staged object never falls through to legacy pathname or JSONL authority. Healthy `VerifiedCommitted` transactions can mint object-bound, one-use authority for `degu undo`, explicit `degu trash purge`, or seven-day expiry. Missing JSONL cannot remove that protection, and adding a JSONL record cannot grant authority. Association, identity, namespace, or recovery uncertainty blocks mutation.

Production forward cleanup is connected to activation and startup recovery. `doctor ready` proves only anchor readiness, not WAL or recovery health. A sealed purge durably records its exact claim before deletion and syncs monotonic progress after every successful unlink or rmdir. An interruption before durable outcome becomes `RecoveryRequired`; startup does not infer completion from paths or automatically resume deletion. A durable outcome finalizes `Purged` without a namespace lookup. `RecoveryRequired` cannot be cleared by reprovisioning an anchor and remains an operator-investigation state.

## Staging, undo, and purge

`degu clean` normally stages findings under `$XDG_STATE_HOME/degu/trash`, or `~/.local/state/degu/trash` when `XDG_STATE_HOME` is unset. Staging keeps the operation undoable with `degu undo`, but staged data continues to consume filesystem quota.

A confirmed mutating `degu clean` permanently purges staging entries at least seven days old — even with an empty current plan — after all current clean items succeed. There is no background timer.

Permanent deletion is always explicit before that expiry:

- `degu clean --purge` routes each item in the fixed current plan through staging and immediately purges its staged entry after a second confirmation. `--yes` skips the prompts.
- `degu trash purge` locks and displays every current trash entry, requires the exact confirmation word `purge`, and permanently deletes only that fixed plan. `--yes` skips the prompt for reviewed automation.
- `degu trash list` shows trash entries, and `degu scan` reports the trash size while it still consumes quota.

Purge removes degu-managed directory entries. Bytes reported as hardlink-shared may remain allocated through links outside the purged tree, so the amount deleted is not a guarantee of equal quota release. Human output calls out this case, and JSON exposes it as `bytes_hardlinked`.

`degu undo` restores the latest staged clean operation to its original paths. Restoring data does not release quota.

## Protected paths and symlinks

The safety guard rejects the entire plan if any candidate resolves onto or around a protected path. It never downgrades that condition to skipping one item.

Built-in protected locations include `.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, keyrings, `.config`, `Documents`, `Desktop`, mixed-state AI tool directories `.claude`, `.codex`, and `.hermes`, and degu's own state directory. Credential directory names are refused wherever they appear in a path, even outside `$HOME`. The configuration `protect` field can add more locations.

The AI tool directories above can contain caches alongside sessions, credentials, configuration, memories, plugins, and databases. An AI tool directory or any descendant is rejected as a project root, whether supplied explicitly to scan or clean, loaded from scan configuration, or reached through a symlink alias. A broader project root remains usable, but degu prunes these subtrees before classification. A precise ecosystem cache that overlaps or contains one may remain visible as **Not managed**, but it never gains cleanup authority. A protected prune is a deliberate, name-based exclusion, so it never blocks cleaning unrelated locations and never grants cleanup authority to anything it hides.

The guard resolves path relationships in both directions: it rejects deleting inside a protected path and rejects deleting an ancestor that contains one. It also resolves symlink aliases for this comparison. Read-only discovery does not intentionally descend through entries classified as symlinks, but it is not a filesystem snapshot. Mutation-time tree validation opens directories relative to already-open directory descriptors with no-follow semantics, so a directory replaced by a symlink is rejected rather than traversed.

## Filesystem and root boundaries

When degu's normal state directory is on another filesystem, it creates a same-filesystem staging directory under a writable, user-owned ancestor of the finding. This preserves the staging-and-undo model across filesystem boundaries instead of treating a cross-filesystem move as an in-place deletion.

Managed trash roots and their claim directories must be real directories owned by the effective user and must not be group- or world-writable. degu creates its own directories with mode `0700` and rejects unsafe existing roots instead of traversing them.

Adapter and project scans account only entries owned by the invoking effective UID. A foreign-owned file or directory is recorded as a measurement gap, a foreign-owned directory is not entered, and the enclosing finding becomes **Not managed**. Group- or world-writable directory mode bits do not make the size a lower bound, but they independently remove cleanup authority because another UID may be able to insert an entry.

Immediately before staging, degu validates the complete no-follow tree before writing the operation log's `Pending` record, then runs the protection re-check and repeats the full tree traversal after `Pending` as the final callback-free operation before the verified rename. Every entry must still belong to the effective UID, every directory must still lack group/world write mode bits, and the tree must remain on the source mount. This owned-tree gate applies to new clean staging only. Undo and purge retain their separate recorded-identity and mount checks so old trash is not made unrestorable merely because its historical ownership differs.

Mutating operations reject a finding or trash entry that is itself a mount point or whose tree contains a mount boundary. Permanent deletion traverses through opened directory descriptors, revalidates each discovered directory before entering it, and rechecks names before unlinking them. A measurement with skipped or unvisited entries is an incomplete lower bound and never receives cleanup authority.

Legacy `.claims` entries remain visible in `degu trash list`, never expire automatically, and require inclusion in a newly confirmed purge plan. Sealed purges do not create `.claims` paths: the exact WAL lease, held inventory, durable claim, and progress records are authoritative. Interruption before the sealed outcome enters `RecoveryRequired` and blocks mutation rather than falling back to legacy retry.

degu refuses to run as root unless it detects a container through `/.dockerenv` or `/run/.containerenv`, or the operator explicitly sets `DEGU_ALLOW_ROOT=1`.

If degu moves or permanently removes data outside the confirmed clean or purge set, or if a protected-path, symlink, or filesystem-boundary check can be bypassed, stop using the affected operation and follow the private process in the [security policy](../SECURITY.md).

degu detects ordinary concurrent path replacement with object-identity snapshots and verified no-replace claims before permanent deletion. Scan classification and the legacy owned-tree gate use Unix ownership and mode bits and do not interpret arbitrary ACL grants; configure ACL-shared legacy locations as protected. Sealed activation and staging fail closed unless ACL absence can be established on certified ext4/XFS/APFS objects. `reclaim uv` applies a separate audited policy: Linux POSIX ACLs are rejected, while macOS deny-only or read-only ACLs are allowed but mutation-granting or unknown entries are rejected. Unix still provides no security boundary against a malicious process running with the same effective user ID; run mutating commands only in a trusted user session.
