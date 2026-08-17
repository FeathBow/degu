# Operational safety

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

`degu doctor` is the read-only user-facing view of the current account's authority selector. The two candidates are fixed: the administrator-hardened platform/EUID path and the self-managed account-database home plus `.local/state/degu/store-activation/<uid>`. HOME, XDG variables, configuration, cwd, test overrides, CLI input, and caller-provided paths select neither candidate.

The selector opens existing candidates descriptor-relatively and authenticates ownership, modes, ACL absence, certified backend, strong identity, parent binding, lock, and durability. It then inspects activation records and the exact recorded store. It never creates an anchor, store, activation record, or lifecycle state.

Selection is deterministic and fail-closed:

1. one existing candidate is selected;
2. two record-empty candidates select the administrator-hardened one;
3. activation evidence in exactly one candidate selects that candidate, even when its peer exists but is empty;
4. evidence in both candidates is `split_authority` and blocks;
5. an unsafe, corrupt, busy, unsupported, or uncertain candidate blocks inspection instead of being treated as absent;
6. a lost or replaced recorded store is `recovery_required`, never first use;
7. no existing candidate is `missing`.

`degu init --initial` is the explicit first-use path for a missing self-managed candidate. It derives the non-root effective UID and account home from account database facts, accepts no UID or path, and uses the same no-follow runtime contract. `--initial` asserts that no earlier authority was lost; it is never migration or recovery permission. Existing entries are validated but never repaired or replaced. The account-database path is rechecked across the provision-to-declaration handoff so a home change cannot declare one leaf while reporting another. Initialization publishes a durable authority claim but does not create a WAL store or prepare/activate that store. Administrator provisioning remains optional and is likewise create-only. It refuses an existing self candidate, and its `--initial` contract requires every setup and lifecycle process for the target UID to be quiescent. Concurrent root system setup is outside the self-managed protocol; an administrator must never run it as a live migration or recovery mechanism.

Before store activation, degu durably publishes the identical peer witness first, then the selected authority claim. A crash therefore leaves either no new claim or a witness that names the selected root, never an unwitnessed newly selected root when a peer already exists. A surviving witness that names a missing selected root is `recovery_required`, not permission to use the empty peer. Matching witnesses select one root; mismatched claims are `split_authority`. When no peer exists, runtime still never resets authority automatically: recreating an absent self root requires the user's explicit `--initial` assertion, which must not be used after loss.

A supported first mutation may activate the canonical current state-store locator only while both visible candidate decisions remain locked. A visible provisioning lock is honored even before its leaf is published, so runtime cannot consume a pre-commit candidate. The selected and existing peer locks are retained for the full lifecycle session, along with the exact WAL lease. Once activation evidence exists, its recorded locator wins over XDG drift. Lost, replaced, corrupt, unsafe, missing, busy, or uncertain authority/store state never creates a substitute store.

The only dormant legacy result is `UnsupportedNeverActivated`: every authenticated candidate is record-empty and the desired WAL backend is positively outside the certified set. Its opaque session lease retains all selector locks. A WAL-associated staged object never falls through to legacy pathname or JSONL authority. Healthy transactions mint object-bound, one-use undo or purge authority; association, identity, namespace, or recovery uncertainty blocks mutation.

For a record-empty authority, `doctor ready` means the authority declaration is usable; the future XDG-selected WAL backend is certified only when first mutation probes it. An activated authority additionally authenticates its exact recorded store. Production cleanup enters this selector before startup recovery and retains the selected authority until the mutation session ends. Sealed purge records its exact claim before deletion and syncs monotonic progress after each successful unlink or rmdir. An interruption before durable outcome becomes `RecoveryRequired`; initialization or reprovisioning cannot clear it.

## Staging, undo, and purge

`degu clean` stages each finding by atomic no-replace rename to trash on the same data mount. When the normal `$XDG_STATE_HOME/degu/trash` lies inside that authenticated mount domain it remains the destination. The recorded mount anchor must pass the same trusted-ancestry resolver before the first WAL frame and on every later reopen; a foreign-controlled non-sticky ancestor is refused before staging. Otherwise degu uses `.degu-trash` beneath the highest writable effective-user-owned ancestor on the source mount. The activation anchor and WAL store may each live on other mounts; neither grants data-mount certification.

New staging transactions use WAL schema v11. Their first atomic frame stores one canonical mount-domain reopen pathname shared by the source and destination locators. That pathname is only a way to obtain candidate descriptors after restart: trusted-ancestry open plus the existing backend, filesystem ID, mount ID, strong parent/root identity, mode, ACL, and held-binding checks still grant recovery authority. A changed pathname, mount, or object blocks. Schema-v10 transactions remain readable and use the former canonical-HOME recovery arm; v10 never gains a synthesized external mount locator.

Staging keeps the operation undoable with `degu undo`, but staged data continues to consume filesystem quota.

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
