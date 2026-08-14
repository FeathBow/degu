<h1 align="center">degu 🐭</h1>

<p align="center">Safely reclaim disk quota from caches and build artifacts on shared HPC and GPU clusters — unprivileged day-to-day cleanup, conservative cleanup, reversible staging by default.</p>

<p align="center"><em>For ML researchers on login nodes, drowning in pip, conda, HuggingFace, and compile caches.</em></p>

<p align="center"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=flat-square" alt="License: MIT OR Apache-2.0"> <img src="https://img.shields.io/badge/platforms-Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platforms: Linux and macOS"></p>

<p align="center"><img src="https://raw.githubusercontent.com/FeathBow/degu/main/docs/assets/demo.svg" alt="degu scan output: Ready to clean, Needs review, and Not managed tiers with sizes, reasons, and a copyable preview command" width="92%"></p>
<p align="center"><sub>Real output from a small demo tree; on a working ML node, model and package caches routinely reach tens of gigabytes.</sub></p>

> [!IMPORTANT]
> The latest published release is **v0.1.4**. This `main` README documents the unreleased v0.1.5, including account readiness, sealed staging, and `reclaim uv`; those commands are not in the published v0.1.4 tag. A source build from `main` prints `degu 0.1.5`, but the version alone does not identify the exact reviewed commit, so verify the commit as well as `--version`. Use the [v0.1.4 README](https://github.com/FeathBow/degu/blob/v0.1.4/README.md) with the published binary, or build the exact commit you reviewed to test the behavior below.

<details>
<summary>The same scan, redirected — copy-pasteable and pinned byte-exact by a contract test</summary>

```console
$ degu scan
22.0 MiB detected across 3 locations - 6.0 MiB ready to clean

Ready to clean - 1 location - 6.0 MiB
 source  on disk   idle  inodes  path
 pip     6.0 MiB  today       2  ~/.cache/pip

Needs review - 1 location - 12.0 MiB
Excluded by default; preview a path before including it.
 source        on disk   idle  inodes  reason                path
 huggingface  12.0 MiB  today       3  costly to regenerate  ~/.cache/huggingface/hub/models--bert--base

Not managed - 1 location - 4.0 MiB
Reported only; degu never cleans these locations.
 source  on disk   idle  inodes  reason         path
 uv      4.0 MiB  today       2  managed by uv  ~/.cache/uv

Preview the largest Needs review location (no changes): degu clean -dn --review ~/.cache/huggingface/hub/models--bert--base
Run this preview in a terminal to receive a Next command with the same path and filters.
Scan build artifacts under this project, or any parent directory: degu scan .
```

</details>


## Why degu

- **Reclaims what actually fills your quota.** Built-in sources across the ML/HPC stack — pip, conda, HuggingFace, vLLM, Triton, cargo, and more (`degu adapters` lists them all) — plus build artifacts under any project tree, found in a single read-only pass; two node-runtime diagnostics stay scan-time opt-in.
- **Safe by default.** Only verified, cheap-to-regenerate findings enter the default plan and are staged for undo.
- **Honest accounting.** `degu quota` reads authoritative filesystem usage and limits, kept separate from degu-detected storage.
- **Linux and macOS, offline, unprivileged daily use.** Scan, preview, and day-to-day cleanup never self-elevate. On the next release, `degu doctor` checks one-time account setup; `missing` has a defined administrator provisioning path, while unsafe or uncertain state requires investigation.

## Why you can trust it to delete

Deleting the wrong files is the core risk, so degu earns every deletion:

- **Corroboration, not names.** A directory becomes eligible only on structural evidence that it is regenerable — a tool's own cache marker, a build manifest — never because it is *named* `cache`, `target`, or `__pycache__`. Among locations degu discovers, anything it cannot corroborate is reported, never cleaned; degu is not a whole-disk file finder.
- **Three tiers, conservative by default.** *Ready to clean* is cheap-to-regenerate cache. *Needs review* is regenerable but costly (model downloads, compile caches) and stays excluded until you preview an exact path. *Not managed* — your data, tool-coordinated caches, checkpoints — can never enter a plan.
- **Fail closed.** If any selected location cannot be fully measured or classified, degu refuses the whole plan instead of guessing. Default cleanup is staged for undo; permanent purge is separately disclosed and confirmed.

## How degu compares

|  | degu | native cleaners (`conda clean`, `pip cache purge`, …) | kondo | ncdu / dust |
|---|---|---|---|---|
| Scope | ML/HPC cache sources + project artifacts, one pass | one tool each | project artifacts | whole-disk usage |
| Evidence before deleting | structural corroboration | n/a (the owning tool) | name and layout match | none — measures only |
| Undo | staged trash, `degu undo` | deletes in place | deletes in place | deletion is manual |
| Cross-tool view | yes | no | no | sizes only |

For datasets, checkpoints, and unknown large files, pair degu with a disk-usage viewer.

## Installation

Install the latest published release, currently **v0.1.4** (static binaries; Linux x86_64/aarch64 and macOS):

```sh
installer=$(mktemp "${TMPDIR:-/tmp}/degu-install.XXXXXX") &&
curl -fsSLo "$installer" "https://github.com/FeathBow/degu/releases/latest/download/degu-install.sh" &&
DEGU_VERSION= sh "$installer" &&
rm -f "$installer"
```

The downloaded installer is an attested release asset that carries its release version and verifies the archive's SHA-256 checksum before installing; the empty `DEGU_VERSION` keeps a value exported in your environment from overriding that pinned release.

Or through cargo — `cargo binstall degu` fetches the same release archives without compiling and fails rather than falling back to a third-party or source build, `cargo install degu --locked` builds from crates.io.

Alternatively, build from source with Git and the current stable Rust toolchain:

```sh
git clone https://github.com/FeathBow/degu.git
cd degu
cargo install --path crates/degu --locked --root "$HOME/.local"
export PATH="$HOME/.local/bin:$PATH"
```

Both `degu` and its short alias, `dg`, install into `~/.local/bin` by default. `DEGU_INSTALL_DIR` may select another binary destination when the caller already has permission. See the [v0.1.4 installation guide](https://github.com/FeathBow/degu/blob/v0.1.4/docs/installation.md) for the published release.

The remainder of this README describes `main`. A source build installs the unreleased code at the checked-out commit. Its installer and account-setup contract are documented in the [next-release installation guide](https://github.com/FeathBow/degu/blob/main/docs/installation.md).

## Quick start

For `main` and the next release, check setup once before the first mutation:

```sh
degu doctor
```

`ready` means continue. If it reports `missing`, give its path and your numeric UID (`id -u`) to your administrator; the user command never creates system authority. Unsafe or uncertain state requires investigation, not automatic repair.

After setup, the daily lifecycle remains five short commands:

```sh
degu scan            # read-only: what exists, what is safe to clean
degu clean -n        # preview the exact plan; changes nothing
degu clean           # stage Ready-to-clean findings into undoable trash
degu undo            # restore the latest clean operation
degu trash purge     # or permanently delete what you reviewed
```

Only **Ready to clean** enters the default plan. For one **Needs review** location, the scan prints a shorter `degu clean -dn --review PATH` preview; the resulting `Next` command keeps the same exact selection.

Staged data stays reversible and still counts against quota until purged; choose one recovery branch per clean operation. A confirmed mutating clean also permanently purges trash entries at least seven days old. On very large shared filesystems a full first scan can take minutes:

```sh
degu scan --budget 300s
```

A time budget returns honest lower bounds: truncated sections are flagged, totals are marked as lower bounds, and the report says how many directories went unvisited. The [user guide](https://github.com/FeathBow/degu/blob/main/docs/usage.md) and [safety model](https://github.com/FeathBow/degu/blob/main/docs/safety.md) cover recovery and permanent deletion in detail.

### Include project builds

Pass a project root when you also want build artifacts below it. The root can be a single project or a parent directory holding many projects. Scope is not remembered between commands, so pass the same root again to authorize its cleanup preview:

```sh
degu scan .
degu clean . --dry-run
```

To include a project tree in every scan, add it to `roots` in the [configuration](https://github.com/FeathBow/degu/blob/main/docs/configuration.md); `clean` still requires the root as an explicit argument.

### Check filesystem quota

```sh
degu quota
```

Validated on Linux ext4 and field-validated on a Lustre 2.15 client; other filesystems and macOS report unsupported instead of guessing. See the [user guide](https://github.com/FeathBow/degu/blob/main/docs/usage.md) for supported providers and failure behavior.

### Advanced: reclaim a uv-managed cache

`uv` caches stay **Not managed** by normal `clean`. The next release can validate and run uv 0.12.3's own irreversible ordinary prune while keeping both authority inputs explicit:

```sh
degu reclaim uv -x /absolute/path/to/uv -c /absolute/path/to/uv-cache -n
```

After reviewing the preview, rerun without `-n` and type `prune`. This bypasses degu trash and cannot be undone; degu never guesses the executable or cache root. See [Tool-native reclaim](docs/usage.md#tool-native-reclaim-advanced).

Run `degu <command> --help` or `degu man <command>` for complete command details.

## Documentation

- [Installation](https://github.com/FeathBow/degu/blob/main/docs/installation.md) covers tagged installers, release archives, and release verification.
- [User guide](https://github.com/FeathBow/degu/blob/main/docs/usage.md) covers project scans, exact-path review, JSON automation, recovery, and cache relocation.
- [Configuration](https://github.com/FeathBow/degu/blob/main/docs/configuration.md) documents every supported setting and adapter selection.
- [Operational safety](https://github.com/FeathBow/degu/blob/main/docs/safety.md) defines cleanup authority, staging, permanent deletion, and filesystem boundaries.

## License

degu is available under your choice of the [Apache License 2.0](https://github.com/FeathBow/degu/blob/main/LICENSE-APACHE) or the [MIT License](https://github.com/FeathBow/degu/blob/main/LICENSE-MIT). Contributions are dual licensed under the same terms.
