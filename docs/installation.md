# Installation

## Install first, then check setup

Install the user binary with one of the methods below. Before its first mutating command, run:

```sh
degu doctor
```

This selector check is read-only. It reports the chosen authority mode and activation state and never creates or repairs state.

- **`ready`** — continue with `degu clean -n`.
- **`missing`** — run `degu init --initial` only when this account has never activated a store; otherwise investigate possible authority loss. An administrator may provision the system authority instead.
- **`split_authority` or `recovery_required`** — stop and investigate the recorded authorities and store; never choose one, reinitialize, or remove records automatically.
- **`unsafe`, `unsupported`, or `uncertain`** — stop and investigate; do not recreate, chmod, or fall back to another path.

`degu init --initial` derives the effective UID and account home from the account database and provisions only the fixed self-managed path. It accepts no UID, path, HOME, XDG, cwd, or configuration selector, rejects root, and never activates a store or repairs an existing object:

```sh
degu init --initial
degu doctor
```

The installer never runs `sudo`, reads `SUDO_UID`, or provisions another account.

## Optional administrator-hardened setup

For a numeric UID that has never activated degu, an administrator may use a separately verified binary from an administrator-owned absolute path:

```sh
sudo /usr/local/sbin/degu admin setup --uid "$(id -u USERNAME)" --initial
```

Replace `USERNAME`; do not run the user-owned copy under `~/.local/bin` with `sudo`. First stop every `degu init`, clean, undo, and purge process for that UID. The command is create-only and requires real effective UID 0. `--initial` asserts that the UID has no self candidate, no concurrent setup or lifecycle process, and no previously declared or activated authority. It is not repair, migration, or recovery authority. System setup refuses an already-visible self candidate; administrator quiescence is required to close the pre-publication cross-flavor race.

The fixed system leaf is `/var/lib/degu/store-activation/<uid>` on Linux and `/private/var/db/degu/store-activation/<uid>` on macOS. Self-managed authority uses the account-database home plus the fixed `.local/state/degu/store-activation/<uid>` suffix. Both paths require authenticated ext4/XFS/APFS namespaces, exact ownership and modes, absent ACLs, strong identity, no-follow bindings, and durable publication.

At runtime degu authenticates both candidates. Existing activation evidence wins over an empty peer; two evidence-bearing roots block as `split_authority`; an unsafe or uncertain system candidate never falls back to self. Every mutating lifecycle session retains the selected and peer locks. The first supported mutation records the exact WAL store; later XDG drift cannot select a new empty store.

`doctor ready` includes selector, activation-record, and recorded-store inspection. A lost or corrupt store reports `recovery_required`; provisioning cannot clear it. The full contract is in [Operational safety](safety.md#sealed-staging-account-readiness).

## Install with Cargo

For versions published on crates.io:

```sh
cargo install degu --locked
```

`cargo binstall degu` installs the same published version from the official release archives without compiling and fails rather than falling back to a third-party or source build.

## Build from source

Building from source works for any repository checkout, published or not, and requires Git plus the current stable Rust toolchain.

```sh
git clone https://github.com/FeathBow/degu.git &&
cd degu &&
cargo install --path crates/degu --locked --root "$HOME/.local" &&
export PATH="$HOME/.local/bin:$PATH" &&
degu --version
```

Cargo installs both `degu` and its short alias, `dg`, into `~/.local/bin` because the command sets an explicit install root.

## Install a published release

Prebuilt installation routes become usable only after the [Releases page](https://github.com/FeathBow/degu/releases) lists a published version. Choose a published tag there; draft releases and workflow artifacts are not installation sources.

Linux and macOS are supported runtime platforms. Published Linux artifacts are static musl binaries that do not require the host's glibc; macOS artifacts are native builds for Apple Silicon and Intel Macs. Such a build reads only the local account file, so on a host whose accounts come from LDAP, SSSD, or winbind degu resolves the account home by running the host's own `getent`; [safety.md](safety.md) states the bounds on that and why it selects no path the account database does not already name.

### Installer

Download the installer from the tag you intend to install, inspect it if required, and then run the local file. It verifies the archive against the SHA-256 checksum published with the same release and installs both binaries into `~/.local/bin`. This detects corruption or an archive/checksum mismatch, but it is not independent build provenance. Use the manual archive route when provenance verification is required. Do not pipe a network response directly into a shell.

Set `DEGU_INSTALL_DIR` for that invocation to install elsewhere, and add the chosen directory to `PATH` if it is not already present.

```sh
version=vX.Y.Z
installer=$(mktemp "${TMPDIR:-/tmp}/degu-install.XXXXXX") &&
curl -fsSLo "$installer" "https://github.com/FeathBow/degu/releases/download/$version/degu-install.sh" &&
DEGU_VERSION="$version" sh "$installer" &&
rm -f "$installer" &&
export PATH="$HOME/.local/bin:$PATH" &&
degu --version
```

The published `degu-install.sh` asset carries its release version as the `DEGU_VERSION` default and is covered by the same build provenance attestation as the archives; the command above still sets `DEGU_VERSION` explicitly so a value inherited from the environment cannot change which release is installed. For tags that predate the installer asset, download `install.sh` from the tag's source tree instead.

### Manual archive

Choose one of these release targets:

- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

The archive contains both binaries, shell completions, man pages, and project licenses. The steps below require an authenticated [GitHub CLI](https://cli.github.com/) and verify both the published SHA-256 checksum and the archive's build provenance before extracting or installing it.

```sh
sh -eu <<'DEGU_INSTALL' &&
version=vX.Y.Z
target=x86_64-unknown-linux-musl
archive="degu-${version}-${target}.tar.gz"
checksum="degu-${version}-${target}.sha256"
base_url="https://github.com/FeathBow/degu/releases/download/$version"
curl -fLO "$base_url/$archive"
curl -fLO "$base_url/$checksum"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c "$checksum"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 -c "$checksum"
else
  echo "sha256sum or shasum is required" >&2
  exit 1
fi
source_digest=$(gh api "repos/FeathBow/degu/commits/$version" --jq '.sha')
gh attestation verify "$archive" \
  --repo FeathBow/degu \
  --cert-identity "https://github.com/FeathBow/degu/.github/workflows/release.yml@refs/tags/$version" \
  --source-ref "refs/tags/$version" \
  --source-digest "$source_digest"
installer=$(mktemp "${TMPDIR:-/tmp}/degu-install.XXXXXX")
curl -fsSLo "$installer" "https://raw.githubusercontent.com/FeathBow/degu/$source_digest/install.sh"
DEGU_LOCAL_DIR=. DEGU_VERSION="$version" sh "$installer"
rm -f "$installer"
DEGU_INSTALL
export PATH="$HOME/.local/bin:$PATH" &&
degu --version
```

`install.sh` is the single install implementation, and pinning its download to `$source_digest` means the attestation you just checked also covers the installer you run. `DEGU_LOCAL_DIR` points it at the archive and checksum you just verified instead of downloading them again; it re-verifies the checksum and then installs transactionally: both binaries are staged and verified inside the destination directory before either is published, any failure rolls the directory back to both old or both new binaries, and if that rollback itself fails the backups are preserved in the reported transaction directory instead of being cleaned up. A SIGKILL or power loss during the final publish can still require rerunning the installer; such an interruption can also leave `.degu-install.lock` and a transaction directory behind — confirm no installer is still running before removing the stale lock, and preserve any reported transaction directory until a successful reinstall completes.

The attestation confirms that the archive was produced for that tag and commit by this repository's release workflow; it does not establish that the source code is free of defects or vulnerabilities.

The `export` commands above affect only the current shell. Add the appropriate bin directory to your shell profile to make it persistent.
