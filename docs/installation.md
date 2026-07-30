# Installation

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

Linux and macOS are supported runtime platforms. Published Linux artifacts are static musl binaries that do not require the host's glibc; macOS artifacts are native builds for Apple Silicon and Intel Macs.

### Installer

Download the installer from the tag you intend to install, inspect it if required, and then run the local file. It verifies the archive against the SHA-256 checksum published with the same release and installs both binaries into `~/.local/bin`. This detects corruption or an archive/checksum mismatch, but it is not independent build provenance. Use the manual archive route when provenance verification is required. Do not pipe a network response directly into a shell.

Set `DEGU_INSTALL_DIR` for that invocation to install elsewhere, and add the chosen directory to `PATH` if it is not already present.

```sh
version=vX.Y.Z
installer=$(mktemp "${TMPDIR:-/tmp}/degu-install.XXXXXX") &&
curl -fsSLo "$installer" "https://raw.githubusercontent.com/FeathBow/degu/$version/install.sh" &&
DEGU_VERSION="$version" sh "$installer" &&
rm -f "$installer" &&
export PATH="$HOME/.local/bin:$PATH" &&
degu --version
```

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
