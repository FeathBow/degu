#!/bin/sh
set -eu

repo="FeathBow/degu"

fail() {
  echo "$1" >&2
  exit 1
}

command -v curl >/dev/null 2>&1 || fail "curl is required."

os=$(uname -s)
arch=$(uname -m)

case "$os" in
  Linux)
    case "$arch" in
      x86_64 | amd64) target="x86_64-unknown-linux-musl" ;;
      aarch64 | arm64) target="aarch64-unknown-linux-musl" ;;
      *) fail "Unsupported architecture: $arch" ;;
    esac
    ;;
  Darwin)
    case "$arch" in
      x86_64 | amd64) target="x86_64-apple-darwin" ;;
      aarch64 | arm64) target="aarch64-apple-darwin" ;;
      *) fail "Unsupported architecture: $arch" ;;
    esac
    ;;
  *)
    fail "Unsupported OS: $os"
    ;;
esac

version=${DEGU_VERSION:-}
if [ -z "$version" ]; then
  latest_url=$(curl -fsSLI -o /dev/null -w "%{url_effective}" "https://github.com/$repo/releases/latest")
  version=${latest_url##*/}
fi

case "$version" in
  v*) ;;
  *) fail "Release version must start with v: $version" ;;
esac

tmp=$(mktemp -d "${TMPDIR:-/tmp}/degu.XXXXXX") || fail "Could not create temporary directory."
txn=""
lock=""

# Recovery reads the transaction directory and the destinations instead of
# shell state, so a signal between any two operations cannot lie to it:
# old.<name> means restore that backup, pub.<name> without old.<name> means
# this run created the destination and must delete it, neither means the
# destination was never touched.
restore_binary() {
  name=$1
  rm -f "$install_dir/$name" || return 1
  (set -C; cat "$txn/old.$name" > "$install_dir/$name") 2>/dev/null || return 1
  cmp -s "$txn/old.$name" "$install_dir/$name" || return 1
  chmod 755 "$install_dir/$name" || return 1
  rm -f "$txn/old.$name" "$txn/pub.$name"
}

rollback() {
  ok=0
  for name in degu dg; do
    if [ -e "$txn/old.$name" ]; then
      restore_binary "$name" || ok=1
    elif [ -e "$txn/pub.$name" ]; then
      rm -f "$install_dir/$name" || ok=1
    fi
  done
  return "$ok"
}

both_committed() {
  cmp -s "$txn/new.degu" "$install_dir/degu" && cmp -s "$txn/new.dg" "$install_dir/dg" \
    && [ ! -L "$install_dir/degu" ] && [ ! -L "$install_dir/dg" ]
}

cleanup() {
  status=$?
  set +e
  trap '' HUP INT TERM
  if [ -n "$txn" ]; then
    if both_committed || rollback; then
      rm -rf "$txn"
    else
      echo "Error: rollback incomplete; backups preserved:" >&2
      ls "$txn"/old.* >&2 2>/dev/null || echo "  (no backups: fresh install, remove partial files manually)" >&2
    fi
  fi
  rm -rf "$tmp"
  [ -z "$lock" ] || rmdir "$lock" 2>/dev/null
  return "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

archive="degu-${version}-${target}.tar.gz"
checksum="degu-${version}-${target}.sha256"
base_url="https://github.com/$repo/releases/download/$version"

if [ "${DEGU_LOCAL_DIR:-}" ]; then
  cp "$DEGU_LOCAL_DIR/$archive" "$tmp/$archive" || fail "Local archive not found: $DEGU_LOCAL_DIR/$archive"
  cp "$DEGU_LOCAL_DIR/$checksum" "$tmp/$checksum" || fail "Local checksum not found: $DEGU_LOCAL_DIR/$checksum"
else
  curl -fsSLo "$tmp/$archive" "$base_url/$archive"
  curl -fsSLo "$tmp/$checksum" "$base_url/$checksum"
fi

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$tmp" && sha256sum -c "$checksum")
elif command -v shasum >/dev/null 2>&1; then
  expected=$(awk '{print $1}' "$tmp/$checksum")
  actual=$(shasum -a 256 "$tmp/$archive" | awk '{print $1}')
  [ "$expected" = "$actual" ] || fail "Checksum verification failed."
else
  fail "sha256sum or shasum is required."
fi

tar -xzf "$tmp/$archive" -C "$tmp"

if [ "${DEGU_INSTALL_DIR:-}" ]; then
  install_dir=$DEGU_INSTALL_DIR
else
  [ "${HOME:-}" ] || fail "HOME is required when DEGU_INSTALL_DIR is not set."
  install_dir="$HOME/.local/bin"
fi

mkdir -p "$install_dir"

# One installer per destination: a second concurrent run would interleave its
# own backup/publish/rollback with this one and can leave degu and dg from two
# different releases. mkdir is the portable atomic take; the lock is released
# by the exit trap, after commit or rollback finishes.
if mkdir "$install_dir/.degu-install.lock" 2>/dev/null; then
  lock="$install_dir/.degu-install.lock"
else
  fail "Another install into $install_dir appears to be in progress (lock: $install_dir/.degu-install.lock). If none is running, remove that directory and rerun."
fi

# The transaction directory shares the destination filesystem and keeps the
# staged copies until commit, so recovery always has originals to work from.
txn=$(mktemp -d "$install_dir/.degu-install.XXXXXX") || fail "Could not create transaction directory in $install_dir."

stage_binary() {
  source=$1
  name=$2
  dest="$install_dir/$name"
  [ ! -L "$dest" ] || fail "Refusing to replace symlink: $dest"
  [ ! -d "$dest" ] || fail "Refusing to replace directory: $dest"
  cp "$source" "$txn/new.$name" || fail "Could not stage $name."
  chmod 755 "$txn/new.$name" || fail "Could not stage $name."
  [ -f "$txn/new.$name" ] && [ -s "$txn/new.$name" ] && [ -x "$txn/new.$name" ] || fail "Staged $name failed verification."
}

# Publishing creates the exact leaf with O_EXCL: a destination swapped for a
# symlink or directory between the precheck and here fails instead of being
# followed. A signal can leave a partial destination; rollback deletes it and
# restores from the retained backup. A SIGKILL or power loss can still strand
# the transaction directory, which then holds every original.
publish_binary() {
  name=$1
  if [ -e "$install_dir/$name" ]; then
    mv -f "$install_dir/$name" "$txn/old.$name" || fail "Could not back up existing $name."
  fi
  : > "$txn/pub.$name"
  (set -C; cat "$txn/new.$name" > "$install_dir/$name") 2>/dev/null || fail "Could not publish $name."
  chmod 755 "$install_dir/$name" || fail "Could not publish $name."
  cmp -s "$txn/new.$name" "$install_dir/$name" || fail "Published $name failed verification."
}

stage_binary "$tmp/degu-${version}-${target}/degu" degu
stage_binary "$tmp/degu-${version}-${target}/dg" dg
publish_binary degu
publish_binary dg
both_committed || fail "Post-install verification failed."
rm -rf "$txn"
txn=""

case ":${PATH:-}:" in
  *":$install_dir:"*) ;;
  *) echo "Warning: $install_dir is not on PATH." >&2 ;;
esac

echo "Installed degu $version to $install_dir"
echo "Next: run 'degu doctor' to check account readiness (read-only; no system state is created)."
