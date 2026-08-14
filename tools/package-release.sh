#!/bin/sh
set -eu

. "$(dirname "$0")/release-contract.sh"

require_nonempty() {
  [ -s "$1" ] || fail "Required file is missing or empty: $1"
}

[ "$#" -eq 3 ] || fail "Usage: $0 <tag> <target> <output-directory>"

tag=$1
target=$2
output_dir=$3
validate_tag "$tag"
release_target_supported "$target" || fail "Unsupported release target: $target"

version=${tag#v}
binary="target/$target/release/degu"
name=$(release_asset_stem "$tag" "$target")
archive=$(release_archive_name "$tag" "$target")
checksum=$(release_checksum_name "$tag" "$target")

[ -x "$binary" ] || fail "Release binary is missing or not executable: $binary"
[ "$("$binary" --version)" = "degu $version" ] || fail "Release tag $tag does not match the binary version."
require_nonempty "LICENSE-APACHE"
require_nonempty "LICENSE-MIT"

mkdir -p "$output_dir"
[ ! -e "$output_dir/$archive" ] || fail "Release archive already exists: $output_dir/$archive"
[ ! -e "$output_dir/$checksum" ] || fail "Release checksum already exists: $output_dir/$checksum"

work=$(mktemp -d "${TMPDIR:-/tmp}/degu-release.XXXXXX") || fail "Could not create a temporary directory."
finalized=false

cleanup() {
  status=$?
  trap - EXIT
  rm -rf "$work"
  if [ "$finalized" != "true" ]; then
    rm -f "$output_dir/$archive" "$output_dir/$checksum"
  fi
  exit "$status"
}

trap cleanup EXIT
trap 'exit 1' HUP INT TERM
root="$work/$name"

write_man_page() {
  page=$1
  shift
  "$root/degu" man "$@" > "$root/man/$page"
}

mkdir -p "$root/completions" "$root/man"
cp "$binary" "$root/degu"
# A hardlink would be smaller, but cargo-binstall's extractor silently skips
# link entries, so dg must be an independent regular file in the tar.
cp "$root/degu" "$root/dg"
cp "LICENSE-APACHE" "LICENSE-MIT" "$root/"
for command_name in degu dg; do
  for shell in bash zsh fish; do
    "$root/$command_name" completions "$shell" > "$root/completions/$command_name.$shell"
  done
done
write_man_page degu.1
write_man_page degu-doctor.1 doctor
write_man_page degu-admin.1 admin
write_man_page degu-admin-setup.1 admin setup
write_man_page degu-quota.1 quota
write_man_page degu-scan.1 scan
write_man_page degu-clean.1 clean
write_man_page degu-undo.1 undo
write_man_page degu-trash.1 trash
write_man_page degu-trash-list.1 trash list
write_man_page degu-trash-purge.1 trash purge
write_man_page degu-reclaim.1 reclaim
write_man_page degu-reclaim-uv.1 reclaim uv
write_man_page degu-relocate.1 relocate
write_man_page degu-ops.1 ops
write_man_page degu-adapters.1 adapters
write_man_page degu-completions.1 completions
write_man_page degu-man.1 man

for file in "$root/degu" "$root/dg" "$root/LICENSE-APACHE" "$root/LICENSE-MIT"; do
  require_nonempty "$file"
done
for completion in $completion_files; do
  require_nonempty "$root/completions/$completion"
done
for page in $man_pages; do
  require_nonempty "$root/man/$page"
done

COPYFILE_DISABLE=1 tar --no-xattrs -C "$work" -czf "$work/$archive" "$name"
write_release_checksum "$work" "$archive" "$checksum"

require_nonempty "$work/$archive"
require_nonempty "$work/$checksum"
mv "$work/$archive" "$output_dir/$archive"
mv "$work/$checksum" "$output_dir/$checksum"
finalized=true
