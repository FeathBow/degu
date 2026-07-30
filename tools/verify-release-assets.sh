#!/bin/sh
set -eu
set -f

. "$(dirname "$0")/release-contract.sh"

require_nonempty() {
  [ -s "$1" ] || fail "Required file is missing or empty: $1"
}

require_regular_nonempty() {
  [ -f "$1" ] && [ ! -L "$1" ] && [ -s "$1" ] || fail "Required archive member is not a nonempty regular file: $1"
}

write_expected_assets() {
  asset_tag=$1
  asset_scope=$2

  if [ "$asset_scope" = "all" ]; then
    for asset_target in $targets; do
      printf '%s\n' "$(release_archive_name "$asset_tag" "$asset_target")"
      printf '%s\n' "$(release_checksum_name "$asset_tag" "$asset_target")"
    done
    return
  fi

  printf '%s\n' "$(release_archive_name "$asset_tag" "$asset_scope")"
  printf '%s\n' "$(release_checksum_name "$asset_tag" "$asset_scope")"
}

write_expected_entries() {
  entry_root=$1

  printf '%s\t%s\n' \
    "$entry_root/" d \
    "$entry_root/LICENSE-APACHE" - \
    "$entry_root/LICENSE-MIT" - \
    "$entry_root/completions/" d
  for completion in $completion_files; do
    printf '%s\t%s\n' "$entry_root/completions/$completion" -
  done
  printf '%s\t%s\n' \
    "$entry_root/degu" - \
    "$entry_root/dg" - \
    "$entry_root/man/" d
  for page in $man_pages; do
    printf '%s\t%s\n' "$entry_root/man/$page" -
  done
}

verify_completion_registration() {
  member_root=$1
  command_name=$2

  grep -F "complete -F _$command_name -o bashdefault -o default $command_name" "$member_root/completions/$command_name.bash" > /dev/null || fail "Completion script does not register $command_name for bash"
  grep -Fx "#compdef $command_name" "$member_root/completions/$command_name.zsh" > /dev/null || fail "Completion script does not register $command_name for zsh"
  grep -F "complete -c $command_name " "$member_root/completions/$command_name.fish" > /dev/null || fail "Completion script does not register $command_name for fish"
}

verify_checksum() {
  checksum_archive=$1
  checksum_path=$2
  require_nonempty "$checksum_archive"
  require_nonempty "$checksum_path"

  line_count=$(wc -l < "$checksum_path" | tr -d '[:space:]')
  [ "$line_count" = "1" ] || fail "Checksum must contain exactly one line: $checksum_path"
  IFS=' ' read -r expected_digest referenced_name trailing < "$checksum_path" || fail "Could not read checksum: $checksum_path"
  [ -n "$expected_digest" ] && [ -n "$referenced_name" ] && [ -z "$trailing" ] || fail "Checksum must contain one digest and one filename: $checksum_path"
  case "$expected_digest" in
    *[!0-9a-f]* | '') fail "Checksum digest is not lowercase hexadecimal: $checksum_path" ;;
  esac
  [ "${#expected_digest}" -eq "$SHA256_HEX_LENGTH" ] || fail "Checksum digest must be $SHA256_HEX_LENGTH hexadecimal characters: $checksum_path"
  [ "$referenced_name" = "$(basename "$checksum_archive")" ] || fail "Checksum references the wrong archive: $checksum_path"
  [ "$(calculate_sha256 "$checksum_archive")" = "$expected_digest" ] || fail "Checksum verification failed: $checksum_archive"
}

verify_extracted_members() {
  member_root=$1
  member_archive=$2

  for member_directory in "$member_root" "$member_root/completions" "$member_root/man"; do
    [ -d "$member_directory" ] && [ ! -L "$member_directory" ] || fail "Required archive directory has the wrong type: $member_directory"
  done
  for member in degu dg LICENSE-APACHE LICENSE-MIT; do
    require_regular_nonempty "$member_root/$member"
  done
  for completion in $completion_files; do
    require_regular_nonempty "$member_root/completions/$completion"
  done
  for page in $man_pages; do
    require_regular_nonempty "$member_root/man/$page"
  done
  for command_name in degu dg; do
    verify_completion_registration "$member_root" "$command_name"
  done
  [ -x "$member_root/degu" ] || fail "Archived degu binary is not executable: $member_archive"
  [ -x "$member_root/dg" ] || fail "Archived dg binary is not executable: $member_archive"
}

reject_macos_metadata() {
  member_names=$1
  member_archive=$2

  if grep -Eq '(^|/)\._|(^|/)\.DS_Store($|/)' "$member_names"; then
    fail "Archive contains AppleDouble or macOS metadata; check COPYFILE_DISABLE/--no-xattrs: $member_archive"
  fi
}

verify_archive() {
  archive_tag=$1
  archive_target=$2
  archive_directory=$3
  archive_root=$(release_asset_stem "$archive_tag" "$archive_target")
  archive_path="$archive_directory/$(release_archive_name "$archive_tag" "$archive_target")"
  checksum_path="$archive_directory/$(release_checksum_name "$archive_tag" "$archive_target")"

  verify_checksum "$archive_path" "$checksum_path"
  names="$temp/names-$archive_target"
  types="$temp/types-$archive_target"
  expected_entries="$temp/expected-entries-$archive_target"
  actual_entries="$temp/actual-entries-$archive_target"
  write_expected_entries "$archive_root" | LC_ALL=C sort > "$expected_entries"
  tar -tzf "$archive_path" > "$names"
  reject_macos_metadata "$names" "$archive_path"
  tar -tvzf "$archive_path" | awk '{print substr($1, 1, 1)}' > "$types"
  paste "$names" "$types" | LC_ALL=C sort > "$actual_entries"
  cmp -s "$expected_entries" "$actual_entries" || fail "Archive entries do not match the release contract: $archive_path"

  extracted="$temp/extracted-$archive_target"
  mkdir -p "$extracted"
  tar -xzf "$archive_path" -C "$extracted"
  extracted_root="$extracted/$archive_root"

  verify_extracted_members "$extracted_root" "$archive_path"
  cmp -s "$extracted_root/degu" "$extracted_root/dg" || fail "Archived degu and dg binaries differ: $archive_path"
  cmp -s "LICENSE-APACHE" "$extracted_root/LICENSE-APACHE" || fail "Archived Apache license differs from the repository copy: $archive_path"
  cmp -s "LICENSE-MIT" "$extracted_root/LICENSE-MIT" || fail "Archived MIT license differs from the repository copy: $archive_path"
}

[ "$#" -eq 3 ] || fail "Usage: $0 <tag> <directory> <target|all>"

tag=$1
directory=$2
scope=$3
validate_tag "$tag"
[ -d "$directory" ] || fail "Release asset directory does not exist: $directory"

[ "$scope" = "all" ] || release_target_supported "$scope" || fail "Unsupported release verification scope: $scope"

temp=$(mktemp -d "${TMPDIR:-/tmp}/degu-release-verify.XXXXXX") || fail "Could not create a temporary directory."

cleanup() {
  status=$?
  trap - EXIT
  rm -rf "$temp"
  exit "$status"
}

trap cleanup EXIT
trap 'exit 1' HUP INT TERM
write_expected_assets "$tag" "$scope" | LC_ALL=C sort > "$temp/expected-assets"
(cd "$directory" && find . ! -name . -prune -print | sed 's#^\./##' | LC_ALL=C sort) > "$temp/actual-assets"
cmp -s "$temp/expected-assets" "$temp/actual-assets" || fail "Release asset set does not match the expected files: $directory"

if [ "$scope" = "all" ]; then
  for target in $targets; do
    verify_archive "$tag" "$target" "$directory"
  done
else
  verify_archive "$tag" "$scope" "$directory"
fi
