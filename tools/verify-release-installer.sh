#!/bin/sh
set -eu

. "$(dirname "$0")/release-contract.sh"

installer_source="install.sh"

[ "$#" -eq 2 ] || fail "Usage: $0 <tag> <directory>"

tag=$1
directory=$2
validate_tag "$tag"
[ -f "$installer_source" ] || fail "Install script does not exist: $installer_source"

asset="$directory/$(release_installer_name)"
[ -f "$asset" ] && [ ! -L "$asset" ] && [ -s "$asset" ] || fail "Release installer is missing or has the wrong type: $asset"

pinned_line=$(release_installer_version_line "$tag")
grep -Fqx "$pinned_line" "$asset" || fail "Release installer does not pin the release version: $asset"

temp=$(mktemp "${TMPDIR:-/tmp}/degu-installer-verify.XXXXXX") || fail "Could not create a temporary file."

cleanup() {
  status=$?
  trap - EXIT
  rm -f "$temp"
  exit "$status"
}

trap cleanup EXIT
trap 'exit 1' HUP INT TERM

awk -v stock="$(release_installer_version_line "")" -v pinned="$pinned_line" '$0 == pinned { print stock; next } { print }' "$asset" > "$temp"
cmp -s "$temp" "$installer_source" || fail "Release installer does not match the repository install script: $asset"
