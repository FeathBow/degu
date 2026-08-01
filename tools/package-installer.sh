#!/bin/sh
set -eu

. "$(dirname "$0")/release-contract.sh"

installer_source="install.sh"

[ "$#" -eq 2 ] || fail "Usage: $0 <tag> <output-directory>"

tag=$1
output_dir=$2
validate_tag "$tag"
[ -f "$installer_source" ] || fail "Install script does not exist: $installer_source"

stock_line=$(release_installer_version_line "")
pinned_line=$(release_installer_version_line "$tag")
output="$output_dir/$(release_installer_name)"

stock_count=$(grep -Fcx "$stock_line" "$installer_source" || true)
[ "$stock_count" = "1" ] || fail "Install script must contain exactly one default version line: $installer_source"

mkdir -p "$output_dir"
[ ! -e "$output" ] || fail "Release installer already exists: $output"

awk -v stock="$stock_line" -v pinned="$pinned_line" '$0 == stock { print pinned; next } { print }' "$installer_source" > "$output"

grep -Fqx "$pinned_line" "$output" || fail "Release installer does not pin the release version: $output"
