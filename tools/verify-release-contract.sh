#!/bin/sh
set -eu

. "$(dirname "$0")/release-contract.sh"

workflow=".github/workflows/release.yml"
installer="install.sh"
manifest="crates/degu/Cargo.toml"

[ "$#" -eq 0 ] || fail "Usage: $0"
[ -f "$workflow" ] || fail "Release workflow does not exist: $workflow"
[ -f "$installer" ] || fail "Install script does not exist: $installer"
[ -f "$manifest" ] || fail "Crate manifest does not exist: $manifest"

temp=$(mktemp -d "${TMPDIR:-/tmp}/degu-release-contract.XXXXXX") || fail "Could not create a temporary directory."

cleanup() {
  status=$?
  trap - EXIT
  rm -rf "$temp"
  exit "$status"
}

trap cleanup EXIT
trap 'exit 1' HUP INT TERM

for target in $targets; do
  printf '%s\n' "$target"
done > "$temp/contract-targets"

sed -n 's/^ *- target: //p' "$workflow" > "$temp/workflow-targets"
cmp -s "$temp/contract-targets" "$temp/workflow-targets" || fail "Workflow build matrix targets do not match the release contract: $workflow"

workflow_tag='${{ needs.metadata.outputs.tag }}'
{
  printf 'dist/%s\n' "$(release_archive_name "$workflow_tag" '${{ matrix.target }}')"
  printf 'dist/%s\n' "$(release_checksum_name "$workflow_tag" '${{ matrix.target }}')"
  for target in $targets; do
    printf 'dist/%s\n' "$(release_archive_name "$workflow_tag" "$target")"
    printf 'dist/%s\n' "$(release_checksum_name "$workflow_tag" "$target")"
  done
  printf 'dist/%s\n' "$(release_installer_name)"
  printf 'dist/%s\n' "$(release_installer_name)"
} > "$temp/contract-workflow-assets"

grep -F 'dist/degu-' "$workflow" | sed 's/^ *//' > "$temp/workflow-assets"
cmp -s "$temp/contract-workflow-assets" "$temp/workflow-assets" || fail "Workflow asset paths do not match the release contract: $workflow"

sed -n 's/^.*) target="\(.*\)" ;;$/\1/p' "$installer" > "$temp/installer-targets"
cmp -s "$temp/contract-targets" "$temp/installer-targets" || fail "Install script targets do not match the release contract: $installer"

installer_stem=$(release_asset_stem '${version}' '${target}')
grep -Fqx "archive=\"$(release_archive_name '${version}' '${target}')\"" "$installer" || fail "Install script archive name does not match the release contract: $installer"
grep -Fqx "checksum=\"$(release_checksum_name '${version}' '${target}')\"" "$installer" || fail "Install script checksum name does not match the release contract: $installer"
grep -Fq "\"\$tmp/$installer_stem/degu\"" "$installer" || fail "Install script degu path does not match the release contract: $installer"
grep -Fq "\"\$tmp/$installer_stem/dg\"" "$installer" || fail "Install script dg path does not match the release contract: $installer"

grep -Fqx "pkg-url = \"{ repo }/releases/download/v{ version }/$(release_archive_name 'v{ version }' '{ target }')\"" "$manifest" || fail "cargo-binstall pkg-url does not match the release contract: $manifest"
grep -Fqx "bin-dir = \"$(release_asset_stem 'v{ version }' '{ target }')/{ bin }\"" "$manifest" || fail "cargo-binstall bin-dir does not match the release contract: $manifest"
grep -Fqx 'pkg-fmt = "tgz"' "$manifest" || fail "cargo-binstall pkg-fmt does not match the release contract: $manifest"
grep -Fqx 'disabled-strategies = ["quick-install", "compile"]' "$manifest" || fail "cargo-binstall fallback strategies must stay disabled: $manifest"
