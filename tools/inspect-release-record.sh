#!/bin/sh
set -eu
set -f

. "$(dirname "$0")/release-contract.sh"

write_local_manifest() {
  manifest_directory=$1
  manifest_output=$2
  names="${manifest_output}.names"
  (cd "$manifest_directory" && find . ! -name . -prune -print | sed 's#^\./##' | LC_ALL=C sort) > "$names"
  : > "$manifest_output"
  while IFS= read -r name; do
    path="$manifest_directory/$name"
    [ -f "$path" ] && [ ! -L "$path" ] || fail "Local release asset is not a regular file: $path"
    size=$(wc -c < "$path" | tr -d '[:space:]')
    digest=$(calculate_sha256 "$path")
    [ "${#digest}" -eq "$SHA256_HEX_LENGTH" ] || fail "Could not calculate SHA-256 for $path"
    printf '%s\t%s\tsha256:%s\n' "$name" "$size" "$digest" >> "$manifest_output"
  done < "$names"
}

[ "$#" -eq 3 ] || fail "Usage: $0 <tag> <release-json> <asset-directory>"

tag=$1
release=$2
directory=$3
[ -s "$release" ] || fail "Release response is missing or empty: $release"
[ -d "$directory" ] || fail "Release asset directory does not exist: $directory"

temp=$(mktemp -d "${TMPDIR:-/tmp}/degu-release-record.XXXXXX") || fail "Could not create a temporary directory."

cleanup() {
  status=$?
  trap - EXIT
  rm -rf "$temp"
  exit "$status"
}

trap cleanup EXIT
trap 'exit 1' HUP INT TERM
manifest="$temp/local-manifest"
write_local_manifest "$directory" "$manifest"
[ -s "$manifest" ] || fail "Local release asset directory is empty: $directory"

jq -Rn '[inputs | split("\t") | {name: .[0], size: (.[1] | tonumber), digest: .[2]}]' < "$manifest" > "$temp/local.json"

jq -e --arg tag "$tag" '
  if ((.id | type) != "number" or .id <= 0 or (.id | floor) != .id) then
      error("release id must be a positive integer")
    elif .tag_name != $tag then
      error("release tag does not match the requested tag")
    elif (.draft | type) != "boolean" then
      error("release draft must be a boolean")
    elif .prerelease != false then
      error("release must not be a prerelease")
    elif ((.body | type) != "string" or (.body | test("[^[:space:]]") | not)) then
      error("release must have non-empty release notes")
    elif (.assets | type) != "array" then
      error("release assets must be an array")
    else
      true
    end
' "$release" > /dev/null

jq -e --slurpfile local "$temp/local.json" '
  $local[0] as $expected
  | if any(.assets[]; (.name | type) != "string" or (.size | type) != "number" or .size < 0 or (.size | floor) != .size or ((.digest | type) != "string" and (.digest | type) != "null")) then
      error("release asset metadata has invalid types")
    elif any(.assets[]; ((.id | type) != "number" or .id <= 0 or (.id | floor) != .id)) then
      error("asset ids must be positive integers")
    elif ([.assets[].id] | length) != ([.assets[].id] | unique | length) then
      error("release contains duplicate asset ids")
    elif ([.assets[].name] | length) != ([.assets[].name] | unique | length) then
      error("release contains duplicate asset names")
    elif any(.assets[]; .state != "uploaded" and .state != "open" and .state != "starter") then
      error("release contains an asset with an unknown state")
    elif any(.assets[]; .state == "uploaded" and (.digest | type) != "string") then
      error("uploaded release assets must have a digest")
    elif .draft == false and any(.assets[]; .state != "uploaded") then
      error("published release assets must be uploaded")
    elif any(.assets[]; . as $actual | all($expected[]; .name != $actual.name)) then
      error("release contains an unexpected asset")
    else
      true
    end
' "$release" > /dev/null

jq -cer --slurpfile local "$temp/local.json" '
  . as $release
  | $local[0] as $expected
  | {
      id: .id,
      draft: .draft,
      assets: [.assets[] | {id, name, state}],
      missing: [$expected[] as $wanted | select(all($release.assets[]; .name != $wanted.name)) | $wanted.name],
      replace: [.assets[] | . as $actual | select(.state != "uploaded" or all($expected[]; (.name != $actual.name or .size != $actual.size or .digest != $actual.digest))) | {id, name}],
      publish_payload: {draft: false, prerelease: false, make_latest: "legacy"}
    }
' "$release"
