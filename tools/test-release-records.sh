#!/bin/sh
set -eu

. "$(dirname "$0")/release-contract.sh"

expect_list_failure() {
  expected=$1
  if ./tools/inspect-release-list.sh "$tag" "$pages" > /dev/null 2> "$error_log"; then
    fail "Release list inspection unexpectedly succeeded."
  fi
  grep -F "$expected" "$error_log" > /dev/null || { cat "$error_log" >&2; fail "Release list inspection failed at the wrong guard."; }
}

expect_record_failure() {
  expected=$1
  if ./tools/inspect-release-record.sh "$tag" "$record" "$assets" > /dev/null 2> "$error_log"; then
    fail "Release record inspection unexpectedly succeeded."
  fi
  grep -F "$expected" "$error_log" > /dev/null || { cat "$error_log" >&2; fail "Release record inspection failed at the wrong guard."; }
}

write_record() {
  draft=$1
  first_digest=$2
  include_second=$3
  jq -n --arg tag "$tag" --arg first_digest "$first_digest" --arg second_digest "$second_digest" --argjson draft "$draft" --argjson first_size "$first_size" --argjson second_size "$second_size" --argjson include_second "$include_second" '
    {
      id: 42,
      tag_name: $tag,
      body: "Release notes",
      draft: $draft,
      prerelease: false,
      assets: (
        [{id: 101, name: "alpha.tar.gz", state: "uploaded", size: $first_size, digest: $first_digest}]
        + if $include_second then [{id: 102, name: "beta.sha256", state: "uploaded", size: $second_size, digest: $second_digest}] else [] end
      )
    }
  ' > "$record"
}

work=$(mktemp -d "${TMPDIR:-/tmp}/degu-release-record-test.XXXXXX") || fail "Could not create a temporary directory."

cleanup() {
  status=$?
  trap - EXIT
  rm -rf "$work"
  exit "$status"
}

trap cleanup EXIT
trap 'exit 1' HUP INT TERM
tag=v1.2.3
pages="$work/pages.json"
record="$work/release.json"
result="$work/result.json"
error_log="$work/error.log"
assets="$work/assets"
mkdir "$assets"
printf 'archive\n' > "$assets/alpha.tar.gz"
printf 'checksum\n' > "$assets/beta.sha256"
first_size=$(wc -c < "$assets/alpha.tar.gz" | tr -d '[:space:]')
second_size=$(wc -c < "$assets/beta.sha256" | tr -d '[:space:]')
first_digest="sha256:$(calculate_sha256 "$assets/alpha.tar.gz")"
second_digest="sha256:$(calculate_sha256 "$assets/beta.sha256")"

jq -n '[[]]' > "$pages"
./tools/inspect-release-list.sh "$tag" "$pages" > "$result"
jq -e '.state == "missing" and .publish_needed == true and .release_id == null' "$result" > /dev/null

jq -n --arg tag "$tag" '[[{id: 8, tag_name: "v0.9.0"}], [{id: 42, tag_name: $tag, body: "Kept notes", draft: true, prerelease: false}]]' > "$pages"
./tools/inspect-release-list.sh "$tag" "$pages" > "$result"
jq -e '.state == "draft" and .publish_needed == true and .release_id == 42 and (has("generate_notes") | not)' "$result" > /dev/null

jq -n --arg tag "$tag" '[[{id: 42, tag_name: $tag, body: "Notes", draft: false, prerelease: false}]]' > "$pages"
./tools/inspect-release-list.sh "$tag" "$pages" > "$result"
jq -e '.state == "published" and .publish_needed == false and .release_id == 42' "$result" > /dev/null

jq -n --arg tag "$tag" '[[{id: 41, tag_name: $tag}, {id: 42, tag_name: $tag}]]' > "$pages"
expect_list_failure "multiple releases have the requested tag"

jq -n --arg tag "$tag" '[[{id: 42, tag_name: $tag, body: " ", draft: true, prerelease: false}]]' > "$pages"
expect_list_failure "existing release must have non-empty release notes"

write_record true "$first_digest" false
./tools/inspect-release-record.sh "$tag" "$record" "$assets" > "$result"
jq -e '.id == 42 and .draft == true and .missing == ["beta.sha256"] and (.replace | length) == 0 and (.publish_payload | keys) == ["draft", "make_latest", "prerelease"]' "$result" > /dev/null

write_record false "$first_digest" true
./tools/inspect-release-record.sh "$tag" "$record" "$assets" > "$result"
jq -e '.draft == false and (.missing | length) == 0 and (.replace | length) == 0 and .publish_payload.draft == false' "$result" > /dev/null

write_record true "sha256:0000000000000000000000000000000000000000000000000000000000000000" true
./tools/inspect-release-record.sh "$tag" "$record" "$assets" > "$result"
jq -e '.replace == [{"id": 101, "name": "alpha.tar.gz"}]' "$result" > /dev/null

write_record true "$first_digest" true
jq '.assets[0] |= (.state = "starter" | .size = 0 | .digest = null)' "$record" > "$work/starter-record.json"
./tools/inspect-release-record.sh "$tag" "$work/starter-record.json" "$assets" > "$result"
jq -e '.replace == [{"id": 101, "name": "alpha.tar.gz"}]' "$result" > /dev/null

write_record false "$first_digest" true
jq '.assets[0] |= (.state = "starter" | .size = 0 | .digest = null)' "$record" > "$work/published-starter-record.json"
record="$work/published-starter-record.json"
expect_record_failure "published release assets must be uploaded"
record="$work/release.json"

write_record true "$first_digest" true
jq '.assets[0] |= (.state = "open" | .digest = null)' "$record" > "$work/open-record.json"
./tools/inspect-release-record.sh "$tag" "$work/open-record.json" "$assets" > "$result"
jq -e '.replace == [{"id": 101, "name": "alpha.tar.gz"}]' "$result" > /dev/null

write_record false "$first_digest" true
jq '.assets[0] |= (.state = "open" | .digest = null)' "$record" > "$work/published-open-record.json"
record="$work/published-open-record.json"
expect_record_failure "published release assets must be uploaded"
record="$work/release.json"

write_record true "$first_digest" true
jq '.assets[0] |= (.state = "mystery")' "$record" > "$work/unknown-state-record.json"
record="$work/unknown-state-record.json"
expect_record_failure "release contains an asset with an unknown state"
record="$work/release.json"

write_record true "$first_digest" true
jq '.assets += [{id: 103, name: "unexpected", state: "uploaded", size: 1, digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}]' "$record" > "$work/record-with-extra.json"
record="$work/record-with-extra.json"
expect_record_failure "release contains an unexpected asset"
