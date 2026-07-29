#!/bin/sh
set -eu

. "$(dirname "$0")/release-contract.sh"

[ "$#" -eq 2 ] || fail "Usage: $0 <tag> <expected-commit>"

tag=$1
expected_commit=$2
validate_tag "$tag"
[ -n "${GITHUB_REPOSITORY:-}" ] || fail "GITHUB_REPOSITORY is required."
[ -n "${GH_TOKEN:-}" ] || fail "GH_TOKEN is required."
case "$expected_commit" in
  *[!0-9a-f]* | '') fail "Expected commit is not a lowercase hexadecimal object ID: $expected_commit" ;;
esac

object=$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/tags/$tag")
object_type=$(printf '%s\n' "$object" | jq -er '.object.type')
object_sha=$(printf '%s\n' "$object" | jq -er '.object.sha')

while [ "$object_type" = "tag" ]; do
  object=$(gh api "repos/${GITHUB_REPOSITORY}/git/tags/$object_sha")
  object_type=$(printf '%s\n' "$object" | jq -er '.object.type')
  object_sha=$(printf '%s\n' "$object" | jq -er '.object.sha')
done

[ "$object_type" = "commit" ] || fail "Release tag resolves to unsupported object type $object_type: $tag"
[ "$object_sha" = "$expected_commit" ] || fail "Release tag $tag resolves to $object_sha, expected $expected_commit."

comparison=$(gh api "repos/${GITHUB_REPOSITORY}/compare/${expected_commit}...main")
merge_base=$(printf '%s\n' "$comparison" | jq -er '.merge_base_commit.sha | if (type == "string" and test("^[0-9a-f]+$")) then . else error("expected a lowercase hexadecimal merge base") end')
[ "$merge_base" = "$expected_commit" ] || fail "Release commit $expected_commit is not reachable from main."
