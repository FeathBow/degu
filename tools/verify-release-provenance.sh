#!/bin/sh
set -eu

. "$(dirname "$0")/release-contract.sh"

[ "$#" -eq 2 ] || fail "Usage: $0 <tag> <directory>"

tag=$1
directory=$2
[ -d "$directory" ] || fail "Release asset directory does not exist: $directory"
[ -n "${GITHUB_REPOSITORY:-}" ] || fail "GITHUB_REPOSITORY is required."
[ -n "${GITHUB_REF:-}" ] || fail "GITHUB_REF is required."
[ -n "${GITHUB_SHA:-}" ] || fail "GITHUB_SHA is required."
[ -n "${GITHUB_SERVER_URL:-}" ] || fail "GITHUB_SERVER_URL is required."
[ -n "${GH_TOKEN:-}" ] || fail "GH_TOKEN is required."
[ "$GITHUB_REF" = "refs/tags/$tag" ] || fail "Release ref $GITHUB_REF does not match tag $tag."
case "$GITHUB_SHA" in
  *[!0-9a-f]* | '') fail "GITHUB_SHA is not a lowercase hexadecimal object ID: $GITHUB_SHA" ;;
esac

for target in $targets; do
  archive="$directory/$(release_archive_name "$tag" "$target")"
  [ -f "$archive" ] && [ ! -L "$archive" ] || fail "Release archive is missing or has the wrong type: $archive"
  gh attestation verify "$archive" \
    --repo "$GITHUB_REPOSITORY" \
    --cert-identity "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/.github/workflows/release.yml@$GITHUB_REF" \
    --source-ref "$GITHUB_REF" \
    --source-digest "$GITHUB_SHA"
done

installer="$directory/$(release_installer_name)"
[ -f "$installer" ] && [ ! -L "$installer" ] || fail "Release installer is missing or has the wrong type: $installer"
gh attestation verify "$installer" \
  --repo "$GITHUB_REPOSITORY" \
  --cert-identity "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/.github/workflows/release.yml@$GITHUB_REF" \
  --source-ref "$GITHUB_REF" \
  --source-digest "$GITHUB_SHA"
