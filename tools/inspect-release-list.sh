#!/bin/sh
set -eu

. "$(dirname "$0")/release-contract.sh"

[ "$#" -eq 2 ] || fail "Usage: $0 <tag> <paginated-releases-json>"

tag=$1
releases=$2
[ -s "$releases" ] || fail "Release list response is missing or empty: $releases"

jq -cer --arg tag "$tag" '
  if type != "array" or any(.[]; type != "array") then
    error("expected an array of release-list pages")
  else
    [.[][] | select(.tag_name == $tag)]
  end
  | if length > 1 then
      error("multiple releases have the requested tag")
    elif length == 0 then
      {state: "missing", publish_needed: true, release_id: null}
    else
      .[0]
      | if ((.id | type) != "number" or .id <= 0 or (.id | floor) != .id) then
          error("release id must be a positive integer")
        elif (.draft | type) != "boolean" then
          error("release draft must be a boolean")
        elif (.prerelease | type) != "boolean" then
          error("release prerelease must be a boolean")
        elif .prerelease then
          error("release must not be a prerelease")
        elif ((.body | type) != "string" or (.body | test("[^[:space:]]") | not)) then
          error("existing release must have non-empty release notes")
        else
          {
            state: (if .draft then "draft" else "published" end),
            publish_needed: .draft,
            release_id: .id
          }
        end
    end
' "$releases"
