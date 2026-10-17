#!/bin/sh
# Reconciles every SHA-pinned action in .github/workflows against the ref its
# comment names. A trailing `# vX.Y.Z` must equal that released version, so a
# release tag that moved fails. A `# rolling-ref: <ref>` on the line above
# names a ref upstream advances on every change, so drift there is reported
# with how far behind the pin is and whether any of those commits touched
# action.yml. A pin with neither comment fails: a bare SHA names nothing to
# reconcile against.
set -eu

fail() {
  printf '%s\n' "$*" >&2
  exit 1
}

command -v gh >/dev/null 2>&1 || fail "gh is required"

workflows_dir=${1:-.github/workflows}
[ -d "$workflows_dir" ] || fail "No such directory: $workflows_dir"

pins=$(mktemp)
report=$(mktemp)
trap 'rm -f "$pins" "$report"' EXIT INT TERM

# One row per distinct pin, with the step count and the first site. Refs that
# are not SHA pins are left to zizmor's unpinned-uses audit.
awk '
  BEGIN { OFS = "\t"; rolling = "" }
  /^[[:space:]]*#[[:space:]]*rolling-ref:[[:space:]]/ {
    rolling = $0
    sub(/^[[:space:]]*#[[:space:]]*rolling-ref:[[:space:]]*/, "", rolling)
    sub(/[[:space:]].*$/, "", rolling)
    next
  }
  index($0, "uses:") && index($0, "@") {
    action = $0
    sub(/^.*uses:[[:space:]]*/, "", action)
    comment = ""
    if (index(action, "#")) {
      comment = action
      sub(/^[^#]*#[[:space:]]*/, "", comment)
      sub(/[[:space:]].*$/, "", comment)
      sub(/[[:space:]]*#.*$/, "", action)
    }
    sub(/[[:space:]]*$/, "", action)
    at = index(action, "@")
    repo = substr(action, 1, at - 1)
    sha = substr(action, at + 1)
    if (length(sha) != 40 || sha !~ /^[0-9a-f]+$/) { rolling = ""; next }
    kind = (comment != "") ? "versioned" : (rolling != "" ? "rolling" : "bare")
    ref = (comment != "") ? comment : (rolling != "" ? rolling : "-")
    key = kind OFS repo OFS ref OFS sha
    uses[key]++
    if (!(key in first)) { first[key] = FILENAME ":" FNR; order[++n] = key }
    rolling = ""
    next
  }
  { rolling = "" }
  END { for (i = 1; i <= n; i++) print order[i], uses[order[i]], first[order[i]] }
' "$workflows_dir"/*.yml > "$pins"

[ -s "$pins" ] || fail "No SHA-pinned actions found under $workflows_dir"

tab=$(printf '\t')
short() { printf '%.12s' "$1"; }
total_uses=0
moved=0
unresolved=0
unexplained=0
drifted=0
printf '| action | ref | uses | pinned | ref now | verdict |\n|---|---|--:|---|---|---|\n' > "$report"

while IFS="$tab" read -r kind repo ref pin uses where; do
  total_uses=$((total_uses + uses))
  if [ "$kind" = "bare" ]; then
    unexplained=$((unexplained + 1))
    printf '| `%s` | none | %s | `%s` | | **bare pin** (%s) |\n' \
      "$repo" "$uses" "$(short "$pin")" "$where" >> "$report"
    continue
  fi
  now=$(gh api "repos/$repo/commits/$ref" -q '.sha' 2>/dev/null || true)
  # gh prints its error body on stdout, so an answer counts only once it has
  # the shape of a commit id. Taken on faith it reads as a mismatch against a
  # nonsense sha, which is the one verdict here that must not be guessed.
  printf '%s' "$now" | grep -qE '^[0-9a-f]{40}$' || now=""
  if [ -z "$now" ]; then
    unresolved=$((unresolved + 1))
    printf '| `%s` | `%s` | %s | `%s` | | **ref does not resolve** (%s) |\n' \
      "$repo" "$ref" "$uses" "$(short "$pin")" "$where" >> "$report"
    continue
  fi
  if [ "$now" = "$pin" ]; then
    printf '| `%s` | `%s` | %s | `%s` | `%s` | matches |\n' \
      "$repo" "$ref" "$uses" "$(short "$pin")" "$(short "$now")" >> "$report"
    continue
  fi
  if [ "$kind" = "versioned" ]; then
    moved=$((moved + 1))
    printf '| `%s` | `%s` | %s | `%s` | `%s` | **release ref moved** (%s) |\n' \
      "$repo" "$ref" "$uses" "$(short "$pin")" "$(short "$now")" "$where" >> "$report"
    continue
  fi
  drifted=$((drifted + 1))
  span=$(gh api "repos/$repo/compare/$pin...$now" \
    -q '[(.commits | length), ([.files[].filename | select(test("^action[.]ya?ml$"))] | length)] | @tsv' \
    2>/dev/null || printf '?\t?')
  behind=${span%%"$tab"*}
  runtime=${span##*"$tab"}
  printf '| `%s` | `%s` (rolling) | %s | `%s` | `%s` | %s commit(s) behind, %s touching `action.yml` -- [compare](https://github.com/%s/compare/%s...%s) |\n' \
    "$repo" "$ref" "$uses" "$(short "$pin")" "$(short "$now")" \
    "$behind" "$runtime" "$repo" "$pin" "$now" >> "$report"
done < "$pins"

{
  printf '## Pinned actions\n\n'
  cat "$report"
  printf '\n%s distinct pin(s) over %s step(s): %s drifted on a rolling ref.\n' \
    "$(wc -l < "$pins" | tr -d ' ')" "$total_uses" "$drifted"
} | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"

[ "$unexplained" -eq 0 ] || fail "$unexplained pinned action(s) carry no version or rolling-ref comment"
[ "$unresolved" -eq 0 ] || fail "$unresolved pinned action(s) name a ref that does not resolve"
[ "$moved" -eq 0 ] || fail "$moved pinned action(s) no longer match the release ref they name"
