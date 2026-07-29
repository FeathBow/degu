#!/bin/sh
set -eu

. "$(dirname "$0")/release-contract.sh"

expect_verification_failure() {
  failure_directory=$1
  expected_message=$2
  failure_log="$work/verification-error"

  if ./tools/verify-release-assets.sh "$tag" "$failure_directory" "$target" > /dev/null 2> "$failure_log"; then
    fail "Release verification unexpectedly succeeded: $failure_directory"
  fi
  if ! grep -F "$expected_message" "$failure_log" > /dev/null; then
    cat "$failure_log" >&2
    fail "Release verification failed at the wrong guard: $failure_directory"
  fi
}

expect_packaging_failure() {
  invalid_tag=$1
  expected_message=$2
  failure_directory=$3
  failure_log="$work/packaging-error"

  if ./tools/package-release.sh "$invalid_tag" "$target" "$failure_directory" > /dev/null 2> "$failure_log"; then
    fail "Release packaging unexpectedly succeeded: $invalid_tag"
  fi
  if ! grep -F "$expected_message" "$failure_log" > /dev/null; then
    cat "$failure_log" >&2
    fail "Release packaging failed at the wrong guard: $invalid_tag"
  fi
  [ ! -e "$failure_directory" ] || fail "Failed release packaging left output behind: $failure_directory"
}

repack_case() {
  case_directory=$1
  extracted=$2
  appledouble_source=${3-}
  rm "$case_directory/$archive" "$case_directory/$checksum"
  if [ -z "$appledouble_source" ]; then
    tar -C "$extracted" -czf "$case_directory/$archive" "$release_root"
  elif tar --version 2>/dev/null | grep -Fq bsdtar; then
    tar -s "#$release_root/$appledouble_source#$release_root/._degu#" -C "$extracted" -czf "$case_directory/$archive" "$release_root"
  else
    tar --transform "s#$release_root/$appledouble_source#$release_root/._degu#" -C "$extracted" -czf "$case_directory/$archive" "$release_root"
  fi
  write_release_checksum "$case_directory" "$archive" "$checksum"
}

test_missing_asset() {
  missing_asset=$1
  case_directory="$work/missing-$(basename "$missing_asset")"
  mkdir -p "$case_directory"
  cp -R "$valid/." "$case_directory/"
  rm "$case_directory/$missing_asset"
  expect_verification_failure "$case_directory" "Release asset set does not match"
}

test_missing_member() {
  missing_member=$1
  case_name=$(printf '%s' "$missing_member" | tr '/' '-')
  case_directory="$work/missing-member-$case_name"
  extracted="$work/extracted-missing-$case_name"
  mkdir -p "$case_directory" "$extracted"
  cp -R "$valid/." "$case_directory/"
  tar -xzf "$case_directory/$archive" -C "$extracted"
  rm "$extracted/$release_root/$missing_member"
  repack_case "$case_directory" "$extracted"
  expect_verification_failure "$case_directory" "Archive entries do not match"
}

apply_member_mutation() {
  mutation=$1
  member_path=$2
  extracted_root=$3

  case "$mutation" in
    symlink) rm "$member_path" && ln -s "LICENSE-MIT" "$member_path" ;;
    empty | appledouble) : > "$member_path" ;;
    nonexec) chmod 0644 "$extracted_root/degu" "$extracted_root/dg" ;;
    independent) cp "$member_path" "$member_path.copy" && rm "$member_path" && mv "$member_path.copy" "$member_path" ;;
    corrupt) printf 'corrupt\n' > "$member_path" ;;
    wrong-completion) printf '#compdef degu\n' > "$member_path" ;;
    extra) printf 'unexpected\n' > "$member_path" ;;
    *) fail "Unknown release test mutation: $mutation" ;;
  esac
}

expected_failure_message() {
  case "$1" in
    symlink | independent | extra) printf '%s\n' "Archive entries do not match" ;;
    empty) printf '%s\n' "Required archive member is not a nonempty regular file" ;;
    nonexec) printf '%s\n' "Archived degu binary is not executable" ;;
    corrupt) printf '%s\n' "Archived MIT license differs" ;;
    wrong-completion) printf '%s\n' "Completion script does not register dg for zsh" ;;
    appledouble) printf '%s\n' "Archive contains AppleDouble or macOS metadata" ;;
    *) fail "Unknown release test mutation: $1" ;;
  esac
}

test_member_mutation() {
  case_name=$1
  member=$2
  mutation=$3
  case_directory="$work/$case_name"
  extracted="$work/extracted-$case_name"
  member_path="$extracted/$release_root/$member"
  mkdir -p "$case_directory" "$extracted"
  cp -R "$valid/." "$case_directory/"
  tar -xzf "$case_directory/$archive" -C "$extracted"

  apply_member_mutation "$mutation" "$member_path" "$extracted/$release_root"
  if [ "$mutation" = appledouble ]; then
    repack_case "$case_directory" "$extracted" "$member"
  else
    repack_case "$case_directory" "$extracted"
  fi
  expected_message=$(expected_failure_message "$mutation")
  expect_verification_failure "$case_directory" "$expected_message"
}

[ "$#" -eq 2 ] || fail "Usage: $0 <tag> <target>"

tag=$1
target=$2
release_root=$(release_asset_stem "$tag" "$target")
archive=$(release_archive_name "$tag" "$target")
checksum=$(release_checksum_name "$tag" "$target")
work=$(mktemp -d "${TMPDIR:-/tmp}/degu-release-test.XXXXXX") || fail "Could not create a temporary directory."

cleanup() {
  status=$?
  trap - EXIT
  rm -rf "$work"
  exit "$status"
}

trap cleanup EXIT
trap 'exit 1' HUP INT TERM
valid="$work/valid"

./tools/package-release.sh "$tag" "$target" "$valid"
./tools/verify-release-assets.sh "$tag" "$valid" "$target"

expect_packaging_failure "v999.999.999" "does not match the binary version" "$work/wrong-tag"
expect_packaging_failure "v0.1.0 bad" "contains characters that are not safe" "$work/invalid-tag"
test_missing_asset "$archive"
test_missing_asset "$checksum"

for member in degu dg completions/degu.bash completions/degu.zsh completions/degu.fish completions/dg.bash completions/dg.zsh completions/dg.fish LICENSE-APACHE LICENSE-MIT; do
  test_missing_member "$member"
done
for page in $man_pages; do
  test_missing_member "man/$page"
done

test_member_mutation "symlink-license" "LICENSE-APACHE" symlink
test_member_mutation "empty-completion" "completions/degu.zsh" empty
test_member_mutation "empty-man" "man/degu-scan.1" empty
test_member_mutation "non-executable-binaries" degu nonexec
test_member_mutation "independent-dg" dg independent
test_member_mutation "corrupt-license" "LICENSE-MIT" corrupt
test_member_mutation "wrong-dg-completion" "completions/dg.zsh" wrong-completion
test_member_mutation "extra-member" unexpected.txt extra
# bsdtar consumes ._ members as AppleDouble metadata, so the rejection this
# case pins is unobservable there; CI runs the case under GNU tar.
if tar --version 2>/dev/null | grep -Fq bsdtar; then
  printf '%s\n' "skip: appledouble-metadata under bsdtar" >&2
else
  test_member_mutation "appledouble-metadata" appledouble-entry appledouble
fi

bad_checksum="$work/bad-checksum"
mkdir -p "$bad_checksum"
cp -R "$valid/." "$bad_checksum/"
printf "%0${SHA256_HEX_LENGTH}d  %s\n" 0 "$archive" > "$bad_checksum/$checksum"
expect_verification_failure "$bad_checksum" "Checksum verification failed"

wrong_checksum_name="$work/wrong-checksum-name"
mkdir -p "$wrong_checksum_name"
cp -R "$valid/." "$wrong_checksum_name/"
printf '%s  wrong.tar.gz\n' "$(calculate_sha256 "$wrong_checksum_name/$archive")" > "$wrong_checksum_name/$checksum"
expect_verification_failure "$wrong_checksum_name" "Checksum references the wrong archive"

extra_asset="$work/extra-asset"
mkdir -p "$extra_asset"
cp -R "$valid/." "$extra_asset/"
printf 'unexpected\n' > "$extra_asset/unexpected.txt"
expect_verification_failure "$extra_asset" "Release asset set does not match"
