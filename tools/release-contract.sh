#!/bin/sh

targets="x86_64-unknown-linux-musl aarch64-unknown-linux-musl x86_64-apple-darwin aarch64-apple-darwin"
man_pages="
degu.1
degu-doctor.1
degu-admin.1
degu-admin-setup.1
degu-quota.1
degu-scan.1
degu-clean.1
degu-undo.1
degu-trash.1
degu-trash-list.1
degu-trash-purge.1
degu-reclaim.1
degu-reclaim-uv.1
degu-relocate.1
degu-ops.1
degu-adapters.1
degu-completions.1
degu-man.1
"
completion_files="
degu.bash
degu.fish
degu.zsh
dg.bash
dg.fish
dg.zsh
"
SHA256_HEX_LENGTH=64

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

validate_tag() {
  case "$1" in
    v[0-9]*) ;;
    *) fail "Release tag must start with v and a numeric version: $1" ;;
  esac
  case "${1#v}" in
    *[!0-9A-Za-z.+-]* | '') fail "Release tag contains characters that are not safe in a release filename: $1" ;;
  esac
}

release_target_supported() {
  case " $targets " in
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
}

release_asset_stem() {
  printf 'degu-%s-%s' "$1" "$2"
}

release_archive_name() {
  printf '%s.tar.gz' "$(release_asset_stem "$1" "$2")"
}

release_checksum_name() {
  printf '%s.sha256' "$(release_asset_stem "$1" "$2")"
}

release_installer_name() {
  printf 'degu-install.sh'
}

# With an empty tag this yields the stock install.sh line; with a release tag
# it yields the line the published installer asset must carry instead.
release_installer_version_line() {
  printf 'version=${DEGU_VERSION:-%s}' "$1"
}

calculate_sha256() {
  digest_path=$1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$digest_path" | awk '{print $1}'
    return
  fi

  command -v shasum >/dev/null 2>&1 || fail "sha256sum or shasum is required."
  shasum -a 256 "$digest_path" | awk '{print $1}'
}

write_release_checksum() {
  checksum_directory=$1
  checksum_archive=$2
  checksum_output=$3
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$checksum_directory" && sha256sum "$checksum_archive" > "$checksum_output")
    return
  fi

  command -v shasum >/dev/null 2>&1 || fail "sha256sum or shasum is required."
  (cd "$checksum_directory" && shasum -a 256 "$checksum_archive" > "$checksum_output")
}
