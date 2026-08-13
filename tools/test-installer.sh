#!/bin/sh
# Failure matrix for install.sh's publish transaction. Fault injection is a
# PATH shim over one tool per scenario that fires once when the argv matches;
# the installer runs unmodified against a real local release tree. This is
# the release boundary state machine, unreachable from the CLI test suite.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
installer="$repo_root/install.sh"
[ -f "$installer" ] || { echo "install.sh not found at $installer" >&2; exit 1; }

version=v9.9.9
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64 | Darwin-aarch64) target=aarch64-apple-darwin ;;
  Darwin-x86_64) target=x86_64-apple-darwin ;;
  Linux-x86_64 | Linux-amd64) target=x86_64-unknown-linux-musl ;;
  Linux-aarch64 | Linux-arm64) target=aarch64-unknown-linux-musl ;;
  *) echo "unsupported test platform: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fails=0

check() {
  if [ "$1" = "$2" ]; then
    echo "ok: $3"
  else
    echo "FAIL: $3 (want [$2] got [$1])" >&2
    fails=$((fails + 1))
  fi
}

sha_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$(dirname "$1")" && sha256sum "$(basename "$1")")
  else
    (cd "$(dirname "$1")" && shasum -a 256 "$(basename "$1")")
  fi
}

new_scenario() {
  scen=$(mktemp -d "$work/scen.XXXXXX")
  mkdir -p "$scen/stage/degu-${version}-${target}" "$scen/dl" "$scen/bin" "$scen/shim" "$scen/tmpdir"
  printf 'NEW-degu\n' > "$scen/stage/degu-${version}-${target}/degu"
  printf 'NEW-dg\n' > "$scen/stage/degu-${version}-${target}/dg"
  (cd "$scen/stage" && tar -czf "$scen/dl/degu-${version}-${target}.tar.gz" "degu-${version}-${target}")
  sha_file "$scen/dl/degu-${version}-${target}.tar.gz" > "$scen/dl/degu-${version}-${target}.sha256"
}

preexisting() {
  for name in "$@"; do
    printf 'OLD-%s\n' "$name" > "$scen/bin/$name"
  done
}

# Shim one tool: when the joined argv first contains $2, run $3 once, then
# hand off to the real tool. $3 is written into the shim verbatim, so runtime
# variables like $PPID must arrive single-quoted.
make_shim() {
  tool=$1
  match=$2
  cmd=$3
  real=$(command -v "$tool") || { echo "missing tool: $tool" >&2; exit 1; }
  cat > "$scen/shim/$tool" <<SHIM
#!/bin/sh
if [ ! -f "$scen/tripped.$tool" ]; then
  case "\$*" in
    *"$match"*)
      : > "$scen/tripped.$tool"
      $cmd
      ;;
  esac
fi
exec "$real" "\$@"
SHIM
  chmod +x "$scen/shim/$tool"
}

run_installer() {
  rc=0
  env PATH="$scen/shim:/usr/bin:/bin" TMPDIR="$scen/tmpdir" \
    DEGU_LOCAL_DIR="$scen/dl" DEGU_VERSION="$version" DEGU_INSTALL_DIR="$scen/bin" \
    sh "$installer" >"$scen/out" 2>"$scen/err" || rc=$?
}

content() { if [ -f "$1" ]; then cat "$1"; else echo "<absent>"; fi }
txn_dirs() { ls -d "$scen/bin"/.degu-install.* 2>/dev/null | wc -l | tr -d ' '; }
rollback_msg() { if grep -q 'rollback incomplete' "$scen/err"; then echo yes; else echo no; fi }

echo "--- S0 fresh install succeeds"
new_scenario; run_installer
check "$rc" "0" "S0 exit status"
check "$(content "$scen/bin/degu")" "NEW-degu" "S0 installs degu"
check "$(content "$scen/bin/dg")" "NEW-dg" "S0 installs dg"
check "$(txn_dirs)" "0" "S0 no transaction dir left"
if grep -Fq "run 'degu doctor'" "$scen/out"; then doctor_hint=yes; else doctor_hint=no; fi
check "$doctor_hint" "yes" "S0 teaches the short read-only readiness command"
if grep -Eq 'sudo|/var/lib/degu|/private/var/db/degu' "$scen/out" "$scen/err"; then privileged_hint=yes; else privileged_hint=no; fi
check "$privileged_hint" "no" "S0 installer neither runs nor prescribes an inline privileged write"

echo "--- S1 upgrade succeeds"
new_scenario; preexisting degu dg; run_installer
check "$rc" "0" "S1 exit status"
check "$(content "$scen/bin/degu")" "NEW-degu" "S1 replaces degu"
check "$(content "$scen/bin/dg")" "NEW-dg" "S1 replaces dg"
check "$(txn_dirs)" "0" "S1 no transaction dir left"

echo "--- S2 only dg preexists, install succeeds"
new_scenario; preexisting dg; run_installer
check "$rc" "0" "S2 exit status"
check "$(content "$scen/bin/degu")" "NEW-degu" "S2 installs degu"
check "$(content "$scen/bin/dg")" "NEW-dg" "S2 replaces dg"

echo "--- S3 fresh install, dg publish fails: nothing left behind"
new_scenario; make_shim cat "new.dg" 'exit 1'; run_installer
check "$rc" "1" "S3 exit status"
check "$(content "$scen/bin/degu")" "<absent>" "S3 no degu"
check "$(content "$scen/bin/dg")" "<absent>" "S3 no dg"
check "$(txn_dirs)" "0" "S3 transaction dir cleaned after full rollback"

echo "--- S4 upgrade, dg publish fails: both old restored"
new_scenario; preexisting degu dg; make_shim cat "new.dg" 'exit 1'; run_installer
check "$rc" "1" "S4 exit status"
check "$(content "$scen/bin/degu")" "OLD-degu" "S4 restores old degu"
check "$(content "$scen/bin/dg")" "OLD-dg" "S4 restores old dg"
check "$(txn_dirs)" "0" "S4 transaction dir cleaned after full rollback"

echo "--- S5 only degu preexists, dg publish fails: degu restored, dg absent"
new_scenario; preexisting degu; make_shim cat "new.dg" 'exit 1'; run_installer
check "$rc" "1" "S5 exit status"
check "$(content "$scen/bin/degu")" "OLD-degu" "S5 restores old degu"
check "$(content "$scen/bin/dg")" "<absent>" "S5 removes partial dg"

echo "--- S6 upgrade, TERM while backing up degu (before degu publish)"
new_scenario; preexisting degu dg; make_shim mv "old.degu" 'kill -TERM $PPID'; run_installer
check "$rc" "1" "S6 exit status"
check "$(content "$scen/bin/degu")" "OLD-degu" "S6 keeps old degu"
check "$(content "$scen/bin/dg")" "OLD-dg" "S6 keeps old dg"

echo "--- S7 upgrade, TERM after degu published (before dg backup)"
new_scenario; preexisting degu dg; make_shim chmod "755 $scen/bin/degu" 'kill -TERM $PPID'; run_installer
check "$rc" "1" "S7 exit status"
check "$(content "$scen/bin/degu")" "OLD-degu" "S7 rolls degu back"
check "$(content "$scen/bin/dg")" "OLD-dg" "S7 keeps old dg"

echo "--- S8 upgrade, TERM while backing up dg (degu already published)"
new_scenario; preexisting degu dg; make_shim mv "old.dg" 'kill -TERM $PPID'; run_installer
check "$rc" "1" "S8 exit status"
check "$(content "$scen/bin/degu")" "OLD-degu" "S8 rolls degu back"
check "$(content "$scen/bin/dg")" "OLD-dg" "S8 restores old dg"

echo "--- S9 fresh install, TERM after degu published: nothing left behind"
new_scenario; make_shim chmod "755 $scen/bin/degu" 'kill -TERM $PPID'; run_installer
check "$rc" "1" "S9 exit status"
check "$(content "$scen/bin/degu")" "<absent>" "S9 removes published degu"
check "$(content "$scen/bin/dg")" "<absent>" "S9 no dg"

echo "--- S10 upgrade, restore of old degu fails: backups preserved, honest error"
new_scenario; preexisting degu dg; chmod 000 "$scen/bin/degu"
make_shim cat "new.dg" 'exit 1'; run_installer
check "$rc" "1" "S10 exit status"
check "$(rollback_msg)" "yes" "S10 reports rollback incomplete"
check "$(ls "$scen/bin"/.degu-install.*/old.degu >/dev/null 2>&1 && echo kept || echo lost)" "kept" "S10 preserves degu backup"
check "$(content "$scen/bin/dg")" "OLD-dg" "S10 still restores old dg"

echo "--- S11 pre-existing symlink destination is refused untouched"
new_scenario; mkdir "$scen/elsewhere"; ln -s "$scen/elsewhere" "$scen/bin/degu"; run_installer
check "$rc" "1" "S11 exit status"
check "$([ -L "$scen/bin/degu" ] && echo link || echo gone)" "link" "S11 leaves the symlink alone"
check "$(content "$scen/bin/dg")" "<absent>" "S11 publishes nothing"
check "$(txn_dirs)" "0" "S11 no transaction dir left"

echo "--- S12 symlink swapped in after the stage check never receives the binary"
new_scenario; mkdir "$scen/elsewhere"
make_shim cp "new.dg" "ln -s \"$scen/elsewhere\" \"$scen/bin/degu\""; run_installer
check "$rc" "0" "S12 exit status"
check "$([ -L "$scen/bin/degu" ] && echo link || echo file)" "file" "S12 destination is a real file"
check "$(content "$scen/bin/degu")" "NEW-degu" "S12 installs degu at the leaf"
check "$(ls -A "$scen/elsewhere" | wc -l | tr -d ' ')" "0" "S12 nothing written through the symlink"

echo "--- S13 tmp cleanup failure does not block rollback"
new_scenario; preexisting degu dg
make_shim cat "new.dg" 'exit 1'; make_shim rm "$scen/tmpdir" 'exit 1'; run_installer
check "$rc" "1" "S13 exit status preserved"
check "$(content "$scen/bin/degu")" "OLD-degu" "S13 restores old degu"
check "$(content "$scen/bin/dg")" "OLD-dg" "S13 restores old dg"
check "$(rollback_msg)" "no" "S13 rollback itself completed"

echo "--- S14 staging failure leaves an existing install untouched"
new_scenario; preexisting degu dg; make_shim cp "new.dg" 'exit 1'; run_installer
check "$rc" "1" "S14 exit status"
check "$(content "$scen/bin/degu")" "OLD-degu" "S14 old degu untouched"
check "$(content "$scen/bin/dg")" "OLD-dg" "S14 old dg untouched"
check "$(rollback_msg)" "no" "S14 no rollback needed"
check "$(txn_dirs)" "0" "S14 transaction dir cleaned"

echo "--- S15 concurrent install is refused by the destination lock"
new_scenario; preexisting degu dg
make_shim chmod "755 $scen/bin/degu" ": > \"$scen/a-paused\"; while [ ! -f \"$scen/b-done\" ]; do sleep 0.1; done"
env PATH="$scen/shim:/usr/bin:/bin" TMPDIR="$scen/tmpdir" \
  DEGU_LOCAL_DIR="$scen/dl" DEGU_VERSION="$version" DEGU_INSTALL_DIR="$scen/bin" \
  sh "$installer" >"$scen/out.a" 2>"$scen/err.a" &
a_pid=$!
while [ ! -f "$scen/a-paused" ]; do sleep 0.1; done
run_installer
check "$rc" "1" "S15 second installer refused while the first holds the lock"
if grep -q "appears to be in progress" "$scen/err"; then lockmsg=yes; else lockmsg=no; fi
check "$lockmsg" "yes" "S15 refusal names the lock"
: > "$scen/b-done"
a_rc=0; wait "$a_pid" || a_rc=$?
check "$a_rc" "0" "S15 first installer completes"
check "$(content "$scen/bin/degu")" "NEW-degu" "S15 degu from the single release"
check "$(content "$scen/bin/dg")" "NEW-dg" "S15 dg from the single release"
check "$(txn_dirs)" "0" "S15 no transaction or lock dir left"

echo "--- S16 corrupt checksum leaves the destination untouched"
new_scenario; preexisting degu dg
printf '%s  degu-%s-%s.tar.gz\n' \
  "0000000000000000000000000000000000000000000000000000000000000000" \
  "$version" "$target" > "$scen/dl/degu-${version}-${target}.sha256"
run_installer
check "$rc" "1" "S16 exit status"
check "$(content "$scen/bin/degu")" "OLD-degu" "S16 degu untouched"
check "$(content "$scen/bin/dg")" "OLD-dg" "S16 dg untouched"
check "$(txn_dirs)" "0" "S16 no transaction dir"

echo "---"
if [ "$fails" -eq 0 ]; then
  echo "installer matrix: PASS"
else
  echo "installer matrix: $fails FAILED"
  exit 1
fi
