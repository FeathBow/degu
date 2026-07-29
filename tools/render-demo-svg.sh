#!/bin/bash
# Regenerate docs/assets/demo.svg from a REAL degu run.
# The image must always come from real output: this script builds the same
# demo fixture the README transcript is pinned to, captures a true TTY
# rendering (colors, glyphs, 100 columns) through a PTY, and converts the
# ANSI capture to SVG with rich. Requires: a degu binary, python3, and the
# rich package (pip install rich, or a throwaway venv).
set -euo pipefail
BIN="${1:?usage: render-demo-svg.sh <path-to-degu-binary> [out.svg]}"
OUT="${2:-docs/assets/demo.svg}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
HOME_DIR="$WORK/home"; CFG="$WORK/cfg"; STATE="$WORK/state"
mkdir -p "$HOME_DIR/.cache/pip" "$CFG/degu" "$STATE"
: > "$CFG/degu/config.toml"
MIB=$((1024 * 1024))
head -c $((6 * MIB)) /dev/zero > "$HOME_DIR/.cache/pip/wheel-cache.bin"
mkdir -p "$HOME_DIR/.cache/huggingface/hub/models--bert--base/blobs"
head -c $((12 * MIB)) /dev/zero > "$HOME_DIR/.cache/huggingface/hub/models--bert--base/blobs/model.bin"
mkdir -p "$HOME_DIR/.cache/uv"
head -c $((4 * MIB)) /dev/zero > "$HOME_DIR/.cache/uv/cache.bin"
python3 - "$BIN" "$HOME_DIR" "$CFG" "$STATE" "$WORK/demo.ansi" <<'PY'
import errno, fcntl, os, pty, select, signal, struct, sys, termios
bin_, home, cfg, state, out = sys.argv[1:6]
env = {"HOME": home, "XDG_CONFIG_HOME": cfg, "XDG_STATE_HOME": state,
       "TERM": "xterm-256color", "PATH": "/usr/bin:/bin",
       "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8"}
pid, fd = pty.fork()
if pid == 0:
    os.execve(bin_, [bin_, "scan"], env)
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 45, 100, 0, 0))
buf = b""
while True:
    ready, _, _ = select.select([fd], [], [], 10)
    if not ready:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        sys.exit("degu scan produced no output for 10s under the PTY")
    try:
        chunk = os.read(fd, 65536)
    except OSError as error:
        # EIO is how a closed PTY reports EOF; anything else is a real failure.
        if error.errno != errno.EIO:
            raise
        break
    if not chunk:
        break
    buf += chunk
_, status = os.waitpid(pid, 0)
if not (os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0):
    sys.exit(f"degu scan failed under the PTY: wait status {status}")
open(out, "wb").write(buf)
PY
python3 - "$WORK/demo.ansi" "$OUT" <<'PY'
import re
import sys
from rich.console import Console
from rich.terminal_theme import MONOKAI
from rich.text import Text
raw = open(sys.argv[1], "rb").read().decode("utf-8").replace("\r\n", "\n").rstrip("\n") + "\n"
console = Console(record=True, width=100, force_terminal=True)
console.print(Text.from_ansi("$ degu scan\n" + raw), highlight=False)
console.save_svg(sys.argv[2], title="degu", theme=MONOKAI)
# Strip the OS-specific window-button circles: the hero image should read
# as "a terminal", not any particular desktop.
svg = open(sys.argv[2]).read()
svg = re.sub(r"\s*<circle[^>]*/>", "", svg)
open(sys.argv[2], "w").write(svg)
PY
echo "wrote $OUT"
