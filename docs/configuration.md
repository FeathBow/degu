# Configuration

degu reads `~/.config/degu/config.toml` and honors `XDG_CONFIG_HOME`. Every field is optional.

```toml
roots = ["~/code"]
protect = [".cache/my-project"]
disable = ["ollama", "vllm"]
max_concurrency = 2
runtime = false
```

## Fields

| Field | Type | Effect |
| --- | --- | --- |
| `roots` | Array of paths | Adds project trees to read-only build-artifact discovery. `clean` requires those roots as explicit positional arguments. |
| `protect` | Array of paths | Adds paths to the safety guard. Relative paths resolve against `$HOME`. |
| `disable` | Array of adapter IDs | Disables registered ecosystem adapters. |
| `max_concurrency` | Integer from 1 through 256 | Overrides the per-filesystem concurrent directory-read limit. |
| `runtime` | Boolean | Opts `scan` into available runtime diagnostics. Defaults to `false`. |

Runtime diagnostics are equivalent to passing `--runtime` to `scan`. Temporary-directory diagnostics are available on Linux and macOS; shared-memory diagnostics for `/dev/shm` are Linux-only. Their findings remain **Not managed** (`report_only` in JSON) and outside cache totals. `clean` never enables runtime adapters.

Without `max_concurrency`, Linux caps concurrent directory reads by detected filesystem: local filesystems, tmpfs, and GPFS use 4; NFS, SMB, FUSE, and unknown filesystems use 2; and Lustre, BeeGFS, and CephFS use 1. On macOS, APFS, HFS, and tmpfs use 4, while NFS, SMB, WebDAV, and unknown filesystems use 2. The field replaces those defaults for every scan root.

## Adapter discovery

Use the running binary to list every valid adapter ID instead of copying a static list that can become stale:

```sh
degu adapters
```

Use IDs from that output in `disable` or with `--only`:

```sh
degu scan --only pip
```

The additional `artifacts` and `checkpoints` IDs are discovery sources rather than configurable adapters. They are accepted only by `--only` and appear when a positional or configured project root is scanned.

Adapter selection changes discovery coverage, but it does not bypass the operational protections described in [Safety](safety.md).
