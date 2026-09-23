# Configuration

degu reads `~/.config/degu/config.toml` and honors `XDG_CONFIG_HOME`. Every field is optional.

```toml
roots = ["~/code"]
protect = [".cache/my-project"]
disable = ["ollama", "vllm"]
max_concurrency = 2
runtime = false

[advisory]
enabled = true
command = "/home/you/bin/degu-advise"
timeout_seconds = 20
```

## Fields

| Field | Type | Effect |
| --- | --- | --- |
| `roots` | Array of paths | Adds project trees to read-only build-artifact discovery. `clean` requires those roots as explicit positional arguments. |
| `protect` | Array of paths | Adds paths to the safety guard. Relative paths resolve against `$HOME`. |
| `disable` | Array of adapter IDs | Disables registered ecosystem adapters. |
| `max_concurrency` | Integer from 1 through 256 | Overrides the per-filesystem concurrent directory-read limit. |
| `runtime` | Boolean | Opts `scan` into available runtime diagnostics. Defaults to `false`. |
| `advisory.enabled` | Boolean | Shows the advisory block in the interactive review. Defaults to `true`. |
| `advisory.command` | Absolute path | A program degu runs for an advisory about locations it could not classify. Unset by default, and nothing runs and nothing is sent without it. |
| `advisory.timeout_seconds` | Integer from 1 through 120 | How long the advisor may take. Defaults to 20. |

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

## Advisory

`degu tui` classifies what it can and says **Not managed** for the rest. That verdict is honest and also where a reader gets stuck: a directory degu cannot name is usually the largest thing on the node, and the only way forward has been `rm -rf`, which gives up staging, `undo`, the operation log, and every boundary check.

The advisory block fills that gap without entering the decision. It appears only on findings degu could not classify, and it reports three separate things under separate headings: what degu measured, why degu says what it says, and — when an advisor is configured — what that advisor thinks. Every line an advisor produced is prefixed with `~`, and degu's own lines never are.

Nothing in this block can reach a classification, a selection, or a plan. The strongest thing it can do is put a sentence on the screen, and the screen says whose sentence it is.

### degu speaks no model protocol

There is no HTTP client here, no TLS stack, no provider adapter, no prompt, and no credential handling. `advisory.command` names an executable the account already trusts. degu hands it a JSON signature on standard input and reads JSON back from standard output, under the same bounds every other host tool runs under: an absolute path never resolved through `PATH`, no shell, an emptied environment, a neutral working directory, a discarded standard error, and hard limits on time and output.

Which model, which endpoint, which key, and which prompt are entirely that program's business. degu could not learn any of them if it tried — the child's environment is emptied before exec, so a credential cannot even be passed through it. An advisor that calls a hosted API reads its own key; one that calls a model on the same machine reads nothing. Both are the same contract to degu, and neither makes degu something that has to be kept up to date with somebody's API.

On a login node with no egress, leave `command` unset. degu runs no program and sends nothing anywhere; the block still reports what degu measured and says no advisor is configured.

### What degu sends

Only findings degu could not classify — those whose reason is that recovery or ownership is unknown. A location degu withheld because it recognized a user asset, a tool-coordinated directory, a credential boundary, or a shared-writable parent is already decided, and is never sent. The account home is elided the way it is everywhere else degu prints a path, and nothing below the named directory is described: no file list, no contents, no names of your own work. At most 32 locations go in one request, largest first.

```json
{
  "degu_advisory_request": 1,
  "subjects": [
    {
      "id": "0",
      "path": "~/.cache/some-tool",
      "name": "some-tool",
      "ecosystem": "artifacts",
      "kind": "other",
      "bytes_allocated": 43123456789,
      "inodes": 812,
      "age_days": 34,
      "measurement_incomplete": false,
      "reason": "recovery requirements are unknown"
    }
  ]
}
```

### What degu reads back

```json
{
  "advice": [
    {
      "id": "0",
      "summary": "structure resembles a build cache written by some-tool",
      "check": "some-tool cache dir"
    }
  ]
}
```

Answers are attached by the `id` degu supplied. A path in the response is ignored entirely, so an advisor cannot attach a sentence to a location that was never part of the request. An unknown `id` is dropped, an empty summary is not an advisory, text is stripped of anything that could move a terminal cursor, and both fields are truncated.

`check` is the most useful field. A summary a reader can confirm in one command becomes evidence they gathered themselves; one they cannot check is an appeal to the advisor's confidence, and the block says so rather than letting it read as settled.

### When an advisor does not work

Every failure is an absence of advice, never an error you have to clear: a program that is missing, exits unsuccessfully, exceeds its bound, floods its output, or answers with something that is not a degu advisory all leave the review working and say what happened. A review has to open whether or not somebody's script did.

### Writing one

```sh
#!/bin/sh
# degu hands the signature on stdin and reads JSON from stdout. Read your own
# credentials here if you need any: degu's environment does not reach this.
input=$(cat)
# ... ask whatever you like, or nothing at all ...
printf '{"advice":[{"id":"0","summary":"...","check":"..."}]}\n'
```
