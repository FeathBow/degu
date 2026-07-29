# Contributing to degu

## Before you start

Browse the [open issues](https://github.com/FeathBow/degu/issues) to find work. For a new change, start with an [issue](https://github.com/FeathBow/degu/issues/new/choose) so the problem, scope, and safety impact can be agreed before implementation — mandatory for new features, cleanup-policy changes, public interface changes, and broad refactors. Leave a comment when you begin to avoid duplicate work.

## Prerequisites

You need Git, [rustup](https://rustup.rs/), and the current stable Rust toolchain. `rust-toolchain.toml` selects stable Rust with rustfmt and clippy, and ordinary CI follows that rolling channel. Release builds will pin an exact stable compiler version in the release workflow when it lands; maintainers will update that pin deliberately. Older stable releases are unsupported and untested; edition 2024 support alone is not a minimum-version guarantee.

The full test suite also requires `expect` because the interactive safety tests invoke it directly. Install it with your system package manager if it is not already available.

## Setup

From a fresh clone:

```sh
rustup toolchain install stable
cargo test --workspace --locked
```

Run the development build with:

```sh
cargo run -p degu -- --help
```

## Make a change

- Keep code, comments, documentation, commit messages, and CLI output in English. Test fixtures may contain non-English text when exercising Unicode behavior. Documentation uses one paragraph per line and is not hard-wrapped.
- Use the default rustfmt style. Clippy runs with `-D warnings`; a necessary exception should be a narrow, per-site `#[allow]` with a reason.
- Use `thiserror` for reusable domain-library errors and `anyhow` in the `degu` application crate for command orchestration and context.
- Prefer end-to-end tests in `crates/degu/tests/` for user-visible CLI contracts. Use unit tests for precise safety, accounting, and error-path invariants, and avoid duplicating identical assertions at both levels.

## Safety invariants

Changes must preserve these invariants:

1. Production adapters discover and classify data; they do not delete or write discovered data.
2. A failed guard rejects the whole clean plan rather than silently skipping an unsafe path.
3. Standard output carries command data; diagnostics and logs go to standard error.
4. Traversal never follows symlink entries; selected roots are canonicalized before traversal.
5. Release binaries make no network requests.

## Validate

Run the standard checks before opening a pull request:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

CI repeats these checks and also validates documentation links; static musl build verification, dependency policy, and workflow security checks arrive with the release tooling. Pull requests must be green before merge.

## Optional Git hooks

Hooks are disabled in a fresh clone. Enable the repository hooks with:

```sh
git config core.hooksPath .githooks
```

The pre-commit hook runs rustfmt and clippy, the pre-push hook runs the workspace tests, and the commit-msg hook checks the type and scope shape plus the 72-character limit described below. CI remains authoritative for code and test validation; the remaining commit-message conventions are reviewed separately.

## Commit messages

Use Conventional Commits:

```text
type(scope)!: subject

[optional body: why, not what]

[optional footer: Refs #123 / BREAKING CHANGE: ...]
```

- **Type:** `feat`, `fix`, `build`, `ci`, `perf`, `refactor`, `docs`, `test`, `chore`, or `revert`. Use `build` for Cargo or packaging policy, `ci` for hosted automation, and `chore` when no narrower type applies.
- **Scope:** optional; use a crate (`core`, `walk`, `adapters`, `cli`) or area (`deps`, `ci`, `tools`, `init`, `release`, `test`). A scope names a place, not a kind of change.
- **Breaking changes:** add `!` and a `BREAKING CHANGE:` footer for incompatible CLI, JSON schema, or configuration changes.
- **Subject:** use imperative mood, omit the trailing period, and keep the first line at 72 characters or fewer.

Git-generated merge and revert messages, plus `fixup!` and `squash!` commits, are exempt from the hook.

Examples:

```text
fix(walk): count symlink itself instead of following it
feat(cli)!: rename --purge to --permanent
```

## Review and testing responsibility

Because degu discovers, stages, and permanently purges filesystem data, contributors must personally review, verify, and test every submitted change — code and prose alike, with or without AI assistance — in proportion to its safety impact.

Changes to discovery, safety classification, path or symlink validation, staging, purge, undo, filesystem boundaries, or quota and reclaimability claims require detailed tests covering both successful behavior and rejection paths.
