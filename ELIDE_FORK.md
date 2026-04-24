# Elide fork of rustls

- **Upstream:** https://github.com/rustls/rustls
- **Upstream tag at fork:** `v/0.23.39` (commit `05416057`)
- **Forked on:** 2026-04-23
- **Fork purpose:** work around a nightly-rustc incompat in rustls 0.23.39: a dead `#![cfg_attr(read_buf, feature(core_io))]` line on line 381 of `rustls/src/lib.rs` tries to opt into a feature name (`core_io`) that was renamed to `core_io_borrowed_buf` in Nov 2023 and is no longer recognized. The next line (`feature(core_io_borrowed_buf)`) is correct and provides what the `read_buf` path actually needs. Upstream will likely drop the dead line soon; when they do, this fork can retire.

## Elide-applied patches

In reverse chronological order:

- (2026-04-23) — `fix: drop dead feature(core_io) cfg_attr`
  - `rustls/src/lib.rs:381`: removed `#![cfg_attr(read_buf, feature(core_io))]`.
  - Reason: `core_io` was renamed to `core_io_borrowed_buf` in rustc via rust-lang/rust#117693 (~Nov 2023). Modern nightlies no longer know the old name and reject `feature(core_io)` as `E0635: unknown feature`. The adjacent `feature(core_io_borrowed_buf)` line on the next line alone is sufficient for rustls' `read_buf` fast path.

## Sync procedure

```bash
git fetch upstream
git merge upstream/main   # or cherry-pick specific commits
# re-apply the one-line patch if upstream hasn't already dropped it
```
