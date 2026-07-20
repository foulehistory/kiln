# Contributing to Kiln

## Development environment

Kiln needs a real Linux kernel at runtime (namespaces, cgroups v2,
overlayfs) — on Windows, develop inside WSL2. Native Windows builds don't
work: `nix`, a core dependency, is Linux-only.

```sh
git clone https://github.com/foulehistory/kiln.git
cd kiln
cargo build --workspace
```

Most integration tests need root (creating namespaces, cgroups, bridges)
and will skip themselves with a message explaining why if run as a
non-root user — that's expected outside of CI, not a failure.

```sh
cargo test --workspace
```

## Before opening a PR

- `cargo test --workspace` passes.
- If your change touches the dashboard (a separate repo,
  [kiln-dashboard](https://github.com/foulehistory/kiln-dashboard)):
  `npx tsc --noEmit` passes there too.
- If your change touches the runtime or networking path (namespaces,
  cgroups, overlayfs, bridge networking, volumes), test it against a
  real running container, not just unit tests — this project's own
  convention is to keep a couple of real reference workloads (a small
  multi-container web app, a game server) running throughout
  development specifically to catch regressions unit tests wouldn't.
- Keep the change scoped. A bug fix doesn't need surrounding cleanup; a
  new feature doesn't need to also refactor what it touches.

## Code conventions

This codebase leans heavily on doc comments to explain *why*, not *what*
— a comment restating what the next line of code obviously does is
worse than no comment. When you're about to write a comment, ask: would
a reader be confused without it? If the answer is no, skip it.

Specific things to know:

- **No premature abstraction.** Three similar lines are better than a
  speculative helper function built for a future case that doesn't
  exist yet.
- **Errors are `Result`, not panics**, outside of genuine invariant
  violations (`expect()` is fine when the alternative truly can't
  happen — e.g. serializing a type that's known to always serialize).
- **External dependencies get weighed, not defaulted to.** If you're
  adding a new crate and there's more than one reasonable choice, say so
  in your PR description — trade-offs, not just "I picked X."
- **Security-relevant claims go in [SECURITY.md](SECURITY.md), and stay
  honest.** If a change affects what is or isn't isolated, update it in
  the same PR — that file is only useful if it never lags the code.

## Commit messages

Focus on *why*, not *what* — the diff already shows what changed.
Imperative mood ("Add X", not "Added X" or "Adds X").

## Versioning

See the README's [Versioning](README.md#versioning) section. All 6
Rust crates in this workspace are version-bumped together (they're
released as one tarball); `kiln-dashboard` has its own independent
version.
