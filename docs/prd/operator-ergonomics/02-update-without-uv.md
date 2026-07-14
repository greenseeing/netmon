# Slice 2 — `netmon update` learns the pip path

Labels: ready-for-agent

## Parent
`00-PRD-operator-ergonomics.md` — Make the record usable.

## What to build
`netmon update` currently refuses to run unless **both** `git` and `uv` are on PATH, and then
shells out to `uv sync`. Ship that unchanged and a pip-built install is stranded forever on the
version it was installed at. So this lands *before* the installer grows a pip path, not after.

Teach `cmd_update` to discover how *this* install was built, and to update it the same way. The
discriminator is free and authoritative: **`uv sync` does not seed pip into the venv it
creates**, so a `pip` binary inside `.venv/bin` means the pip/`requirements.txt` path built it.
Do not invent a marker file — the venv already knows.

Using the *same* builder matters beyond taste: re-syncing a pip-built venv with uv would rebuild
it around a different interpreter and silently drop any `--setcap` grant sitting on the current
one, turning passwordless capture off without a word.

Two further corrections while here. The precondition check must gate on `git` alone now, and must
still resolve the update plan **before** the pull, so a doomed update fails before it mutates the
checkout. And the editable reinstall should run **only when `pyproject.toml` actually changed in
the pull** — `cmd_update` already has the old and new revisions to diff — because otherwise every
no-op update reaches out to PyPI for the build backend, a real regression against `uv sync`'s
no-op. If the diff itself fails, run the reinstall: fail safe, not silent.

## Acceptance criteria
- [ ] An install whose venv contains `pip` is updated with pip against `requirements.txt`, not with `uv sync`.
- [ ] An install whose venv has no `pip` is updated with `uv sync`, exactly as today.
- [ ] `netmon update` no longer refuses when `uv` is absent but the install was built by pip; it still refuses, with an actionable message, when it cannot determine any way to sync.
- [ ] The update plan is resolved before the `git pull`, so an install that cannot be synced is not left with a pulled-but-unbuilt checkout.
- [ ] A pull that does not touch `pyproject.toml` does not trigger the editable reinstall; one that does, does; a diff that errors falls back to reinstalling.
- [ ] The pip update path installs with `--require-hashes`, so an update cannot pull an unpinned dependency.
- [ ] The existing test asserting the "needs both git and uv" refusal is rewritten rather than deleted, and pip-path cases are added beside it.

## Blocked by
- `01-requirements-txt.md` — the pip update path installs from that file.
