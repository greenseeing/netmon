# Slice 1 — A hash-pinned requirements.txt that cannot drift

Labels: ready-for-agent

## Parent
`00-PRD-operator-ergonomics.md` — Make the record usable.

## What to build
Check in a `requirements.txt` exported from `uv.lock`, so netmon can be installed with
nothing but a Python interpreter and pip. It must carry the `tui` extra — `netmon run` *is*
the dashboard, so a tui-less install is a broken one-liner — and it must keep its hashes, so
`pip install --require-hashes` gives the same integrity guarantee as `uv sync`. That matters
most to the person taking this path precisely because they declined an unchecked download.

The file is **generated, never hand-edited**, so the risk is silent drift from
`pyproject.toml` / `uv.lock`. Close that with a test, because there is no CI in this repo —
`uv run pytest -q` *is* the gate. `uv export` writes its own invocation into the file's header
comment, so the test can read the command out of the file and re-run it: the artifact documents
how it is made, and the test executes that documentation, with no second copy of the argument
list to fall out of step. Compare only the non-comment, non-blank lines, so a future uv's header
wording cannot cause a spurious failure, and make the failure message contain the exact
regeneration command.

Do not add a `requirements-dev.txt`: the contributor gate is `uv run pytest/ruff/mypy`, so it
would be a second authority for the dev toolchain with no consumer.

## Acceptance criteria
- [ ] `requirements.txt` is checked in, includes the `tui` extra and its transitive tree, carries `--hash` entries, and does not include the project itself.
- [ ] `pip install --require-hashes -r requirements.txt` into a bare venv succeeds and yields a working `import netmon` once the project is installed alongside it.
- [ ] A test fails when `requirements.txt` disagrees with `uv.lock`, and its message names the exact command that regenerates the file.
- [ ] A test fails when `uv.lock` disagrees with `pyproject.toml`.
- [ ] Both tests skip cleanly (not fail) when `uv` is not on PATH, so the pip-installed contributor can still run the suite.
- [ ] CONTRIBUTING records the one-line regeneration step for anyone who touches `pyproject.toml`.

## Blocked by
None — can start immediately.
