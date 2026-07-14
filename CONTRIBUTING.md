# Contributing to netmon

Thanks for your interest. netmon is a passive network monitor; the capture/parse
core lives in `netmon.py` and the optional live dashboard in `netmon_tui.py`, with
tests in `tests/test_netmon.py` (pure, Textual-free) and `tests/test_tui.py`.

## Development setup

Requires Python ≥ 3.13 and [uv](https://docs.astral.sh/uv/).

```sh
uv sync --extra tui   # --extra tui pulls in Textual for the --tui dashboard
```

## Before you open a PR

Run the full local gate — all three must be clean:

```sh
uv run pytest -q                     # tests
uv run ruff check .                  # lint + import order
uv run mypy netmon.py netmon_tui.py  # types
```

The tests decode crafted packets with scapy in-process — no capture privileges
or network access are needed to run them.

## If you touch `pyproject.toml`

`requirements.txt` is generated, never hand-edited — it is what lets netmon be
installed with nothing but a Python interpreter and pip. Regenerate it whenever a
dependency changes:

```sh
uv lock
uv export --format requirements.txt --extra tui --no-dev --no-emit-project --locked > requirements.txt
```

`uv run pytest -q` fails if you forget: `tests/test_packaging.py` re-runs that
export and compares.

## Guidelines

- Keep the tool **passive**: it reads traffic, it must never transmit.
- Match the existing style — comments explain *why* (a non-obvious constraint or
  RFC reference), not *what*. Prefer precise names over comments.
- Add or update a test for any behavior change; a bug fix should come with a
  regression test that fails before the fix.
- Keep the capture/parse **core** dependency-light and in `netmon.py`; the
  headless tool runs with no Textual installed. UI-only code and its dependency
  belong in `netmon_tui.py` behind the `tui` optional extra.
- Every generated artifact gets a test that fails when it drifts from its source.
  There is no CI here — `uv run pytest -q` *is* the gate.

## Licensing of contributions

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).

Note: netmon imports [scapy](https://scapy.net/), which is GPL-2.0-only. netmon
does not bundle scapy, so netmon's own source stays MIT — but if you redistribute
netmon **together with** scapy as a combined work, that combination is governed
by the GPL. Keep this in mind for any packaging or vendoring change.
