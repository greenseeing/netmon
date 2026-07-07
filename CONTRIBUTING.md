# Contributing to netmon

Thanks for your interest. netmon is a single-file passive network monitor; the
whole implementation lives in `netmon.py`, with tests in `tests/test_netmon.py`.

## Development setup

Requires Python ≥ 3.13 and [uv](https://docs.astral.sh/uv/).

```sh
uv sync
```

## Before you open a PR

Run the full local gate — all three must be clean:

```sh
uv run pytest -q          # tests
uv run ruff check .       # lint + import order
uv run mypy netmon.py     # types
```

The tests decode crafted packets with scapy in-process — no capture privileges
or network access are needed to run them.

## Guidelines

- Keep the tool **passive**: it reads traffic, it must never transmit.
- Match the existing style — comments explain *why* (a non-obvious constraint or
  RFC reference), not *what*. Prefer precise names over comments.
- Add or update a test for any behavior change; a bug fix should come with a
  regression test that fails before the fix.
- Keep it dependency-light and single-file unless there's a strong reason not to.

## Licensing of contributions

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).

Note: netmon imports [scapy](https://scapy.net/), which is GPL-2.0-only. netmon
does not bundle scapy, so netmon's own source stays MIT — but if you redistribute
netmon **together with** scapy as a combined work, that combination is governed
by the GPL. Keep this in mind for any packaging or vendoring change.
