# Slice 3 — install.sh picks a builder instead of demanding uv

Labels: ready-for-agent

## Parent
`00-PRD-operator-ergonomics.md` — Make the record usable.

## What to build
Today the installer's only way to build a venv is uv, and its only way to get uv is to pipe
`astral.sh/uv/install.sh` into `sh` as root — a step the script's own header calls an
unchecksummed trust boundary. A user running the documented one-liner on a machine without the
Astral toolchain could not install netmon.

Give the installer a **builder-selection** step, and make reaching `astral.sh` the last resort
rather than the precondition:

1. `--pip` given → the pip path; die if no interpreter satisfies `requires-python`. This is the
   explicit refusal of the curl trust boundary, and it must never touch the network for a toolchain.
2. `uv` already on PATH → today's path, byte for byte (including every host a previous install
   already bootstrapped).
3. No uv, but a system Python that satisfies `requires-python` **and** can actually build a venv →
   the pip path. This is the fix for the reported bug.
4. No uv, no usable Python, `curl` present → bootstrap uv. Only uv can *provide* an interpreter,
   so this is the one case where the trust boundary is genuinely the only option.
5. Otherwise → die with a message that names what was found, what was missing, and the two ways
   out. That message is the whole point of the exercise; a `SyntaxError` is not a diagnosis.

Detection must test that the interpreter can *import venv and ensurepip*, not merely that its
version is high enough — Debian ships those in a separate `python3-venv` package, so a host with
a new-enough Python but no venv module must be rejected up front rather than failing obscurely
three steps later. The Python floor lives in one place in the script and is asserted against
`requires-python` by a test.

The clone must move ahead of builder selection, since the pip path needs `requirements.txt` on
disk to work from.

**The pip venv must be built with `--copies`.** A default venv symlinks `bin/python3` out to
`/usr/bin/python3.x`, which `maybe_setcap` refuses to arm — correctly, since a capability there
would give every venv on the host a raw socket. Copying the launcher binary keeps the capability
scoped to netmon's own interpreter, exactly as the uv-managed one is, so the pip path loses
nothing. (The stdlib still comes from the system, so distro security updates still apply.)

While in `maybe_setcap`, replace the `/usr/*` blocklist with a `$NETMON_DIR/*` **allowlist** — that
is the actual invariant, "the capability lands on a binary we own", and it is the one that stays
true as the venv's provenance changes. Then prove the armed interpreter still starts before
trusting it: a file capability puts the loader into secure-execution mode, where an interpreter
that finds its libpython via an `$ORIGIN` rpath stops working the moment it is armed. If it will
not run, hand the capability back rather than leaving a broken install.

Also add the `curl` guard the bootstrap never had — today its absence surfaces as a bare
`curl: command not found` from `set -e` rather than the script's own message.

Finally: try to reproduce the original failure (`curl -fsSL … | sudo bash` on a host with no
Astral toolchain) in a clean container. `curl` was demonstrably present in that report, so the
missing guard is not the whole story, and the root cause is still unknown.

## Acceptance criteria
- [ ] On a host with `python3.13` + venv and **no uv**, `sudo bash install.sh` installs successfully without contacting `astral.sh`.
- [ ] `--pip` forces the pip path even when uv is present, and never fetches a toolchain.
- [ ] On a host with uv, the install is byte-for-byte the path it is today.
- [ ] On a host with neither uv nor a usable Python, the script dies with a message naming what it found, what it needs, and both remedies — never a `SyntaxError` or a bare `command not found`.
- [ ] A Python new enough but lacking the venv module is rejected during selection, with the package to install named.
- [ ] After `--pip --setcap`, the venv interpreter resolves to a real file **inside** the install prefix, `getcap` shows `cap_net_raw`, and the TUI starts with no sudo prompt.
- [ ] `maybe_setcap` refuses any target outside the install prefix, and revokes the capability if the armed interpreter will not start.
- [ ] A test asserts the installer's Python floor equals `requires-python` in `pyproject.toml`.
- [ ] README, the install.sh header's trust-boundary note, and the RUNBOOK all say uv is now optional; the RUNBOOK's stale hand-rolled "without uv" recipe is deleted rather than left to rot.

## Blocked by
- `01-requirements-txt.md` — the pip path installs from it.
- `02-update-without-uv.md` — the pip path must never ship un-updatable.
