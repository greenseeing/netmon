# Slice 11 — Test coverage: cmd_update, cmd_service, live-capture queue

Labels: ready-for-agent

## Parent
`00-PRD-audit-hardening.md` — Harden the leak audit.

## What to build
Several trust-critical, operator-facing paths have no test coverage, so a
regression in them would pass CI:
- `LiveCapture.packets` (`netmon.py` ~1856): the sniff→`call_soon_threadsafe`→
  `put_nowait` enqueue and the `QueueFull`→`_userspace_dropped += 1` drop counter
  that backs every `stats`/`summary` drop line, plus the stop/drain race — none
  exercised (tests only cover `stats()` kernel-drop math).
- `cmd_update` (~2200): a root-capable self-updater (`git pull --ff-only`,
  `uv sync`, `systemctl restart`) — dirty-tree refusal, not-a-checkout refusal,
  ff-only failure, sync failure, restart branch, already-up-to-date — all untested.
- `cmd_service` (~2245): bad-action→usage/exit-2, the `logs`/journalctl branch, the
  "systemd not available"→exit-1 branch — untested.
- `check_capture_privileges`, `build_session`'s live-capture branch, `stats_loop`,
  `announce_start`, and `main`'s `--tui` non-tty guard.

Add focused tests for these branches (the refusal/error paths especially), driving
real functions with a fake queue/subprocess boundary — no capture hardware needed.

## Acceptance criteria
- [ ] `LiveCapture`'s enqueue path and `_userspace_dropped` counter are exercised
      by driving `on_packet`/the queue directly and asserting the drop count under
      `QueueFull`.
- [ ] Each `cmd_update` and `cmd_service` refusal/error branch has a test asserting
      the exit code / refusal, with `subprocess`/`systemctl` faked at the boundary.
- [ ] The remaining CLI guards (`check_capture_privileges`, `--tui` non-tty) are
      covered.

## Blocked by
None — can start immediately; pure test work, no production change required.
