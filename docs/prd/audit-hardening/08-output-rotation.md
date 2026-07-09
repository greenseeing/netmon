# Slice 8 — Output rotation / size cap for the recorder

Labels: ready-for-agent

## Parent
`00-PRD-audit-hardening.md` — Harden the leak audit.

## What to build
A single run's `*.jsonl` files grow unbounded, flushed per line, for the life of
the run. `docs/RUNBOOK.md` claims each restart doubles as log rotation, but the
systemd unit uses `Restart=on-failure`, so a healthy long-lived recorder never
restarts and its files grow without bound. Add dumpcap-style rotation — a size
(and/or time) cap per run that rolls the JSONL (and the slice-05 pcap, if enabled)
to a new numbered file, keeping a bounded ring of N files. This is the in-run
complement to the disk-full degrade already shipped (`2db588a`).

## Acceptance criteria
- [ ] A per-run size cap rolls output to a new file at the threshold; a bounded
      number of rolled files is kept, oldest deleted.
- [ ] Rotation honours the owner-only (0600) file discipline and the disk-full
      degrade path (a roll that fails to open degrades, does not crash).
- [ ] Configurable via a flag / the systemd unit; off or generous by default so
      existing behaviour is unchanged unless opted in.
- [ ] Tests: driving past the cap produces multiple bounded files; the ring never
      exceeds N.

## Blocked by
None — integrates with slice 05 (pcap sink) for a shared rotation mechanism.
