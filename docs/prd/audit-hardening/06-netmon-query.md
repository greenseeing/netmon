# Slice 6 — `netmon query`: display filter over recorded logs

Labels: ready-for-agent

## Parent
`00-PRD-audit-hardening.md` — Harden the leak audit.

## What to build
Wireshark's core audit ergonomics separate a *capture* filter from a *display*
filter, and let you re-read a saved capture. netmon has `-r` (re-run a *pcap*
through capture) but no way to query its own recorded `*.jsonl` — the operator
hand-rolls `jq` (README recipes). Add a `netmon query` subcommand that reads a run
directory's JSONL (via `KIND_TO_FILE`) and applies a simple display filter — by
`kind`, host/SNI/qname substring, and `scope` — printing matching events. This is
a read-only convenience over already-written records; it is not a new capture
path.

## Acceptance criteria
- [ ] `netmon query <run-dir> [--kind …] [--host …] [--scope …]` prints matching
      events from the run's JSONL, newest-or-chronological, without re-capturing.
- [ ] Filters compose (kind AND host AND scope) and an empty filter prints all.
- [ ] Missing/partial run dirs fail with a clear message, not a traceback.
- [ ] Tests drive `main(["query", …])` against a fixture run directory and assert
      the filtered output.

## Blocked by
None — can start immediately.
