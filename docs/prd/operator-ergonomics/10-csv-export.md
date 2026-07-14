# Slice 10 — CSV export, safe to open in a spreadsheet

Labels: ready-for-agent

## Parent
`00-PRD-operator-ergonomics.md` — Make the record usable.

## What to build
Give `netmon query` a `--format csv`, so a recorded run can be handed to someone who lives in a
spreadsheet without anyone writing a converter first.

The row already exists. The dashboard's one presentation projection of an event — time, kind,
direction, host, detail — is already scrubbed, already the authority for "what an operator reads off
an event", and already tested for every kind. CSV re-serialises exactly that, with one change the
medium demands: the full timestamp rather than the feed's time-of-day slice, because an exported run
spans midnight and gets sorted in a spreadsheet.

That makes it **lossy, by design and honestly**: CSV is the dashboard's view; the JSONL is the
evidence. Say so in the help text and the README. The payoff is that the header is a *projection*,
not a schema — a new event kind adds rows, never columns, so nobody's pivot table breaks. (A lossless
per-kind mode is coherent, but it forces twelve invocations to see one run and solves nobody's problem
yet. Deferred, deliberately.)

**A spreadsheet is an interpreter too.** Excel and LibreOffice evaluate any cell whose first character
is `=`, `+`, `-` or `@`, and netmon records attacker-controlled DNS names and HTTP paths verbatim — so
a queried name of `=cmd|'/C calc'!A0`, faithfully recorded, becomes a command on the auditor's machine
when they open the export. This is the same threat the terminal-escape scrubber exists for, in a second
interpreter, and it takes the same posture: **map, never drop.** Prefix a leading apostrophe — the
spreadsheet's own "this cell is literal text" marker — so the original character stays visible and the
export does not lie by omission about what was on the wire.

Run the existing scrubber first, and a cell can never contain a newline: a row is always one physical
line, so the file stays greppable, and it is safe to `cat` a CSV that is on its way to a terminal.

One trap worth naming, because the obvious spelling is a real bug: testing "is the first character one
of `=+-@`" against a *string* is true for the empty string, which would stamp an apostrophe onto every
empty cell in the file. Use a set.

Default to the existing format, so every current contract holds untouched.

## Acceptance criteria
- [ ] `netmon query <run> --format csv` prints one header row and one row per event to stdout; the default remains the current format.
- [ ] The columns are exactly the dashboard's five projections, and a test pins the column count to the feed's cell count so a sixth cell can never silently misalign the export.
- [ ] Every one of the twelve kinds renders a row.
- [ ] The timestamp column is the full stamp, not the feed's time-of-day slice.
- [ ] A cell beginning `=`, `+`, `-` or `@` is neutralised so a spreadsheet will not evaluate it, and the original character remains visible.
- [ ] An **empty** cell is not prefixed — the set-membership trap is covered by a test.
- [ ] A comma in an HTTP path round-trips through a CSV reader; a newline on the wire cannot forge a row.
- [ ] Terminal escapes never survive into the output, so the CSV is safe to `cat`.
- [ ] A run with zero matching events still prints the header and exits zero — a headerless CSV is not a CSV.
- [ ] The format composes with every existing filter, and with `--min-severity`.
- [ ] The README and RUNBOOK state that CSV is the dashboard's view and the JSONL is the evidence, and explain the leading apostrophe.

## Blocked by
- `05-event-filter.md` — the export composes with that one predicate.
