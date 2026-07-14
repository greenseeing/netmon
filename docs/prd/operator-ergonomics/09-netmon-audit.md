# Slice 9 — `netmon audit`: re-read a recorded run for its leaks

Labels: ready-for-agent

## Parent
`00-PRD-operator-ergonomics.md` — Make the record usable.

## What to build
The always-on recorder is headless: it has no dashboard, so its findings live only in
`summary.json`. And the runs already sitting on disk — recorded before any of this existed — hold
every fact the rules need. Give the operator a command that reads a recorded run and reports what
leaked, with the diagnosis in full.

`netmon audit <run-dir>` reuses the existing record loader and the same assessor the live dashboard
uses, groups the findings by severity and rule, and prints what leaked, to whom, and what to do
about it. It captures nothing and writes nothing — a read-only view over the record, like `query`.

The headline property is worth stating in the acceptance criteria because it is the whole argument
for computing findings instead of storing them: **`netmon audit` works on a run recorded before the
feature existed.** Nothing was migrated; the record was always sufficient.

Add `--min-severity` and `--rule` to `netmon query` as well, so the record can be *sliced* by leak,
not just summarised. `query` keeps printing the raw recorded line — it is a view over the record,
never a rewriter of it — and these compose with the kind/direction/scope filters and with the CSV
export.

## Acceptance criteria
- [ ] `netmon audit <run-dir>` prints findings grouped by severity, each with its subject, count, and the full three-part diagnosis.
- [ ] It runs against a run directory recorded **before** this feature existed and produces findings — no migration, no version field, no re-capture.
- [ ] It reads rotated archives as one record, exactly as `query` does, and never crashes on a truncated or hand-edited line.
- [ ] It exits non-zero with a clear message on a path that is not a netmon run directory.
- [ ] `netmon query --min-severity` selects only events at or above that severity, and the comparison respects severity order rather than string order.
- [ ] `netmon query --rule` selects a single rule, with its choices constrained to the known rules.
- [ ] Both compose with `--kind` / `--direction` / `--scope` / `--host`, and the output is still the raw recorded line.
- [ ] The tool still never transmits, and `audit` opens no socket.

## Blocked by
- `05-event-filter.md` — the new flags extend that one predicate.
- `07-leak-findings.md` — the assessor and the ledger it reuses.
