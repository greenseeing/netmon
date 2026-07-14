# Slice 8 — Show the leaks in the dashboard

Labels: ready-for-agent

## Parent
`00-PRD-operator-ergonomics.md` — Make the record usable.

## What to build
Surface the findings where the operator is already looking. A bordered panel at the top of the side
column — it is the headline, so it goes first — listing the top findings as severity, subject and
count, ordered by severity and then by count. The running tally goes in the panel's **border title**
rather than as another line in the health panel: one authority, no new widget.

The panel reads straight off the processor's findings table at render time, exactly as the existing
host and kind panels read their counters off it. No new state in the dashboard model, and no new
paint call site — the single existing painter takes a rich `Text`, and every subject is wire-derived
(a queried name, an SNI, an address), so every subject goes through the scrubber first. That is not
belt-and-braces: it is the exact hole the scrubber exists to close, and there is already a test class
for hostile text reaching the panels.

Link the panel to the feed visually rather than structurally: accent the offending row's existing
direction cell by severity. The row projection returns a fixed set of cells and the column fitting is
built on that count, so adding a sixth column would ripple; accenting an existing cell costs nothing
and still tells the operator which line the panel is talking about.

No toast. A notification per leak on a busy network is noise, and noise is how a panel like this loses
the operator's trust in its first minute.

## Acceptance criteria
- [ ] The panel lists findings ordered by severity, then by count, each row naming the subject and how many times it was seen.
- [ ] The panel's border carries the running tally.
- [ ] A finding whose subject contains terminal escapes or bidi overrides is scrubbed before it reaches the panel — asserted, beside the existing hostile-text tests.
- [ ] A high-severity event's row is visually distinguished in the feed without adding a column.
- [ ] The panel is empty and harmless on a run with no findings, and an empty panel does not read as an assurance of safety.
- [ ] The dashboard still runs with the capture core alone — no capture-side module gains a UI import.
- [ ] The feed's column layout and width fitting are unchanged.

## Blocked by
- `07-leak-findings.md` — the panel is a view onto that ledger.
