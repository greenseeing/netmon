# Slice 6 — A filter bar with checkboxes, not a one-at-a-time cycle

Labels: ready-for-agent

## Parent
`00-PRD-operator-ergonomics.md` — Make the record usable.

## What to build
Replace the `f`-cycles-one-substring interaction with a collapsible **filter bar** carrying three
multi-select lists — kind, direction, scope — so an operator can ask for "DNS *and* TLS", or "only
internet-bound", and can finally reach `arp`, `icmp6_ra`, `llmnr` and `nbns`, which the cycle never
offered at all.

**An in-place bar, not a modal.** Textual's `App.children` contains only the active screen, so
while a modal screen is pushed the app can no longer query its own feed widget: the 10 Hz render
loop would early-return for the modal's entire life, the pending-event list would pile up behind
it, and the rebuild would raise. A bar above the feed changes the feed's **height**, never its
width, so the column-fitting logic is untouched — and if a scrollbar appears because the feed got
shorter, the existing width watch refits automatically.

`escape` is already bound to *follow*, which looks like a collision and is not. Textual resolves
bindings along the focused widget's ancestors before reaching the app, so binding `escape` on the
bar itself shadows the app's binding **only while focus is inside the bar**, and nowhere else. The
app's binding is untouched and still follows the newest event when the bar is closed. Likewise, a
selection list does not consume ordinary letter keys, so `f` still reaches the app and can both
open and close the bar; `space` *is* consumed, which is what you want while ticking boxes.

The two new places text reaches the screen — the list prompts and the border title — both parse
console markup when handed a plain string, so both must be handed a rich `Text` instead. The
existing single-call-site paint guard extends rather than breaks. The vocabularies are closed and
netmon-owned, so no wire text enters the widget; the border title's host substring, when it exists,
goes through the same scrubber every other wire-derived string does.

The active filter must be **unmissable**, for the same reason the paused and inspecting modes are
surfaced three ways: a filtered feed must never be mistaken for a quiet network. Fold a compact
label into the feed's border title, and when the filter empties the feed say so — "no rows match
the filter" is a different fact from "no events".

## Acceptance criteria
- [ ] The bar is hidden at startup and the default filter passes everything.
- [ ] `f` opens the bar and focuses it; `f` again closes it.
- [ ] `escape` with focus in the bar closes it **without** snapping the feed back to follow; `escape` with the bar closed still follows.
- [ ] Ticking kinds rebuilds the feed to exactly those kinds; direction and scope compose with it.
- [ ] Unticking every box in a group empties the feed and shows "no rows match the filter", not "no events".
- [ ] The three lists offer exactly the closed vocabularies — a drift guard, and the proof no wire text can enter the widget.
- [ ] The feed's border names the active filter whenever it is constrained.
- [ ] Filtering while scrolled back re-filters the frozen snapshot: an event that arrived while scrolled stays hidden.
- [ ] A run under a constrained filter still records every event to the JSONL — the filter is display-only, end to end.
- [ ] README and the RUNBOOK stop describing the `all → dns → tls → http → flow` cycle.

## Blocked by
- `05-event-filter.md` — the bar is a view onto that value object.
