# Slice 5 — One EventFilter, shared by the dashboard and `netmon query`

Labels: ready-for-agent

## Parent
`00-PRD-operator-ergonomics.md` — Make the record usable.

## What to build
netmon has two filter vocabularies today. The dashboard cycles one lowercase substring, matched
against kind-or-host-or-detail. `netmon query` has its own flags and its own predicate. They share
`event_host()` and nothing else. Collapse them into one value object.

`EventFilter` is a frozen dataclass holding, for each of the three dimensions, **the set of values
that pass**: OR within a dimension, AND across dimensions. Its defaults are the full vocabularies,
so "unset" needs no special case in the predicate and a checkbox group maps 1:1 onto a set. It also
carries a `host` substring, matched against `event_host()` exactly as `query --host` does — with the
empty string as the identity, so that too needs no special case.

**No boxes checked means nothing passes.** That is honest — it is what "I selected zero kinds"
says — and it must be signposted rather than silently reinterpreted as "all".

`DashboardModel.passes()` stays as the seam the feed calls and simply delegates. The query
predicate is **deleted**, along with its `getattr`-based scope lookup. `netmon query` gains
repeatable `--kind` / `--direction` / `--scope`, all constrained to their vocabulary, and the
"flag absent means every value" convention is written down in exactly one place.

Two deliberate breaking changes to `query`, both improvements, both worth a CHANGELOG entry:

- `--scope internet` now selects **every kind whose peer is on the internet** — the DNS query to a
  public resolver, the SNI to the CDN, the flow — not just flows.
- `--scope local` is now rejected with the list of valid choices, because `local` is a *direction*,
  not a scope. The existing query fixture records a flow with `scope="local"`, a value the scope
  classifier can never return; that fixture is fibbing and this surfaces it. Fix the fixture rather
  than widening the vocabulary to accommodate it.

Dropping the dashboard's substring matching is a zero-capability loss: all four of its current
needles are kind names, so its host and detail arms are unreachable-in-practice accidents. Keep the
`f` cycle working over `EventFilter` values for now — the widget is the next slice, and this one
should be shippable on its own with the UI unchanged.

## Acceptance criteria
- [ ] A default filter passes every kind; the ring remains filter-independent, so re-selecting a value re-reveals events already captured.
- [ ] Selecting two kinds passes both and nothing else (OR within a dimension).
- [ ] Constraining kind and scope together excludes an event that matches only one (AND across dimensions).
- [ ] An empty set in any dimension passes nothing, and the emptiness is reported to the user rather than treated as "all".
- [ ] The host substring is case-insensitive, and the empty string matches everything.
- [ ] `netmon query --kind` is repeatable; `--direction` exists; `--scope internet` matches DNS, TLS and flow events alike, not only flows.
- [ ] `netmon query --scope local` exits non-zero listing the valid scopes, and the fixture that recorded an impossible scope is corrected.
- [ ] The query-side predicate and its field-existence lookup are gone — one predicate serves both consumers.
- [ ] Filtering while scrolled back still re-filters the frozen snapshot, not the live tail; a filter that empties the feed still clears the stale detail pane; the filter still never reaches the writer or the pcap sink.

## Blocked by
- `04-total-event-projections.md` — the predicate is a product of three total projections.
