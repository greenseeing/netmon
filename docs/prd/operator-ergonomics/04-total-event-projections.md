# Slice 4 — Make direction and scope total over every event kind

Labels: ready-for-agent

## Parent
`00-PRD-operator-ergonomics.md` — Make the record usable.

## What to build
A prefactor: make the change easy, then make the easy change. No behaviour changes here.

Today `scope` is a field on `FlowEvent` and nowhere else, and `direction` likewise. The query
predicate reaches for scope with `getattr(ev, "scope", None)` — the only field-existence dispatch
in the tool, and the reason `netmon query --scope internet` silently matches flows only, even
though the DNS query and the SNI *are* the disclosure.

Introduce three closed vocabularies — kind, direction, scope — and three **total** projections
over every one of the twelve kinds:

- `event_remote_addr(event)` — the address of the peer at the other end. Every kind has one
  (`dst`, `resolver`, `remote_ip`, `target_ip`, `router`), so this invents nothing.
- `event_scope(event)` — `remote_scope()` of that peer. Derived, never read off `FlowEvent.scope`:
  a flow's recorded scope *is* `remote_scope(remote_ip)` by construction, so the two always agree,
  and deriving keeps `remote_scope` the single authority. Pin the agreement with a test.
- `event_direction_name(event)` — the name, of which the existing `event_direction` becomes a
  glyph lookup.

`remote_scope` moves up beside them: it is not capture-side code, it is shared classification with
three callers.

Dispatch on `event.kind`, never `isinstance` — running `netmon.py` as a script makes its event
classes `__main__.*` while `netmon_tui` imports the `netmon.*` copies, so class-based matching
silently misses every event. The module-copy test exists because this has already bitten the
codebase once; extend it to cover the new projections.

The proof this prefactor is behaviour-preserving is that **the existing direction-glyph assertions
pass untouched.** If they need editing, the refactor is wrong.

## Acceptance criteria
- [ ] Three vocabularies exist as closed, ordered constants; the kind vocabulary is derived from `KIND_TO_FILE`, not typed out a second time.
- [ ] `event_remote_addr`, `event_scope` and `event_direction_name` are total: a test builds one event of every kind in `KIND_TO_FILE` and asserts each projection returns a value from its vocabulary, with no empty peer.
- [ ] For a processor-emitted flow, `event_scope(flow) == flow.scope` — the derived value and the recorded one agree by construction.
- [ ] LLMNR resolves to a multicast peer, ICMPv6 RA to link-local, ARP to LAN, and a DNS query to a public resolver to internet.
- [ ] The existing direction-glyph tests pass **unmodified**, and a flow carrying a bogus direction still renders the neutral glyph.
- [ ] The module-copy test covers the new projections, proving they dispatch on the kind discriminator rather than class identity.
- [ ] No CLI flag, no TUI behaviour, and no recorded output changes.

## Blocked by
None — can start immediately.
