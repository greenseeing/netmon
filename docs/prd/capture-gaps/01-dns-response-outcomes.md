# Slice 1 — DNS response outcomes (rcode + empty answers)

Labels: ready-for-agent

## Parent
`00-PRD-capture-gaps.md` — Close the remaining capture gaps.

## What to build
Parse a DNS response as a whole rather than only its answer section. Read the
response code (rcode), iterate every question, and emit a record even when the
answer section is empty — so NXDOMAIN / NODATA / SERVFAIL / REFUSED outcomes are
captured instead of silently dropped. Successful answers additionally carry their
rcode. Decide here whether this is a new `rcode`/section field on the existing
answer event or a sibling response-outcome event; keep the on-wire→event path
running through `process(pkt)`.

## Acceptance criteria
- [ ] A response with rcode NXDOMAIN and no answers emits an event recording the queried name and the rcode, written to `dns.jsonl`.
- [ ] A normal (NOERROR) answer event carries its rcode.
- [ ] A multi-question response records every question, not just the first.
- [ ] In the coverage ledger, an empty-answer response counts as `event`, not `no_disclosure`.
- [ ] Tests drive `process(pkt)` with scapy `DNS(qr=1, rcode=...)` packets and assert the emitted events; a malformed response yields nothing and does not crash.

## Blocked by
None — can start immediately.
