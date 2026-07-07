# Slice 5 — LLMNR / NBNS name-resolution capture

Labels: ready-for-agent

## Parent
`00-PRD-capture-gaps.md` — Close the remaining capture gaps.

## What to build
Capture LAN name-resolution leaks that are not scapy's DNS layer. Recognise the
LLMNR (udp/5355) and NBNS (udp/137) query layers and emit name-query events
(new `llmnr` and `nbns` kinds) carrying the queried hostname, routed to their
own JSONL file(s). These currently fall through to a bare flow with the queried
name never decoded.

## Acceptance criteria
- [ ] An LLMNR query emits an `llmnr` event carrying the queried name.
- [ ] An NBNS name query emits an `nbns` event carrying the queried name.
- [ ] The new kinds are routed to their own JSONL file(s) via `KIND_TO_FILE`.
- [ ] In the coverage ledger these packets count as `event` rather than `no_disclosure`.
- [ ] Tests drive `process(pkt)` with scapy LLMNR/NBNS packets; a malformed one yields nothing and does not crash.

## Blocked by
None — can start immediately.
