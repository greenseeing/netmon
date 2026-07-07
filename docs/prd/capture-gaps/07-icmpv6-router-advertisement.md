# Slice 7 — ICMPv6 Router Advertisement disclosure

Labels: ready-for-agent

## Parent
`00-PRD-capture-gaps.md` — Close the remaining capture gaps.

## What to build
Decode ICMPv6 Router Advertisements — currently dropped as `unhandled:icmpv6` —
into an `icmp6_ra` event that surfaces what the network advertises: the announced
prefix(es), the router (source) address, and any RDNSS (recursive DNS server)
option. The RDNSS address seeds the `NameLedger` so later flows to that resolver
are named.

## Acceptance criteria
- [ ] An RA carrying a prefix and an RDNSS option emits an `icmp6_ra` event recording the router, prefix, and RDNSS address(es).
- [ ] The RDNSS address seeds the `NameLedger`.
- [ ] The `icmp6_ra` kind is routed to its own JSONL file via `KIND_TO_FILE`.
- [ ] The packet leaves the `unhandled:icmpv6` fate for `event` in the coverage ledger.
- [ ] Tests drive `process(pkt)` with a scapy ICMPv6 RA; a malformed RA yields nothing and does not crash.

## Blocked by
None — can start immediately.
