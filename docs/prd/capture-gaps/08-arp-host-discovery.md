# Slice 8 — ARP host-discovery capture

Labels: ready-for-agent

## Parent
`00-PRD-capture-gaps.md` — Close the remaining capture gaps.

## What to build
Decode ARP frames — currently dropped at ingress as `non_ip` — into an `arp`
event that records who-has/is-at with the sender and target IP+MAC, making LAN
host discovery visible. Bound the state with `LruSet` so a broadcast ARP storm
cannot grow memory, with evictions routed to the Coverage ledger.

## Acceptance criteria
- [ ] An ARP request (who-has) emits an `arp` event with sender IP/MAC and target IP.
- [ ] An ARP reply (is-at) emits an `arp` event with the resolved IP↔MAC binding.
- [ ] Repeated identical ARP within the bound is deduplicated; dedup uses `LruSet` and evictions increment the Coverage ledger.
- [ ] The frame leaves the `non_ip` fate for `event` in the coverage ledger.
- [ ] The `arp` kind is routed to its own JSONL file via `KIND_TO_FILE`.

## Blocked by
None — can start immediately.
