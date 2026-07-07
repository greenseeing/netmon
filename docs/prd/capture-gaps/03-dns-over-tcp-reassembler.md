# Slice 3 — DNS-over-TCP reassembler

Labels: ready-for-agent

## Parent
`00-PRD-capture-gaps.md` — Close the remaining capture gaps.

## What to build
A DNS-over-TCP reassembler — a sibling of `TcpReassembler`/`QuicReassembler`,
the one new internal seam in this effort. When a TCP stream is length-prefixed
DNS (2-byte length + DNS message), assemble the message across segments and feed
the whole thing to the DNS response parser, so large answers (AXFR/IXFR, big
DNSSEC/TXT/RRset) that span more than one segment are captured instead of parsed
only if they fit one segment. Bounded like the existing reassemblers, with
evictions routed to the Coverage ledger.

## Acceptance criteria
- [ ] A DNS/TCP answer split across two or more TCP segments parses once, whole.
- [ ] The reassembler has its own direct unit-test class (feed segments, assert the assembled message), mirroring `TestTcpReassembler`.
- [ ] Per-flow and total byte caps bound memory; a clear/eviction increments the Coverage ledger's `evicted` counts.
- [ ] A single-segment DNS/TCP answer still parses (no regression).

## Blocked by
- Slice 1 (DNS response outcomes) — reuses the response parser.
