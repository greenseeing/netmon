# Slice 1 — TcpReassembler: overlap & out-of-order for SNI

Labels: ready-for-agent

## Parent
`00-PRD-audit-hardening.md` — Harden the leak audit.

## What to build
Make `TcpReassembler` (which reassembles the client→server stream carrying the
TLS ClientHello / HTTP request) tolerant of reordered and overlapping TCP
segments, the same way slice `734d5ab` made the DNS-over-TCP reassembler robust.
Today `TcpReassembler.add` (`netmon.py` ~1105) keys chunks by absolute offset
first-writer-wins and `_reassemble` stops at the first gap, so: (a) if the
*second* segment of a split ClientHello arrives before the first, the first is
discarded by the `_client_stream_start` gate and the SNI is never captured; and
(b) an overlapping retransmit repacketized at a different boundary loses bytes.
Buffer segments regardless of arrival order until the opening `_client_stream_start`
segment anchors the stream, and resolve overlaps by a defined rule (first-data-wins
for the contiguous prefix, matching the DoT fix), so a reordered ClientHello still
yields its SNI.

## Acceptance criteria
- [ ] A ClientHello split across two segments delivered **out of order** (second
      then first) still parses and emits its `tls_sni`.
- [ ] An overlapping/repacketized retransmit does not corrupt the assembled bytes
      or drop the SNI (mirror the DoT overlap regression test).
- [ ] A direct unit-test class feeds reordered/overlapping segments and asserts the
      whole ClientHello, alongside the existing in-order cases (no regression).
- [ ] Memory stays bounded per the existing per-flow/total caps.

## Blocked by
None — can start immediately. Reuses the compaction pattern proven in `734d5ab`.
