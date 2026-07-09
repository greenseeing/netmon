# Slice 2 — Reassembler eviction: clear-all → per-flow LRU

Labels: ready-for-agent

## Parent
`00-PRD-audit-hardening.md` — Harden the leak audit.

## What to build
When the total byte cap is exceeded, `TcpReassembler` and `DnsTcpReassembler`
(`netmon.py` ~1118, ~1187) call `self._flows.clear()` and `QuicReassembler`
(~859) calls `self._crypto.clear()` — a single burst of many concurrent
in-progress streams wipes **every** in-flight ClientHello/CRYPTO stream at once,
dropping many SNIs together. This is also attacker-triggerable for QUIC: Initial
keys are publicly derivable, so a flood of distinct DCIDs forces periodic full
wipes that discard legitimate multi-Initial (post-quantum) ClientHellos
mid-reassembly. Replace clear-all with **per-flow LRU eviction** (evict the
oldest stream(s) until under cap), matching the `LruSet`/`NameLedger` pattern
the rest of the codebase already uses, so a burst ages out idle flows instead of
the one being processed.

## Acceptance criteria
- [ ] Exceeding the total cap evicts the least-recently-updated stream(s), not all
      of them; a hot/in-progress stream survives a burst of new ones.
- [ ] Applies consistently to `TcpReassembler`, `DnsTcpReassembler`, and
      `QuicReassembler`.
- [ ] Evictions still increment the `cleared`/coverage eviction counters.
- [ ] Unit tests: a burst past the cap keeps the most-recent in-progress stream and
      evicts the oldest; the QUIC flood case keeps a legitimate concurrent Initial.

## Blocked by
None — can start immediately.
