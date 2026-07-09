# Slice 5 — Raw pcap evidence sink

Labels: ready-for-agent

## Parent
`00-PRD-audit-hardening.md` — Harden the leak audit.

## What to build
netmon can *read* a pcap (`ReplayCapture`, `-r`) but cannot *write* one. For a
leak audit you often want to preserve the raw bytes so a finding can be
re-examined later with tshark/Wireshark for the signals netmon deliberately does
not compute (JA3/JA4, cert timing) — JSONL is lossy and derived. Add an opt-in raw
capture sink (scapy `PcapWriter`) that writes captured packets alongside the JSONL
record, behind a new capture flag, size-capped and honouring the same private
(0600) file discipline as `JsonlWriter`. Pairs with slice 08 (rotation) so an
always-on recorder's pcap does not grow unbounded.

## Acceptance criteria
- [ ] A new opt-in flag (e.g. `--pcap`) writes captured packets to a `.pcap` in the
      run directory; without it, nothing is written (default off).
- [ ] The pcap file is created owner-only (0600) via the `open_private_new`
      discipline, and a write failure degrades like the JSONL writer (no crash).
- [ ] `netmon -r <in.pcap> --pcap` round-trips (read then re-write) without
      corrupting packets.
- [ ] README documents the flag and the evidence-preservation use case.

## Blocked by
None — can start immediately; integrates with slice 08 for size-capping.
