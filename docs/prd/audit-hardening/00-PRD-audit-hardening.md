# Harden the leak audit: reassembler robustness, recorder ops, evidence & query

Labels: ready-for-agent

## Problem Statement
An architecture review (2026-07-09) comparing netmon to Wireshark, plus three
adversarial code audits, closed the highest-severity gaps. The remaining findings
are lower-severity but real: the TCP-stream and QUIC reassemblers still mishandle
reordered/overlapping segments and evict by wiping everything; a multi-record
ClientHello is misparsed; the local-address set is a one-shot snapshot; the
recorder has no in-run rotation and thin systemd sandboxing; tunnel interfaces are
silently `non_ip`; several operator-facing CLI paths are untested; and the tool
can neither preserve raw evidence nor query its own recorded logs. This PRD turns
those into independently-grabbable slices.

## Already shipped (branch `fix/coverage-ledger-honesty`)
- Coverage-ledger honesty — fragments / unparseable DNS no longer masquerade as
  `no_disclosure` — `c54d99f`
- Recorder survives a full disk (degrade, not crash-loop) — `2db588a`
- DNS-over-TCP sliding-window reassembler (DoT no longer blind after 64 KB) — `734d5ab`
- NameLedger last-writer-wins (correct CDN/shared-IP naming) — `80f8021`
- Address-class flow direction & scope (`local` direction; cgnat/linklocal/loopback) — `c15c122`

## Locked decisions (do not re-litigate)
- Flow "local" model = hybrid address-class (private/link-local/loopback OR own IP).
- Candidate E fingerprint scope = **cert-SAN only** (recover missed destinations);
  **no JA3/JA4**; the scope reopen is recorded via the ADR in slice 07.

## Slices
See `01`…`11` in this directory. Independently grabbable: all except `07` (adds an
ADR step). Reassembler group: `01`, `02`, `03`. Recorder-ops group: `08`, `09`,
`10`, `11`. Capabilities group: `05`, `06`, `07`.

## Out of scope
Per README "What this tool does NOT show you" / the capture-gaps PRD: traffic-analysis
statistics, JA3/JA4 fingerprints, the IPv6 EUI-64 MAC-derivation flag, IP-layer
defragmentation *decoding*, decryption needing session secrets (DoH bodies, QUIC/TLS
application data), and QUIC versions beyond v1/v2.
