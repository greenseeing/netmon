# Slice 7 — TLS 1.2 server-cert SAN as a fallback destination (+ ADR)

Labels: ready-for-agent

## Parent
`00-PRD-audit-hardening.md` — Harden the leak audit.

## What to build
On the still-common TLS 1.2 path the server's certificate — with its SANs —
crosses the wire in cleartext during the handshake; TLS 1.3 encrypts it. netmon
currently parses only the client's ClientHello, so it misses destinations on
connections where it never saw the SNI: TLS 1.2 connections and streams it joined
mid-flight. Parse the server→client `Certificate` message and extract SANs (via
`cryptography.x509`, already a dependency), feed recovered names into the
`NameLedger`, and surface them so a destination netmon otherwise misses is
recovered. **Locked scope: cert-SAN only — no JA3/JA4.** This reopens the README's
stated scope, so record it as an ADR.

## Acceptance criteria
- [ ] A TLS 1.2 handshake pcap yields the server-cert SAN name(s); the `NameLedger`
      is seeded so a later flow to that IP is named.
- [ ] Uses the server→client reassembler (the Certificate message spans segments);
      malformed/truncated certs yield nothing and do not crash.
- [ ] JA3/JA4 remain out of scope.
- [ ] `docs/adr/0001-reopen-cert-san-scope.md` records *why* (recovers missed
      destinations) and *why JA3/JA4 stays out* (client-identity axis, ASN.1 /
      attack-surface cost); the README "What this tool does NOT show you" section is
      updated to reflect cert-SAN now captured.

## Blocked by
Server→client reassembly robustness — benefits from slices 1 and 2 landing first.
