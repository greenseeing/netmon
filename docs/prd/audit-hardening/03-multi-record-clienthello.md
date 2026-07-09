# Slice 3 — Multi-record TLS ClientHello reassembly

Labels: ready-for-agent

## Parent
`00-PRD-audit-hardening.md` — Harden the leak audit.

## What to build
`parse_client_hello` (`netmon.py` ~619) reads exactly one TLS record length from
`payload[3:5]` and hands `payload[5:]` to the handshake parser. A ClientHello that
exceeds the 16384-byte record limit (post-quantum key shares increasingly do) is
fragmented across two or more TLS records; the current code then treats the second
record's 5-byte header as handshake body, shifting every SNI/ALPN offset and
reading garbage. Reassemble consecutive handshake (`0x16`) records into one
handshake message — concatenating record payloads and stripping each record header
— before dissecting, so a multi-record ClientHello yields its true SNI/ALPN/ECH.

## Acceptance criteria
- [ ] A ClientHello spanning two TLS records parses to the correct SNI and ALPN.
- [ ] A single-record ClientHello still parses (no regression); a non-`0x16` record
      after the handshake is not mistakenly concatenated.
- [ ] Works on both the TCP path (`parse_client_hello`) and, where relevant, the
      QUIC CRYPTO path (already message-oriented, so confirm no double handling).
- [ ] Unit tests build a two-record ClientHello and assert the extracted fields.

## Blocked by
None — can start immediately. Pairs naturally with slice 1.
