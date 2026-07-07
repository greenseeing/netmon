# Slice 4 — Framing-based QUIC recognition (DoQ + alt-port HTTP/3)

Labels: ready-for-agent

## Parent
`00-PRD-capture-gaps.md` — Close the remaining capture gaps.

## What to build
Recognise QUIC by its long-header framing rather than by destination port. Feed
the `QuicReassembler` on any UDP datagram whose payload is a QUIC long-header
Initial, not only `dport == 443`, so DNS-over-QUIC (udp/853) and HTTP/3 on
alternate ports yield their ClientHello SNI/ALPN/ECH as `tls_sni` events with
`transport=quic`. The port becomes a hint, not a gate; non-QUIC UDP is untouched.

## Acceptance criteria
- [ ] A QUIC Initial on udp/853 (DoQ) yields a `tls_sni` event with `transport=quic`.
- [ ] A QUIC Initial on an alternate port (e.g. udp/8443) yields a `tls_sni` event.
- [ ] A non-QUIC UDP datagram still yields only its flow event (no false decode, no crash).
- [ ] Port-443 behaviour is unchanged (existing QUIC tests still pass).

## Blocked by
None — can start immediately.
