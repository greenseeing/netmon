# Slice 2 — DNS authority & additional sections (EDNS/ECS, glue, SVCB)

Labels: ready-for-agent

## Parent
`00-PRD-capture-gaps.md` — Close the remaining capture gaps.

## What to build
Read the authority (`dns.ns`) and additional (`dns.ar`) sections of a DNS
response, not just the answer section. Decode EDNS OPT records including Client
Subnet (ECS) so the leaked client subnet is surfaced; surface SOA/NS from the
authority section; surface glue A/AAAA and SVCB/HTTPS records placed in the
additional section (the SVCB path reuses the existing `DnsHttpsEvent`). Glue
addresses seed the name ledger.

## Acceptance criteria
- [ ] An OPT record carrying EDNS Client Subnet surfaces the client subnet disclosure.
- [ ] An HTTPS/SVCB record in the additional section produces a `dns_https` event with its hints/alpn/ech.
- [ ] Glue A/AAAA records in the additional section seed the `NameLedger` (a later flow to that IP is named).
- [ ] SOA/NS records in the authority section are surfaced.
- [ ] Tests drive `process(pkt)` with responses whose disclosure lives only in ns/ar; answer-only responses are unaffected.

## Blocked by
- Slice 1 (DNS response outcomes) — shares the response-parsing path.
