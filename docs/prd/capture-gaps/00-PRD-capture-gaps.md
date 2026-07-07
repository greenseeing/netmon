# Close the remaining capture gaps: non-TCP/UDP disclosure, framing-based recognition, complete DNS responses

Labels: ready-for-agent

## Problem Statement
I run netmon to see exactly what my host leaks to the network. Even with the new
coverage ledger telling me *how many* packets it couldn't turn into events, it
still shows me nothing about whole classes of traffic sitting on the wire in
front of it:
- Anything that isn't TCP/UDP-over-IP — ARP host discovery, ICMPv6 Router
  Advertisements that hand out the network prefix, gateway and DNS servers.
- QUIC and DNS spoken on non-standard ports — DNS-over-QUIC (udp/853), HTTP/3 on
  alternate ports, LLMNR/NBNS LAN name-resolution leaks, split-horizon resolvers.
- The non-answer parts of a DNS response — whether a query was refused or
  redirected (NXDOMAIN/SERVFAIL), and EDNS Client-Subnet / glue / SVCB records
  carried in the authority and additional sections.
The ledger now *counts* some of these as `unhandled`, but I can't *see what they
disclose*, so my leak audit still has silent blind spots on the LAN and on any
non-standard port.

## Solution
Teach netmon to recognise traffic by its framing rather than its port, to decode
the disclosure-bearing non-TCP/UDP protocols, and to parse a DNS response as a
whole. After this, the leak audit has no silent blind spots for the named
classes: LAN discovery (ARP/RA/LLMNR/NBNS), non-standard-port QUIC/DNS, and DNS
outcomes (refused/redirected, subnet-leaked) all appear as events, and the
coverage ledger's `unhandled`/`no_disclosure` counts visibly shrink as those
packets become named disclosures.

## User Stories
1. As an operator, I want ARP who-has/is-at frames captured, so that I can see every host discovering peers on my LAN.
2. As an operator, I want ICMPv6 Router Advertisements decoded, so that I learn the prefix, gateway and RDNSS the network is advertising.
3. As an operator, I want the RDNSS from an RA seeded into the name ledger, so that later flows to those resolvers are named.
4. As an operator, I want DNS-over-QUIC on udp/853 to yield its SNI, so that encrypted-DNS destinations are not invisible just because they use QUIC.
5. As an operator, I want HTTP/3 on alternate ports (e.g. 8443) parsed for SNI, so that alt-port QUIC destinations are captured like port-443 ones.
6. As an operator, I want QUIC recognised by its long-header framing, so that recognition no longer depends on a hard-coded port.
7. As an operator, I want LLMNR queries captured, so that Windows/desktop LAN hostname leaks are visible.
8. As an operator, I want NBNS name queries captured, so that legacy NetBIOS name leaks are visible.
9. As an operator, I want plaintext DNS on non-standard ports captured, so that local forwarders / dnscrypt-proxy on custom ports are not missed.
10. As an operator, I want a DNS response with an empty answer section still recorded with its rcode, so that NXDOMAIN/NODATA/SERVFAIL outcomes are not silently dropped.
11. As an operator, I want to see that a host asked and was refused/redirected, so that I can detect DNS filtering and blocklists.
12. As an operator, I want the rcode on every DNS response, so that I can distinguish success from failure.
13. As an operator, I want EDNS Client-Subnet (ECS) options decoded, so that I can see my client subnet being leaked to authoritative servers.
14. As an operator, I want authority-section SOA/NS records surfaced, so that referrals and negative answers carry their provenance.
15. As an operator, I want additional-section A/AAAA glue and SVCB records surfaced, so that pre-connection IP/ALPN/ECH disclosures placed there are not skipped.
16. As an operator, I want every question in a multi-question response recorded, so that I do not lose all but the first.
17. As an operator, I want large DNS-over-TCP answers (AXFR, big DNSSEC/TXT) reassembled across segments, so that answers spanning more than one segment are not lost.
18. As an operator, I want each new disclosure type deduplicated under memory bounds, so that an RA/ARP/LLMNR flood cannot grow state unbounded.
19. As an operator, I want the coverage ledger to show these packets moving from `unhandled`/`no_disclosure` into named kinds, so that I can confirm the blind spot closed.
20. As an operator, I want the new event kinds written to their own JSONL files, so that the run directory stays organised by disclosure type.
21. As an operator running on a mirrored/transit port, I want LAN-discovery and non-standard-port disclosures captured in transit direction too, so that a bridged deployment sees them.
22. As an operator, I want documentation of what is now captured vs still out of scope, so that I keep an honest picture of the leak surface.

## Implementation Decisions
- **Single external seam.** All work stays behind `PacketProcessor.process(pkt) -> list[Event]`. New disclosure types are new `Event` subtypes built by new `_*_events` helpers that mirror `_dns_events`/`_sni_event`, routed to files via `KIND_TO_FILE`.
- **04 — non-TCP/UDP decoding.** Add decoding for the disclosure-bearing protocols the ledger currently records as `unhandled`/`non_ip`: ARP (who-has/is-at → new `arp` kind), ICMPv6 Router Advertisement (prefix/router/RDNSS → new `icmp6_ra` kind). RDNSS seeds the `NameLedger`. Decoded protocols migrate out of the `unhandled:<proto>` fate into their own kind; the accounting half already shipped with the Coverage ledger.
- **05 — framing over port.** Recognise QUIC by long-header framing on any UDP datagram (feed `QuicReassembler` regardless of `dport`), so DoQ (udp/853) and alt-port HTTP/3 yield SNI. Recognise DNS/LLMNR/NBNS by their scapy layer regardless of port. Dispatch is a small recognition step at the top of the udp branch; the port becomes a hint, not a gate.
- **06 — whole DNS response.** Parse `rcode` and iterate all questions; read the authority (`dns.ns`) and additional (`dns.ar`) sections (EDNS OPT/ECS, SOA/NS, glue A/AAAA, SVCB). Emit a response record even when the answer section is empty (carrying rcode). SVCB/glue in the additional section reuses the existing `DnsHttpsEvent` path. Add a **DNS-over-TCP reassembler** (new internal seam, sibling of `TcpReassembler`) invoked when a client→server TCP stream is length-prefixed DNS.
- **Event model.** `DnsAnswerEvent` gains `rcode` (and section provenance) or a sibling `DnsResponseEvent` is introduced for the empty-answer/outcome case — decided during slice 1. New kinds `arp`, `icmp6_ra`, `llmnr`, `nbns` each get a `KIND_TO_FILE` entry.
- **Bounding.** New per-key state (ARP/ND/name-query dedup) reuses `LruSet`; new counters route through the existing `Coverage` ledger so evictions stay accounted.

## Testing Decisions
- **Test through the highest seam.** Drive `process(pkt)` with scapy-built packets (`Ether()/IP()/...`) and assert on the returned `Event` list and on `summary()["coverage"]` deltas — external behaviour only, never implementation details. This matches every existing processor test.
- **Reassembler tested directly.** The DNS-over-TCP reassembler gets its own unit class like `TestTcpReassembler`/`TestQuicSniExtraction` (feed segments, assert the whole answer).
- **A good test** states the on-the-wire bytes and asserts the disclosure that must surface (e.g. "a udp/853 QUIC Initial yields a `tls_sni` with transport=quic"), plus a negative (a malformed/short packet yields nothing and no crash).
- **Prior art:** `TestDnsEvents`, `TestDnsHttpsRecords`, `TestQuicViaProcess`, `TestTcpReassembler`, `TestCoverageLedger`.

## Out of Scope
- Decrypting anything needing session secrets (QUIC 0-RTT/1-RTT app data, TLS application data, DoH bodies).
- IP-layer defragmentation (a distinct effort; remains a documented gap).
- QUIC versions beyond the v1/v2 salts already supported.
- Full ICMP/ICMPv6 error inner-packet extraction (only RA is in scope here; ND/errors optional follow-ups).

## Further Notes
The Coverage ledger shipped in the previous change already records the fate of
every packet these candidates target, so each slice has a built-in before/after
demo: the `unhandled:<proto>` / `no_disclosure` counts drop as the new named
kinds appear.

## Slices
See `issues/01`…`issues/08` in this directory. Independently grabbable: 01, 04,
05, 07, 08. DNS-foundation dependents: 02, 03, 06 (blocked by 01).
