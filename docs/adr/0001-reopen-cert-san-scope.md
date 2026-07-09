# ADR 0001 — Reopen the fingerprint scope for TLS 1.2 certificate SANs (and only those)

Date: 2026-07-09
Status: accepted

## Context

The README's "What this tool does NOT show you" section declared server
certificates out of scope, alongside JA3/JA4 client fingerprints. The
capture-gaps PRD locked that scope ("candidate E: no fingerprinting").

Two audit findings reopened the question for the certificate half only. On the
still-common TLS 1.2 path the server's certificate — with its SubjectAltName
DNS entries — crosses the wire in cleartext during the handshake. netmon
parses only the client's ClientHello, so it misses the destination name
whenever it never saw an SNI: TLS 1.2 clients that omit it, and any stream
netmon joined mid-flight after the ClientHello had already passed. Those are
exactly the flows a leak audit must still name — the data left the host either
way.

## Decision

Parse the server→client TLS 1.2 `Certificate` handshake message, extract the
leaf certificate's SAN DNS names via `cryptography.x509`, and seed the
`NameLedger` with one name per server IP — `observe_if_absent`, so a
certificate name only ever fills a gap and never overwrites a name learned
from DNS or SNI. No new event kind: the recovered name surfaces as the
`hostname` on subsequent flow events, like every other ledger name.

JA3/JA4 stays out of scope. It sits on the client-identity axis — it
fingerprints the *browser*, not the *destination* — and netmon is a leak
auditor: it answers "where did my data go", not "who do I look like". Naming a
destination the audit would otherwise miss serves that mission; classifying
the local client does not.

Accepted cost: this parses attacker-supplied ASN.1/DER from the wire. It is
confined to `cryptography`'s Rust-backed parser, only the leaf certificate is
touched, and every parse runs under the processor's blanket
one-bad-packet-never-kills-the-capture guard; a malformed or truncated
certificate yields nothing.

## Consequences

- TLS 1.2 destinations are named even without a captured SNI; TLS 1.3
  encrypts the certificate, so nothing changes there — noted in the README.
- The scope ledger is honest again: the README's NOT-shown list no longer
  claims certificates are unread.
- Any future fingerprinting proposal (JA3/JA4 included) needs a new ADR
  arguing from the leak-audit mission, not a quiet scope creep.
