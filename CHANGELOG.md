# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Live dashboard (`--tui`)** — an opt-in btop-style terminal view built on
  Textual (install with `uv sync --extra tui`). A single colour-coded feed shows
  every DNS/SNI/HTTP/flow event as it happens (kind, direction, host, detail),
  with side panels for top hosts, per-kind counts, an events/sec sparkline, and
  live capture health (queue depth, kernel/userspace drops), plus a selectable
  detail pane. Columns resize to fit any terminal width, and the feed follows the
  newest event at the top; scrolling down or selecting a row freezes it to read
  history (`g` resumes following), with `space` to pause and `f` to filter. JSONL
  logging continues underneath; the headless, `-q`, and systemd paths are unchanged
  and need no Textual installed.

## [0.1.0] – Initial public release

Passive network monitor that logs, as timestamped JSONL, what a host discloses on
the wire:

- **DNS** — queries and answers (A/AAAA/CNAME/…), HTTPS/SVCB records with
  SvcParams, response outcomes (NXDOMAIN/NODATA/SERVFAIL/REFUSED), authority and
  additional sections, EDNS Client Subnet, and DNS-over-TCP reassembly. Plaintext
  DNS is recognised by message shape, not just port 53.
- **TLS** — SNI and ALPN from the ClientHello of every HTTPS connection, over both
  TCP and decrypted QUIC Initials (v1 and v2), with ECH cover-name flagging.
- **HTTP** — plaintext method/path/Host/User-Agent, with captive-portal probe
  tagging.
- **Flows** — every connection with protocol, direction, endpoints, service guess,
  reverse-mapped hostname, scope, and disclosure notes; pre-existing connections
  are inventoried on first sight.
- **LAN & non-IP** — LLMNR/NBNS, ICMPv6 Router Advertisements (RDNSS), and ARP.
- **Coverage ledger** — every packet is accounted under exactly one fate, and each
  bounded structure reports what it dropped, so the monitor is honest about its own
  blind spots.
