# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`netmon` command with subcommands** — a console entry point (`pip`/`uv`
  installable) replaces the long `sudo $(command -v uv) run netmon.py` form.
  `netmon run` opens the live TUI; `netmon run --log` also persists the record;
  `netmon run --headless` gives the classic stdout stream; `netmon update` pulls
  the latest revision and re-syncs deps (refusing a dirty tree); `netmon service`
  drives the background recorder via systemd. The historical `python netmon.py
  [flags]` form is preserved byte-for-byte.
- **`install.sh`** — a reviewable one-command installer: clones to `/opt/netmon`,
  builds an isolated uv-managed venv, installs a `netmon` launcher (which re-execs
  under sudo only when live capture needs `CAP_NET_RAW`), and — with
  `--enable-service` — a hardened `netmon.service` that records as a non-root
  `netmon` user holding only `CAP_NET_RAW` via systemd `AmbientCapabilities`.
  `--setcap` enables a passwordless interactive TUI, scoping the capability to the
  `netmon` group (`chmod 0750 root:netmon` on the private interpreter, guarded against
  shared `/usr` targets) rather than every local user; `--uninstall` reverses everything.

- **TUI freeze cues + `y` to copy** — when the live feed freezes (selecting or
  scrolling off the top row = INSPECT, or `space` = PAUSED) the feed border and
  title change colour and a reverse-video FOLLOW/INSPECT/PAUSED badge shows in the
  capture panel, so a frozen feed can no longer be mistaken for a hang; `Esc`
  resumes following alongside `g`. Press `y` to copy the selected packet's detail
  to the clipboard (OSC 52 — reaches the local clipboard even over SSH).

### Changed

- **`netmon run` is ephemeral unless `--log`.** Persisting your DNS/TLS/HTTP
  history to disk is now an explicit opt-in for the new `run` subcommand — bare
  `netmon run` writes nothing. The legacy `python netmon.py`/`--tui` form still
  writes files as before, so existing scripts and the systemd `ExecStart` are
  unaffected.

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

### Fixed

- **Timestamps use the local timezone.** Every timestamp netmon reports — the
  `--tui` feed and detail pane, the JSONL `ts` field, structlog lines, and the run
  directory name — now renders in the local timezone of the host running it,
  instead of UTC. Event and record timestamps keep an explicit ISO 8601 offset
  (e.g. `+08:00`) so they stay unambiguous.

- **Capture crash on malformed packets (`AttributeError`).** A truncated or
  malformed packet on a DNS port is accepted by the parser but raises when a
  record field is read, which killed the capture worker — taking the `--tui`
  dashboard down with it, and crashing the headless path too. Packet processing
  is now resilient: any parser failure is caught and counted as `parse_failed`
  (`packet`) in the coverage summary instead of aborting the run, so one bad
  packet can no longer stop monitoring. DNS/LLMNR question parsing was
  additionally hardened to never mistake a resource record for a question.

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
