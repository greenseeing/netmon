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
  resumes following alongside `g`. Press `y` to copy the selected packet's
  detail to the clipboard: a local session copies through a clipboard tool
  (`wl-copy`/`xclip`/`xsel`/`pbcopy`/`clip.exe`), which is confirmable and works
  through `tmux`/`screen`; SSH/remote sessions fall back to OSC 52. The toast
  reports which path was taken instead of always claiming success, and each
  attempt logs a `clipboard_copy` event.

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

- **A missing `-r` pcap fails cleanly instead of crashing.** Pointing `netmon -r`
  at a nonexistent file crashed the pcap reader mid-run with a Python traceback,
  after already creating an empty run directory. The path is now validated up front:
  a missing capture file logs `pcap_not_found` and exits 1 without creating a run
  directory.

- **Flow direction and scope read the address class, not just this host's IPs.** A
  connection was `outbound`/`inbound` only when one end was a configured local IP,
  otherwise `transit` — so a loopback or LAN-to-LAN connection was emitted **twice**
  (both legs looked outbound), a multicast frame a peer sent was mislabelled
  `transit`, and loopback, link-local and carrier-grade NAT (`100.64/10`) addresses
  were all flattened into `lan`. Direction now anchors on address class
  (private/link-local/loopback, or one of this host's own IPs): private→internet is
  `outbound`, internet→private is `inbound`, both-local (loopback, LAN↔LAN, LAN
  multicast) is a new `local` direction that deduplicates a connection's two legs
  into one event, and internet↔internet stays `transit`. `scope` gains `cgnat`,
  `linklocal` and `loopback`, so carrier NAT and link-local no longer masquerade as
  your LAN. This also fixes a mirror/SPAN deployment, which now classifies LAN peers
  it does not own.

- **A reused IP is named for the site you most recently visited.** The IP→hostname
  ledger kept the first name an address was ever seen with, so a shared or CDN edge
  that later served a different site mislabeled every subsequent flow with the stale
  first name (an early `imgs.example.com` shadowing a later `login.bank.com`).
  Attribution is now last-writer-wins: a newer DNS answer or SNI re-attributes the
  address, tracking CDN/DHCP reuse by temporal locality and self-healing after a
  one-off wrong answer. The per-flow `hostname` stays a best-effort hint — the
  authoritative per-connection SNI is in `tls.jsonl` — and an RA's RDNSS placeholder
  never overwrites a real learned name.

- **DNS-over-TCP no longer goes blind on a long-lived connection.** The
  DNS-over-TCP reassembler capped a stream by its *cumulative* bytes and never freed
  a message once parsed, so a persistent connection — an Android "Private DNS" (DoT)
  device multiplexes its entire lookup stream over one connection — stopped
  surfacing every query and answer after the first ~64 KB. The reassembler is now a
  sliding window: each whole message is dropped once yielded and the buffer advances,
  so the per-flow cap bounds only the in-flight partial message. One connection can
  carry unbounded lookups without falling silent; the cap is sized to hold any single
  maximum-length message; reordered or overlapping segments compact without corrupting
  the buffer; and reassembly is now linear rather than quadratic in the stream length.

- **The always-on recorder survives a full disk.** Writing the JSONL record and the
  exit summary was unguarded, so an `ENOSPC` on the disk the recorder itself fills
  with history propagated out of the capture loop and crashed the run — which, under
  the systemd unit's `Restart=on-failure`, became a crash loop. The writer now
  degrades instead: the first write error stops persistence (a one-way latch — no
  churn retrying a full disk), every subsequent event is counted, and the run keeps
  capturing so the live view and coverage ledger stay up. This holds for both the
  headless recorder and interactive `netmon run --log` (whose diagnostic log lives on
  the same disk — the degrade path's own error logging is now failure-tolerant), and
  a disk already full at startup degrades to a no-op writer rather than crashing
  before the run begins. The exit summary carries `persistence.events_dropped`, so a
  truncated record is visibly incomplete rather than a silent gap. The
  `O_EXCL|O_NOFOLLOW` symlink refusal (CWE-59) is re-raised, never swallowed by the
  degrade path.

- **Silent packet drops no longer masquerade as "no disclosure".** The coverage
  ledger's promise is that a clean log is never a silent gap, but two classes of
  undecodable traffic slipped through it. An IP/IPv6 fragment was tallied as
  `no_disclosure` (or `unhandled:<proto>`), and a datagram that looked like DNS by
  shape yet failed to fully parse was lost the same way, so the summary could read
  clean while a real DNS answer had vanished. A fragment's L4 payload can't be
  reassembled (that stays a documented out-of-scope gap), but a first fragment still
  carries the connection's L4 header, so its flow — who contacted whom — is now
  recorded as before; only the unreadable payload is skipped. A fragment that yields
  no event (a later, header-less fragment, or a repeat of an already-seen flow) lands
  under a distinct `ip_fragment` fate, and a plausible-but-unparseable DNS message is
  counted in the coverage summary's `parse_failed.dns`, beside the existing QUIC and
  packet counters.

- **Non-DNS traffic on ports 53/5353 reported as bogus `dns_query`.** scapy binds
  a DNS layer to UDP 53 and 5353 by port number alone, so any non-DNS datagram
  squatting there (BitTorrent DHT, QUIC, scans, spoofed packets) was force-decoded
  into a DNS message with a garbage `qname` and `qtype` and surfaced as a
  `dns_query`. DNS is now recognised by message shape on every port — the same
  validation already used on unbound ports — instead of trusting scapy's port
  binding, so junk on the DNS ports is dropped while genuine DNS and mDNS are
  unaffected.

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
