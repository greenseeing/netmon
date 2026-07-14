# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **The dashboard filters with checkboxes instead of a one-at-a-time cycle.** `f` used to
  advance a single substring through `all → dns → tls → http → flow`; you could not ask for
  DNS *and* TLS, you could not ask for "only internet-bound", and four of the twelve recorded
  kinds — `arp`, `icmp6_ra`, `llmnr`, `nbns` — could not be selected **at all**. `f` now opens
  a filter bar with a checkbox per kind, direction and scope: OR within a group, AND across
  them. `a`/`n` tick or clear a group, `esc` closes it. Unticking everything empties the feed
  and says *"no rows match the filter"* — a different fact from *"no events"*, and not one the
  tool will quietly reinterpret. Any active filter is named in the feed's border, for the same
  reason the paused state is: a feed that is hiding events must never read as a quiet network.

  It is an in-place bar rather than a modal because Textual's `App.children` holds only the
  active screen — with a modal pushed, the 10 Hz render loop could no longer find the feed and
  would have stalled for the modal's whole life. `escape` is bound on the bar rather than the
  app, so it closes the filter without also yanking a scrolled-back reader to the newest row.

### Fixed

- **The feed lost keyboard focus to an invisible widget.** Textual's default `AUTO_FOCUS`
  claims the first focusable widget in the DOM, which became a `SelectionList` inside the
  (hidden) filter bar — so `escape` opened the filter instead of following the feed, and the
  arrow keys drove a bar nobody could see. Focus is now stated explicitly rather than left to
  DOM order. Caught by driving the real app, not by a unit test.

- **One filter, shared by the dashboard and `netmon query`.** There were two, agreeing on
  nothing but `event_host()`: the feed cycled a single lowercase substring, and `query` had
  its own flags and its own predicate. Both are now the same `EventFilter` over three closed
  vocabularies — kind, direction, scope — with OR *within* a dimension and AND *across* them.
  `--kind`, `--direction` and `--scope` are repeatable and validated against their vocabulary.

### Changed

- **`netmon query --scope` now classifies the peer of *any* event, not just a flow's.**
  Previously the predicate read `FlowEvent.scope` with `getattr`, so `--scope internet`
  silently matched flows alone — even though the DNS query that named the host and the SNI
  that announced it *are* the disclosure you asked for. It now matches all three. **This is a
  behaviour change**: expect more rows than before, and the right ones.
- **`netmon query --scope local` is now rejected** with the list of valid scopes. `local` is a
  *direction*, not a scope — `remote_scope()` can never return it. The old free-string flag
  accepted it and quietly returned whatever happened to match. (The repo's own query fixture
  had been recording a flow with `scope: "local"`, a value no real capture could produce; the
  closed vocabulary surfaced the lie.)

- **The installer no longer demands uv, and no longer reaches astral.sh by default.**
  `install.sh` could only build a venv with uv, and could only get uv by piping an
  unchecksummed script into a root shell — so the documented one-liner simply failed on a
  host without the Astral toolchain. It now *picks* a builder: uv when it is already
  present (that path is byte-for-byte what it was), otherwise the system `python3` plus
  the hash-pinned `requirements.txt`, and it fetches uv only when the host has no Python
  ≥ 3.13 at all — the one case where uv is the only thing that can *provide* an
  interpreter. `--pip` refuses that fallback outright. When nothing works it now dies with
  a message naming what it found on the host and both remedies, instead of a bare
  `curl: command not found` or a `SyntaxError` three steps later.

  Two details that are load-bearing rather than incidental. The pip venv is built with
  `--copies`: a default venv's `bin/python3` resolves out to `/usr/bin/python3.x`, and
  `maybe_setcap` rightly refuses to arm *that* — so without the copy the pip path would
  have silently lost passwordless capture. And an interpreter is only accepted if it can
  actually `import venv, ensurepip`, because Debian ships those separately: a host can
  have a perfectly new Python that cannot seed a venv, and the failure otherwise surfaces
  as an inscrutable `No module named pip` long after the decision that caused it.
  `maybe_setcap` also swaps its `/usr/*` blocklist for a `$NETMON_DIR/*` allowlist — the
  actual invariant is "the capability lands on a binary we own" — and now smoke-tests the
  armed interpreter, revoking the grant rather than leaving a netmon that cannot start
  (a file capability puts the loader into secure-execution mode, where an interpreter that
  finds libpython via an `$ORIGIN` rpath stops working the moment it is armed).

- **`netmon update` no longer demands uv.** It refused to run unless both `git` and
  `uv` were on PATH, so a pip-built install would have been stranded forever on the
  version it was installed at — which is why this lands before the installer grows a pip
  path, not after. The builder is now read off the venv itself rather than a marker file
  that would need keeping honest: `uv sync` never seeds pip into the venv it creates, so
  a `pip` in `.venv/bin` is an authoritative "the pip path built this". Using the *same*
  builder matters beyond tidiness — re-syncing a pip-built venv with uv would rebuild it
  around a different interpreter and silently drop the `cap_net_raw` grant on the current
  one, turning passwordless capture off with nothing said. The update plan is resolved
  *before* the pull, so an install with no usable builder fails while it is still
  consistent instead of being left pulled-but-unbuilt; the editable reinstall now runs
  only when `pyproject.toml` actually moved, since otherwise every no-op update would
  reach out to PyPI for the build backend — a real regression against `uv sync`'s no-op.
  A diff that cannot be computed reinstalls anyway: a skipped rebuild is a silently stale
  entry point, a redundant one merely costs time.

- **netmon can be installed with nothing but Python and pip.** The install path
  required uv, and got it by piping `astral.sh/uv/install.sh` into `sh` as root — a
  step install.sh's own header calls an unchecksummed trust boundary. A user running
  the documented one-liner on a machine without the Astral toolchain could not install
  netmon at all. A generated `requirements.txt` is now checked in, exported from
  `uv.lock` with the `tui` extra and full `--hash` pins, so
  `pip install --require-hashes -r requirements.txt` gives the same integrity guarantee
  `uv sync` does — which matters most to the person who declined the unchecked download
  in the first place. The file is never hand-edited: `uv export` writes its own
  invocation into the header, and `tests/test_packaging.py` reads that command back out
  and re-runs it, so the artifact documents how it is made and the test executes that
  documentation. There is no CI here, so every generated artifact gets a test that fails
  when it drifts.

### Fixed

- **A junk SNI could be read out of encrypted bytes, and then crash the TUI.** An
  overnight run emitted a `tls_sni` event for a DNS-over-TLS flow whose `sni` held
  ~200 bytes of ciphertext, which then killed the dashboard with a `MarkupError`.
  Three defects composed, each now closed independently:
  - The `server_name` extension walk never read the `name_type` byte and bounded the
    host name by the whole handshake message instead of the extension's own length, so
    a coincidental `0x0000` extension in ciphertext yielded a 200-byte "SNI". The walk
    now follows RFC 6066 §3 and is bounded by `elen`, exactly as `_parse_alpn` already
    was, and every name passes a new `Hostname` value type — an allowlist grammar
    (strict-ASCII, LDH + underscore, label ≤63, name ≤253) shared with certificate SAN
    dNSNames. A name netmon cannot prove is a hostname is no longer a name. Validation
    only: case and IP literals reach `tls.jsonl` as sent.
  - A mid-stream TCP segment could false-anchor the reassembler, which then never gave
    up on the flow — re-parsing a growing 64 KB buffer on every segment until FIN, and
    squatting on the LRU budget that genuine pending ClientHellos need. The anchor gate
    is now tri-state (`StreamStart`): a prefix too short to settle the question anchors
    provisionally and is *confirmed* once the bytes arrive, so an evasive three-byte
    first segment still anchors (the HTTP side gains the same resistance) while a
    disconfirmed guess gives the flow back. `parse_client_hello` is likewise tri-state
    (`Scan`): a stream that provably can never be a ClientHello is abandoned, not
    buffered. The TLS record header is validated once, in one place, with a legacy-version
    and 2^14 length bound.
  - Wire text reached the terminal as *markup*, and — separately and more quietly — as
    raw control bytes. Rich and Textual strip only BEL/BS/VT/FF/CR, so an `ESC` in an
    HTTP path already drove the operator's cursor through the feed's DETAIL column, and
    a `\n` in a User-Agent could forge a line in the detail pane and in the `y` clipboard
    yank. Every wire-derived leaf now passes through `printable()` (control characters,
    C1, and bidi/zero-width marks become one-cell Control Pictures — mapped, never
    dropped, so the auditor still sees the byte was there), every panel is
    `markup=False`, and a single `Text`-typed `_paint` funnel makes a raw `str` at a
    panel a mypy error rather than an overnight crash. The JSONL record is unchanged:
    JSON already escapes control bytes losslessly.
- **Top-SNI counts no longer split on case.** `sni_names` keys on the case-folded name
  (DNS is case-insensitive, RFC 4343); the event keeps the bytes as sent.

### Added

- **Operator-path test coverage** — the trust-critical CLI and capture paths a
  regression could silently break now have focused tests: `LiveCapture`'s
  enqueue path and `userspace_dropped` counter under queue overflow (with the
  stop-drain race pinned), every `netmon update` refusal/error/restart branch
  and `netmon service` branch (subprocess/systemctl faked at the boundary), the
  capture-privilege check, the `--tui` non-tty guard, `build_session`'s live
  branch, `stats_loop`, and `announce_start`.
- **systemd sandbox hardening** — the recorder unit (install.sh and RUNBOOK, kept
  in sync) adds the modern defence-in-depth set for a long-lived raw-socket
  process storing browsing history: `RestrictAddressFamilies` (AF_PACKET capture,
  AF_NETLINK enumeration, AF_UNIX for asyncio's own socketpair, AF_INET/6 for
  scapy's ioctl queries), `SystemCallFilter=@system-service`,
  `SystemCallArchitectures=native`, the `ProtectKernel*`/`ProtectControlGroups`/
  `ProtectProc=invisible` family, `RestrictNamespaces`, `LockPersonality`,
  `MemoryDenyWriteExecute`, `RestrictSUIDSGID`, `RestrictRealtime`,
  `PrivateDevices`, and `MemoryHigh=384M`/`MemoryMax=512M` above the documented
  worst-case footprint. `systemd-analyze security` exposure improves 6.0 (MEDIUM)
  → 2.0 (OK), verified offline on systemd 257.
- **In-run output rotation (`--rotate-mb`, `--rotate-keep`)** — dumpcap-style size
  caps for the recorder: each JSONL file (and the `--pcap` evidence file) rolls to
  a numbered archive at the cap, the active file keeps its canonical name, and
  only the newest `--rotate-keep` archives survive (numeric ordering, oldest
  deleted). `netmon query` reads active + archives as one timeline. Rotation
  honours the owner-only and symlink-refusing discipline (a pre-staged file at
  the canonical name still crash-stops), and a failed roll degrades without
  counting the already-written record as dropped — the persistence ledger only
  claims loss that happened. Off by default; the systemd recorder unit ships with
  `--rotate-mb 256 --rotate-keep 4`, replacing the RUNBOOK's restart-as-rotation
  claim.
- **Tunnel and non-Ethernet honest accounting** — raw-IP links (`tun*`/`wg*`/
  `ppp*`/`sit*`) and Linux cooked captures decode from their IP header like any
  Ethernet frame. Directly-encapsulated tunnels (IP-in-IP, 6in4, 4in6) report the
  flow's *inner* endpoints — the real peer, not the tunnel server — with the
  descent stopping at any fragmented layer, which cannot vouch for a complete
  inner packet (both fragments of one tunnelled datagram attribute to the same
  layer). GRE/ESP stay on the outer flow. Frames that decode to no IP at all are
  tallied under a named `non_ip:<layer>` coverage fate (e.g. `non_ip:Ether`,
  `non_ip:Raw`) instead of one opaque bucket.
- **Mid-run local-address refresh** — the host's own-address set is re-enumerated
  every 60 s during a live capture (headless and `--tui` alike), so an address
  assigned mid-run — an RFC 4941 IPv6 privacy-address rotation, a DHCP renewal —
  classifies its egress as `outbound` instead of `transit`. A failed enumeration
  keeps the last-known set (stale beats dead); replays are untouched.
- **TLS 1.2 server-certificate SAN naming** — on the still-common TLS 1.2 path the
  server's certificate crosses the wire in cleartext, and netmon now reassembles the
  server→client handshake flight, reads the leaf certificate's SubjectAltName DNS
  names, and seeds the IP→name ledger with one name per server (a concrete SAN wins
  over a wildcard). A destination is thereby named even when no SNI was ever
  captured — a client that omitted it, or a stream netmon joined mid-flight. A
  certificate name only fills gaps: it never overwrites a name learned from DNS or
  SNI. TLS 1.3 (and resumed TLS 1.2) never sends a cleartext certificate, so those
  streams stop buffering at the cipher change; malformed or truncated certificates
  yield nothing and cannot crash the capture. Packets whose certificate named a
  server are tallied under a new `cert_san` coverage fate, and cert-stream evictions
  surface as `cert_streams`. Scope decision (cert-SAN only, still no JA3/JA4):
  `docs/adr/0001-reopen-cert-san-scope.md`.
- **`netmon query` display filter** — a read-only subcommand that reads a recorded
  run directory's JSONL and filters it by `--kind`, `--host` (a substring of the
  event's SNI / qname / hostname, via the same one-authority projection the live feed
  uses), and `--scope`, printing the matching records as a single chronological stream
  merged across the per-kind files. Filters compose with AND semantics; an empty filter
  prints everything. It replaces the hand-rolled `jq` recipes for the common lookups
  and never re-captures. A missing or non-run directory fails with a clear message, and
  a truncated or hand-edited JSONL line is skipped rather than crashing the query.
- **`--pcap` raw evidence sink** — an opt-in flag that also saves every captured
  packet to `capture.pcap` in the run directory, so a leak-audit finding can be
  re-opened later in tshark/Wireshark for the signals netmon deliberately does not
  compute (JA3/JA4 fingerprints, certificate timing, exact packet sizes). The JSONL
  record is derived and lossy; the pcap preserves the wire bytes. It honours the same
  owner-only (`0600`), symlink-refusing (`O_EXCL|O_NOFOLLOW`, CWE-59) discipline as the
  JSONL writer, and degrades rather than crashing — a full disk or a packet scapy
  cannot serialize (Raw frames from a tun/tunnel capture or an exotic `-r` pcap) is
  counted as `persistence.pcap_dropped` in `summary.json`, never a traceback. Off by
  default; because it writes raw bytes to disk it persists the run. `netmon -r
  <in.pcap> --pcap` round-trips a capture faithfully. Pairs with output rotation to
  keep an always-on recorder's pcap bounded.

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

- **Shutdown no longer silently loses the last packets.** A packet handed over by
  the sniffer thread while shutdown blocked in `join()` scheduled its enqueue too
  late for the post-stop drain and was lost without being counted. The capture
  loop now gives the event loop one turn after the sniffer stops, so raced-in
  packets are drained (found by the new stop-drain test).
- **A TLS flow's continuation is no longer misrouted to the DNS reassembler.** The
  client-stream router re-classified every segment independently, so once the TLS
  reassembler owned a flow, a later segment that happened to begin like a DNS-over-TCP
  length prefix (e.g. a multi-record ClientHello whose second record starts `0x16 0x03`)
  was handed to the DNS reassembler instead, losing the SNI. A flow already tracked by
  the TLS reassembler now stays on the TLS path.
- **A multi-record TLS ClientHello now parses to its true SNI/ALPN.** A ClientHello
  over the 16384-byte TLS record limit (post-quantum key shares increasingly force
  this) is fragmented across two or more handshake records; `parse_client_hello` read
  only the first record and dissected the next record's 5-byte header as handshake body,
  shifting every SNI/ALPN offset into garbage. Consecutive handshake records are now
  reassembled into one message before dissecting. The handshake message is also clipped
  to its own declared length first, so a lying extension/SNI length field can no longer
  read past it into a following record's bytes.
- **A zero-length QUIC CRYPTO frame can no longer hang the reassembler.** Such a frame
  is legal on the wire and, since QUIC Initial keys are publicly derivable, attacker-
  craftable. It made `_crypto_fragments` emit an empty chunk, which spun the stream
  reassembler forever (a network-triggerable denial of service) and squatted its offset
  so the real ClientHello fragment there was rejected. Zero-length CRYPTO frames are now
  skipped, and the reassembler treats an empty chunk as the end of the contiguous prefix.
- **Reassembler eviction is per-flow LRU, not clear-all.** When the total byte cap
  was exceeded, `TcpReassembler`, `DnsTcpReassembler`, and `QuicReassembler` wiped
  *every* in-flight stream at once, dropping many SNIs together — and for QUIC this
  was attacker-triggerable, since Initial keys are publicly derivable, so a flood of
  distinct connection IDs forced periodic full wipes that discarded legitimate
  multi-Initial (post-quantum) ClientHellos mid-reassembly. Eviction now ages out the
  least-recently-updated streams until back under cap (the `LruSet`/`NameLedger`
  pattern), so a burst evicts idle streams while the connection being processed
  survives; each eviction still increments the coverage `evicted.*_streams` counter.
- **TcpReassembler tolerates reordered and overlapping segments.** The client→server
  reassembler (TLS ClientHello / HTTP request head) previously dropped a ClientHello
  whose *second* segment was captured before its opening one, and could truncate the
  stream when an overlapping retransmit was repacketized at a different boundary —
  both losing the SNI. Segments seen before the opening ClientHello/HTTP segment are
  now buffered (byte-bounded, LRU-evicted so the server→client firehose cannot exhaust
  memory) and absorbed once that segment anchors the stream, and overlaps resolve
  first-data-wins so a repacketized retransmit merges cleanly. The verified opening
  segment always wins its own bytes, so buffered data cannot pre-empt it.
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
