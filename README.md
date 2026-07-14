# netmon

Passive network monitor for auditing what your device leaks to the ISP and which sites it contacts. Captures on all interfaces and logs timestamped, categorized JSONL.

## What it records

| File | Contents |
|------|----------|
| `dns.jsonl` | Every DNS query (name, type, resolver), every answer (A/AAAA/CNAME/… with TTL), and every HTTPS/SVCB (type 65/64) record with its SvcParams: `alpn`, `port`, `ipv4hint`, `ipv6hint`, and an `ech` flag |
| `tls.jsonl` | SNI from the ClientHello of every HTTPS connection — TCP TLS and decrypted QUIC Initials (`transport`), the cleartext `alpn` list, with `ech: true` marking a cover name (see Limitations) |
| `http.jsonl` | Plaintext HTTP requests: method, path, Host, User-Agent; known captive-portal probes carry `tag: "captive-portal"` |
| `flows.jsonl` | Every new connection: protocol, direction (`outbound`/`inbound` across the LAN edge, `local` for LAN-internal or loopback, `transit` for mirrored upstream traffic), local/remote IP+port, service guess, hostname (reverse-mapped from observed DNS answers), scope (`internet`, `cgnat`, `lan`, `linklocal`, `loopback`, or `multicast`), and a `note` on disclosive services (NTP, STARTTLS mail) |
| `summary.json` | Written on exit: top DNS names, top SNI hostnames, top internet hosts, event counts |

All events carry ISO 8601 timestamps in the host's local timezone (with an explicit UTC offset) at millisecond precision. Runs that persist — `netmon run --log`, the background recorder, or the legacy `python netmon.py` form — write to `<output>/run-<stamp>/`.

## Install

One command — but read it before you run it (never pipe a script you haven't seen):

```sh
curl -fsSLO https://git.disroot.org/afk/netmon/raw/branch/main/install.sh
less install.sh                       # inspect
sudo bash install.sh                  # add --enable-service and/or --setcap
```

It clones to `/opt/netmon`, builds an isolated venv, and installs a `netmon` launcher on your PATH. Options: `--enable-service` also installs and starts a hardened systemd recorder; `--setcap` grants `CAP_NET_RAW` to the private interpreter so the interactive TUI runs without sudo — scoped to the `netmon` group (you're added automatically), not every local user. Remove everything with `sudo bash install.sh --uninstall`.

**uv is optional.** The installer uses it when it is already there, and otherwise builds the venv with your system `python3` and the checked-in, hash-pinned `requirements.txt` — no toolchain download, and `pip install --require-hashes` gives the same integrity guarantee `uv sync` does. It only falls back to fetching uv (`curl https://astral.sh/uv/install.sh | sh`, unchecksummed, as root) when the host has **no** Python ≥ 3.13 at all, since only uv can then provide one. Pass `--pip` to refuse that fallback outright:

```sh
sudo bash install.sh --pip            # never fetches a toolchain; needs python3 >= 3.13
```

If your Python is too old *and* you don't want the uv bootstrap, install one first — `apt install python3.13 python3.13-venv` — and re-run with `--pip`. The installer tells you exactly this if it gets stuck.

If you'd rather have a single command and accept the risk of running unreviewed code as root, the pipe form is equivalent to the three steps above:

```sh
curl -fsSL https://git.disroot.org/afk/netmon/raw/branch/main/install.sh | sudo bash
```

## Run

```sh
netmon run              # live btop-style dashboard — ephemeral, nothing written
netmon run --log        # ...and persist the JSONL record to logs/run-<stamp>/
netmon run --headless   # classic per-event stdout logs instead of the dashboard
netmon update           # pull latest + re-sync deps; restart the recorder if running
netmon service status   # background recorder: start|stop|status|enable|disable|logs
netmon query <run-dir>  # filter a recorded run's JSONL by kind/host/scope (read-only)
```

Live capture needs `CAP_NET_RAW`: with `--setcap` it just runs; otherwise the launcher re-execs under `sudo` (one prompt). Capture flags carry over — `-i wlan0`, `--bpf 'not port 22'`, `-q`, `-r <pcap>` (replay, no privilege), `--keep-query`, `--pcap`. Stop with Ctrl-C.

`netmon run` is **ephemeral by design**: it shows traffic live and writes nothing. Your DNS/TLS/HTTP history — the whole point of this tool — only lands on disk when you ask, via `--log`, `--pcap` (which persists the run so the raw evidence has a home — see below), or the recorder.

### Preserving raw evidence (`--pcap`)

The JSONL record is *derived* and lossy: it keeps the SNI/qname/host netmon parsed, not the bytes on the wire. For a leak audit you often want the raw packets too, so a finding can be re-examined later in tshark/Wireshark for the signals netmon deliberately does **not** compute — JA3/JA4 client fingerprints, certificate timing, exact packet sizes. `--pcap` writes every captured packet to `capture.pcap` in the run directory alongside the JSONL, owner-only (`0600`) like the rest of the record. It is off by default and persists the run (a raw-evidence file implies writing to disk). It round-trips a replay too — `netmon -r old.pcap --pcap` re-writes the input faithfully. An incomplete write (full disk) degrades rather than crashing and is reported as `persistence.pcap_dropped` in `summary.json`; pair it with the recorder's rotation to keep an always-on capture bounded.

### Background recorder

For always-on logging, enable the systemd unit that `install.sh` drops in:

```sh
sudo systemctl enable --now netmon.service    # or: netmon service enable
netmon service logs                           # follow it
```

It records headless to `/var/log/netmon/run-<stamp>/` as a non-root `netmon` user holding a single Linux capability (`CAP_NET_RAW`) via systemd's `AmbientCapabilities` — no root shell, no setcap on a shared interpreter.

### From a git checkout (dev)

The historical flat form is unchanged, so a working tree still runs directly:

```sh
uv sync --extra tui
sudo $(command -v uv) run netmon.py --tui     # == netmon run --log
```

### Dashboard

One colour-coded feed shows every DNS / SNI / HTTP / flow event as it happens (kind, direction, host, detail) with the newest at the top, alongside panels for top hosts, per-kind counts, an events/sec sparkline, and capture health (queue depth, drops). The columns resize to fit any terminal width. Keys: `q` quit, `space` pause, `f` cycle filter (all → dns → tls → http → flow), ↑/↓ to inspect a row's full record, `g` to follow the newest again. Scrolling down or selecting a row freezes the feed so you can read history without it snapping back; `g` resumes the live tail. With `--log`, the JSONL record plus a `netmon.log` diagnostic are written to `logs/run-*/` underneath while the dashboard owns the screen; without it the view is purely ephemeral.

## Reading the results

What your ISP sees even with HTTPS: everything in `dns.jsonl` (unless you use encrypted DNS), every `sni` value in `tls.jsonl`, and every remote IP in `flows.jsonl`. Quick looks:

```sh
jq -r '.sni' logs/run-*/tls.jsonl | sort | uniq -c | sort -rn   # sites visited via SNI
jq -r 'select(.kind=="dns_query") | .qname' logs/run-*/dns.jsonl | sort -u
jq -r 'select(.scope=="internet") | .hostname // .remote_ip' logs/run-*/flows.jsonl | sort | uniq -c | sort -rn
```

Or skip the `jq` plumbing with the built-in display filter — `netmon query` reads a run directory's JSONL and applies a filter by `--kind`, `--host` (a substring of the SNI / qname / hostname), and `--scope`, printing the matching records as one chronological stream across the per-kind files. It is read-only over what was already recorded — never a new capture:

```sh
netmon query logs/run-20250702-100000                              # every event, in order
netmon query logs/run-20250702-100000 --kind tls_sni --host example.com  # one site's TLS handshakes
netmon query logs/run-20250702-100000 --scope internet             # only flows that left the LAN
```

Operations: [docs/RUNBOOK.md](docs/RUNBOOK.md).

## Limitations

- QUIC (HTTP/3, `udp/443`): the SNI in a QUIC Initial packet is **not** hidden from your ISP. Initial packets are protected with keys derived from the connection's cleartext Destination Connection ID plus a public, version-specific salt (RFC 9001 §5.2), so any passive observer on the path can decrypt the ClientHello — and mainstream DPI already does. netmon decrypts these Initials (QUIC v1 and v2, reassembling the CRYPTO stream across coalesced and fragmented packets) and logs the SNI in `tls.jsonl` with `"transport": "quic"`. It parses only `udp/443` and only the client's Initial flight.
- Encrypted DNS (DoH/DoT/DoQ) *does* hide the query name from your ISP; it shows up here only as flows to the resolver.
- Encrypted Client Hello (ECH) hides the SNI by design: the cleartext ClientHello then carries a public *cover* name, not the site you visited. netmon flags these with `"ech": true` in `tls.jsonl` — such a line means the real hostname was hidden from your ISP (a leak *prevented*), and the `sni` value is only the cover name. If the ECH handshake fails, the browser retries without it and the real SNI goes out in cleartext, which netmon still records.
- Segmented parsing: SNI and HTTP requests are reassembled across TCP segments (post-quantum ClientHellos routinely span several), so a request split mid-header is still parsed once whole. The one gap is a connection whose *opening* segment was never captured — if netmon starts mid-stream, that flow is not reassembled and its SNI/HTTP is skipped (the flow itself is still logged).
- Tunnels and non-Ethernet links: raw-IP interfaces (`tun*`/`wg*`/`ppp*`/`sit*`) and Linux cooked captures decode like any other link — the frame is dissected from its IP header. Directly-encapsulated tunnels (IP-in-IP, 6in4, 4in6) report the flow's *inner* endpoints — the real peer, not the tunnel server; GRE/ESP encapsulation stays on the outer flow (the inner is not decoded). A frame that decodes to no IP at all is tallied under a named `non_ip:<layer>` fate in the coverage summary, never silently.
- TLS 1.2 server certificates: on the still-common TLS 1.2 path the server's certificate crosses the wire in cleartext, and netmon reads the leaf's SAN names to name a destination it would otherwise miss (no SNI captured, or a stream joined mid-flight). A certificate name only fills gaps — it never overrides a name learned from DNS or SNI. TLS 1.3 encrypts the certificate, so nothing is recovered there. Scope decision: [docs/adr/0001-reopen-cert-san-scope.md](docs/adr/0001-reopen-cert-san-scope.md).

## What this tool does NOT show you

Even at zero of qname/SNI/remote-IP (ECH + encrypted DNS + VPN), an on-path ISP still has signal netmon cannot capture — the honest bound on "what the ISP sees":

- **Traffic analysis** — packet sizes, timing, direction, and per-flow byte volumes. These alone fingerprint individual websites (and often individual pages) behind TLS, ECH, and a VPN, because the shape of a page load is distinctive. netmon logs *that* a flow happened, not its size/timing profile.
- **TLS client fingerprint (JA3/JA4)** — the ordering of cipher suites, extensions, and supported groups in the ClientHello identifies the client software and version. netmon reads SNI and ALPN from that hello but does not compute the fingerprint ([docs/adr/0001-reopen-cert-san-scope.md](docs/adr/0001-reopen-cert-san-scope.md)).
- **IPv6 address leakage** — a SLAAC EUI-64 address embeds the NIC MAC, and a stable IPv6 identifies the device across networks even as the SNI is hidden. netmon records the addresses but does not flag this derivation.

Only Tor-class tooling (onion routing plus traffic padding) meaningfully addresses the traffic-analysis/correlation channel; a VPN or ECH relocates the observer, it does not remove the shape of your traffic.
