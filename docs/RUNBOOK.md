# netmon operator runbook

How to deploy, run, verify, and read the passive network monitor on any Linux host.

## 1. Requirements

- Linux (uses `AF_PACKET` raw sockets; macOS/Windows not supported)
- Python ≥ 3.13 and [uv](https://docs.astral.sh/uv/) (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- `tcpdump` binary — only needed if you pass `--bpf` (scapy shells out to it to compile the filter)
- Root or `CAP_NET_RAW` (section 3)

## 2. Install

```sh
# copy the project to the target host, e.g.:
rsync -a netmon.py pyproject.toml uv.lock README.md docs/RUNBOOK.md host:/opt/netmon/
ssh host
cd /opt/netmon
uv sync --no-dev
```

Without uv: `python3.13 -m venv .venv && .venv/bin/pip install scapy pydantic structlog cryptography`, then substitute `.venv/bin/python netmon.py` for `uv run netmon.py` everywhere below.

> **After moving or renaming the project directory, re-run `uv sync`.** The venv's console-script shebangs (`.venv/bin/mypy`, etc.) are absolute paths baked in at creation; a move leaves them pointing at the old path, so `.venv/bin/<tool>` fails with `bad interpreter` until `uv sync` regenerates them. `uv run …` is unaffected (it re-resolves the interpreter), but a dir move also invalidates the `setcap` grant from section 3B — re-apply it.

## 3. Capture privileges — pick one

**A. sudo per run** (simplest, nothing persistent):

```sh
sudo $(command -v uv) run netmon.py
```

`sudo uv` alone usually fails — root's PATH lacks `~/.local/bin`, hence `$(command -v uv)`.

**B. Grant the capability once** (for unattended use and running without sudo):

```sh
sudo setcap cap_net_raw+eip "$(readlink -f .venv/bin/python3)"
```

Caveat: `.venv/bin/python3` is a symlink; the capability lands on the **real** interpreter it points to. If that's the system `/usr/bin/python3.13`, every venv on the host built from it can open raw sockets. Acceptable on a personal machine; on shared hosts build the venv with a private interpreter first (`uv venv --python 3.13` uses a uv-managed copy under `~/.local/share/uv/python/`). Revoke anytime:

```sh
sudo setcap -r "$(readlink -f .venv/bin/python3)"
```

**C. systemd service** (continuous monitoring, survives reboots) — see section 7.

## 4. Run

```sh
uv run netmon.py                     # all interfaces incl. loopback/VPN-tun/docker
uv run netmon.py -q                  # files only (recommended for long runs)
uv run netmon.py -i wlan0            # single interface
uv run netmon.py --bpf 'not port 22' # exclude your own SSH session noise
uv run netmon.py -o /var/log/netmon  # custom output root (default: ./logs)
```

Each start creates a fresh `logs/run-YYYYMMDD-HHMMSS/`. Stop with `Ctrl-C` (or `kill -TERM <pid>`) — the summary is only written on clean shutdown.

Startup prints `capture_started` with the interface list and detected local IPs — check that list; direction (inbound/outbound) classification depends on it. A `stats` line is logged every 30 s with packets, event counts, queue depth, `userspace_dropped` (netmon's own queue overflowed) and `kernel_dropped` (the kernel's `tp_drops`: packets the socket buffer shed before netmon ever saw them). `kernel_dropped: "unavailable"` means the source can't report it (e.g. pcap replay).

`--read file.pcap` replays a capture file through the same pipeline instead of sniffing live — no privileges needed; useful for testing and offline analysis.

### Live dashboard (`--tui`)

`uv sync --extra tui` (pulls in Textual), then `uv run netmon.py --tui` for a btop-style live view: a colour-coded feed of every DNS/SNI/HTTP/flow event (newest at the top, columns fit to terminal width) plus top-hosts, per-kind, events/sec, and capture-health panels. Keys: `q` quit, `space` pause, `f` cycle filter, ↑/↓ inspect a row for its full record, `g` follow the newest. Scrolling down or selecting a row freezes the feed (the health panel shows FOLLOW/INSPECT/PAUSED) so history can be read without it snapping back; `g` resumes the live tail. Requires an interactive terminal (both stdin and stdout a tty) — it exits `2` otherwise, so it is **not** for systemd/headless use; those keep using `-q`. The JSONL files are still written, and structlog is redirected to `<run>/netmon.log` so it can't garble the display. Only `q`/`ctrl+q`/`ctrl+c` quit from the keyboard; an external `kill -TERM <pid>` also stops it cleanly and writes the summary. The headless deploy needs only `netmon.py` (the `--tui` import is lazy); add the `tui` extra only where you want the dashboard.

## 5. Verify capture is working

From a second terminal, generate one known event of each type:

```sh
dig example.com                 # → dns_query + dns_answer in dns.jsonl
curl -s https://example.com >/dev/null   # → tls_sni in tls.jsonl, flow in flows.jsonl
curl -s http://neverssl.com >/dev/null   # → http event in http.jsonl
```

Then confirm:

```sh
ls logs/run-*/                  # dns.jsonl tls.jsonl http.jsonl flows.jsonl
jq -r 'select(.sni=="example.com")' logs/run-*/tls.jsonl
```

If those appear, capture is healthy.

## 6. Output reference

| File | One line per | Key fields |
|------|--------------|------------|
| `dns.jsonl` | DNS query / answer / HTTPS-SVCB record | `qname`, `qtype`, `rtype`, `value`, `ttl`, `resolver`; HTTPS/SVCB (type 65/64) adds `alpn`, `port`, `ipv4hint`, `ipv6hint`, `ech`, `target` |
| `tls.jsonl` | ClientHello with SNI (TCP TLS or QUIC) | `sni`, `dst`, `dport`, `transport` (`tcp`/`quic`), `alpn` (negotiated protocols), `ech` (`true` = `sni` is an ECH cover name) |
| `http.jsonl` | plaintext HTTP request | `method`, `host`, `path`, `user_agent`, `tag` (e.g. `captive-portal`) |
| `flows.jsonl` | new 5-tuple connection | `direction`, `scope` (`internet`/`lan`/`multicast`), `service`, `hostname`, `remote_ip`, `note` (on NTP / STARTTLS-mail flows) |
| `summary.json` | run (written at exit) | top DNS/SNI names, top internet hosts, event counts, `capture` drop counters (`userspace_dropped`, `kernel_dropped`) |

All events: ISO 8601 UTC `ts` with millisecond precision. `hostname` on flows is reverse-mapped from DNS answers observed **during this run** — flows to IPs resolved before the monitor started show no hostname.

### Analysis recipes

```sh
R=logs/run-20260703-090000   # pick a run

jq -r '.sni' $R/tls.jsonl | sort | uniq -c | sort -rn            # sites visited (SNI)
jq -r 'select(.kind=="dns_query").qname' $R/dns.jsonl | sort -u  # every name resolved
jq -r 'select(.scope=="internet") | .hostname // .remote_ip' $R/flows.jsonl \
  | sort | uniq -c | sort -rn                                    # internet endpoints
jq -rs 'sort_by(.ts) | .[] | "\(.ts) \(.kind) \(.sni // .qname // .hostname // .remote_ip // "")"' \
  $R/*.jsonl                                                     # merged timeline
```

**What your ISP sees even with HTTPS:** every `qname` in `dns.jsonl` (unless DNS is encrypted), every `sni` in `tls.jsonl`, every `remote_ip` in internet-scope flows, and everything in `http.jsonl` in full. And beyond what netmon can capture — traffic-analysis (packet sizes/timing), TLS fingerprints, TLS 1.2 server certs, IPv6 MAC leakage — see "What this tool does NOT show you" in the [README](../README.md).

## 7. Continuous monitoring (systemd)

`/etc/systemd/system/netmon.service`:

```ini
[Unit]
Description=netmon passive network monitor
After=network.target

[Service]
WorkingDirectory=/opt/netmon
ExecStart=/opt/netmon/.venv/bin/python netmon.py -q -o /var/log/netmon
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/log/netmon
Restart=on-failure
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
```

```sh
sudo mkdir -p /var/log/netmon
sudo systemctl daemon-reload
sudo systemctl enable --now netmon
journalctl -u netmon -f          # structlog JSON: capture_started, stats, capture_stopped
```

`AmbientCapabilities` makes setcap (section 3B) unnecessary for the service. Each restart opens a new run directory, which doubles as log rotation. Prune old runs:

```sh
find /var/log/netmon -maxdepth 1 -name 'run-*' -mtime +30 -exec rm -r {} +
```

## 8. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `insufficient_privileges` at startup | No root/CAP_NET_RAW — section 3. After rebuilding `.venv` (e.g. `uv sync` upgraded Python), setcap must be re-applied. |
| `sudo: uv: command not found` | Use `sudo $(command -v uv) run netmon.py`. |
| Starts, but zero packets in `stats` | Wrong `-i` name (check `ip link`); or a too-narrow `--bpf` expression. |
| `--bpf` raises an error | `tcpdump` not installed — scapy needs it to compile the filter. |
| `userspace_dropped` > 0 in stats | Consumer can't keep up (very busy link). Narrow with `--bpf` or `-i`, and use `-q`. |
| `kernel_dropped` > 0 in stats | The kernel shed packets before netmon read them — the run under-reports by at least that many packets; treat the record as incomplete. Same remedies: `--bpf`, `-i`, `-q`. |
| Flows show `direction: "transit"` | Neither endpoint is a local IP — broadcast/multicast from other LAN devices, or you're capturing a mirrored/bridged port. Normal. |
| Flow has no `hostname` | The DNS lookup happened before this run started, or the app used DoH. Correlate `remote_ip` manually. |
| DNS queries only show `dst: 127.0.0.53` | systemd-resolved stub on loopback — those are your apps' real queries. If no matching upstream `udp/53` appears on a physical interface, the upstream leg is inside a VPN tunnel (e.g. Tailscale MagicDNS): your ISP does not see that DNS. |
| Nothing in `http.jsonl` | Expected — nearly everything is HTTPS now. It only catches plaintext HTTP. |
| No SNI for QUIC/HTTP-3 flows (`service: "quic"`) | netmon decrypts `udp/443` client Initials and logs the SNI to `tls.jsonl` with `transport: "quic"`. A QUIC flow with no SNI means QUIC on a non-443 port, ECH in use, or the Initial wasn't captured. |
| No SNI for some TCP HTTPS traffic | Encrypted Client Hello (ECH) genuinely hides it — a leak *prevented*, not a gap; see README limitations. |

## 9. Ops notes

- Purely passive: sends nothing, modifies nothing; promiscuous mode is off (you see this host's traffic plus broadcast/multicast).
- The logs themselves are the sensitive artifact — they are your browsing history. Each run directory is created owner-only (`0700`) and every `*.jsonl`/`summary.json` is `0600`, so other local users can't read captured traffic. The **output root** (e.g. `logs/`, or a `-o` path) keeps whatever mode it already had — if it predates this and is world-listable, `chmod 700` it yourself so run-directory timestamps aren't enumerable. Still: prune old runs and don't sync them to shared storage.
- Memory is bounded — every per-key structure evicts: the flow-dedup table is an LRU capped at 200k five-tuples (an idle flow can age out and re-emit one `flow` event; an active one never does), the IP→hostname ledger is an LRU capped at 64k entries, and the DNS/SNI/host tallies cap at 50k keys each (past that, only the hottest keys keep exact counts, so `top_*` lists stay right but `unique_*` totals become estimates). Worst case is on the order of 100 MB of tables on a pathological link, tens of MB in practice. JSONL files are flushed per line, so a crash loses at most the final summary (re-derivable from the JSONL with `jq`).
