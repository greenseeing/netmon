# netmon operator runbook

How to deploy, run, verify, and read the passive network monitor on any Linux host.

## 1. Requirements

- Linux (uses `AF_PACKET` raw sockets; macOS/Windows not supported)
- **`git`** — required, and not only to install: `netmon update` *is* a `git pull --ff-only`
  against the checkout, which is what lets it refuse a dirty tree and report exactly which
  revision you are running. A leak auditor that cannot name its own revision is a poor one.
- **Either** Python ≥ 3.13 with its `venv` module (`apt install python3.13 python3.13-venv`)
  **or** [uv](https://docs.astral.sh/uv/). The installer uses whichever it finds, and only
  fetches uv when the host has no usable Python at all. If it finds neither it says so, names
  what it found, and gives you both remedies.
- `libcap2-bin` — only for `--setcap` (the passwordless TUI)
- `curl` — only if the installer has to bootstrap uv: no usable Python **and** no uv
- `tcpdump` binary — only needed if you pass `--bpf` (scapy shells out to it to compile the filter)
- Root or `CAP_NET_RAW` (section 3)

Everything the default install needs on a stock Debian/Ubuntu box:

```sh
sudo apt install git python3-venv libcap2-bin
```

## 2. Install

**Recommended — the installer** (clones to `/opt/netmon`, builds an isolated venv,
installs a `netmon` launcher, and optionally the systemd recorder):

```sh
curl -fsSLO https://raw.githubusercontent.com/greenseeing/netmon/main/install.sh
less install.sh                          # read before running
sudo bash install.sh                     # + --enable-service and/or --setcap
```

`--enable-service` installs and starts the section-7 unit; `--setcap` grants
`CAP_NET_RAW` to the private interpreter (needs `libcap2-bin`); `--uninstall`
reverses everything. It clones over **HTTPS** so `netmon update` (`git pull`) works
without an SSH key. Thereafter: `netmon update` pulls the latest revision and
rebuilds with whichever builder made the install; it refuses if the working tree has
local edits (`git stash` first).

**Which builder?** uv if it is on PATH; otherwise your system `python3` plus the
checked-in, hash-pinned `requirements.txt`; and only if there is no Python ≥ 3.13 at
all does it fetch uv (unchecksummed, as root — see the script's header). `--pip` forces
the pip path and never fetches a toolchain:

```sh
sudo bash install.sh --pip
```

Both paths build the venv with a **private** interpreter under `/opt/netmon`, which is
what lets `--setcap` (section 3B) arm netmon's own copy rather than a shared `/usr`
interpreter — the pip path uses `venv --copies` precisely so that stays true.

**Manual** (a dev checkout, or no installer):

```sh
rsync -a netmon.py netmon_tui.py pyproject.toml uv.lock requirements.txt README.md docs/ host:/opt/netmon/
ssh host && cd /opt/netmon && uv sync --no-dev
```

Without uv, install the same pinned tree pip understands — do **not** hand-list the
dependencies (you will omit `textual`, and `netmon run` is the dashboard):

```sh
python3.13 -m venv --copies .venv
.venv/bin/pip install --require-hashes -r requirements.txt
.venv/bin/pip install --no-deps -e .
```

Then substitute `.venv/bin/netmon` for `uv run netmon.py` everywhere below.

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

`install.sh --setcap` does exactly this, but safely: it targets the private uv-managed interpreter under `/opt/netmon/pythons` (refusing any target under `/usr`), and — because a file capability is usable by *anyone who can execute the binary* — it then `chown root:netmon` + `chmod 0750`s that interpreter so only root and the `netmon` group get it. The installing user is added to the group automatically (`usermod -aG netmon`); add other interactive users the same way. Everyone else falls back to a sudo prompt.

Caveat: `.venv/bin/python3` is a symlink; the capability lands on the **real** interpreter it points to. If that's the system `/usr/bin/python3.13`, every venv on the host built from it can open raw sockets. Acceptable on a personal machine; on shared hosts build the venv with a private interpreter first (`uv venv --python 3.13` uses a uv-managed copy under `~/.local/share/uv/python/`). Revoke anytime:

```sh
sudo setcap -r "$(readlink -f .venv/bin/python3)"
```

**C. systemd service** (continuous monitoring, survives reboots) — see section 7.

## 4. Run

With the installer's launcher (it re-execs under `sudo` when live capture needs
`CAP_NET_RAW`, unless you used `--setcap`):

```sh
netmon run                           # live TUI dashboard — ephemeral, writes nothing
netmon run --log                     # ...and persist the JSONL record
netmon run --headless -q             # classic stdout stream (files only with --log)
netmon run -i wlan0 --log            # single interface
netmon run --bpf 'not port 22' --log # exclude your own SSH session noise
netmon run --log -o /var/log/netmon  # custom output root (default: ./logs)
```

From a checkout the historical flat form is unchanged and still writes files:
`uv run netmon.py -q`, `uv run netmon.py -i wlan0`, etc.

A persisting run (`--log`, the recorder, or the legacy form) creates a fresh
`<output>/run-YYYYMMDD-HHMMSS/`; a bare `netmon run` creates nothing. Stop with
`Ctrl-C` (or `kill -TERM <pid>`) — the summary is only written on clean shutdown.

Startup prints `capture_started` with the interface list and detected local IPs — check that list; direction (inbound/outbound) classification depends on it. A `stats` line is logged every 30 s with packets, event counts, queue depth, `userspace_dropped` (netmon's own queue overflowed) and `kernel_dropped` (the kernel's `tp_drops`: packets the socket buffer shed before netmon ever saw them). `kernel_dropped: "unavailable"` means the source can't report it (e.g. pcap replay).

`--read file.pcap` replays a capture file through the same pipeline instead of sniffing live — no privileges needed; useful for testing and offline analysis.

### Live dashboard (`netmon run`)

`netmon run` opens the btop-style live view (the installer already added the `tui`
extra; from a checkout, `uv sync --extra tui` then `netmon run` or the equivalent
`uv run netmon.py --tui`). A colour-coded feed of every DNS/SNI/HTTP/flow event (newest at the top, columns fit to terminal width) plus top-hosts, per-kind, events/sec, and capture-health panels. Keys: `q` quit, `space` pause, `f` open the filter bar (a checkbox per kind / direction / scope; `a` all, `n` none, `space` toggle, `esc` close), ↑/↓ inspect a row for its full record, `g` follow the newest. The feed's border names any active filter. Scrolling down or selecting a row freezes the feed (the health panel shows FOLLOW/INSPECT/PAUSED) so history can be read without it snapping back; `g` resumes the live tail. Requires an interactive terminal (both stdin and stdout a tty) — it exits `2` otherwise, so it is **not** for systemd/headless use; those use `netmon run --headless --log -q`. By default `netmon run` is ephemeral (writes nothing); add `--log` to persist the JSONL record, which also redirects structlog to `<run>/netmon.log` so it can't garble the display. Only `q`/`ctrl+q`/`ctrl+c` quit from the keyboard; an external `kill -TERM <pid>` also stops it cleanly and writes the summary (when `--log`). The headless deploy needs only `netmon.py` (the TUI import is lazy); add the `tui` extra only where you want the dashboard.

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

### 6B. Reading a recorded run — `audit` and `query`

**Both are offline readers. Neither captures.** They take a *run directory* that a previous
capture wrote, so the sequence is always **record, then read** — and `netmon run` without
`--log` is ephemeral by design and leaves nothing behind to read.

```sh
netmon run --log        # record (or --headless --log -q for no dashboard) -> logs/run-<stamp>/
```

Given no run directory, `audit` and `query` both read the **newest run** under the output dir
(default `logs/`, override with `-o`) and print which one they chose **on stderr**, so a
redirected `--format csv` is unaffected. Name a directory explicitly to override.

`netmon audit` recomputes the leak findings from the record and prints the diagnosis —
what leaked, to whom, and what to do about it:

```sh
netmon audit                                  # the newest run under logs/
netmon audit --min-severity high
netmon audit -o /var/log/netmon               # the recorder's runs (needs sudo, see below)
netmon audit logs/run-20250702-100000         # a specific run
```

`netmon query` returns the raw recorded events, filtered:

```sh
netmon query --kind tls_sni --host example.com
netmon query --scope internet                 # everything that left the LAN
netmon query --min-severity high --rule cleartext-http
```

`--format csv` projects the dashboard's five columns for a spreadsheet. It is an **export from
the record, not a logging format** — there is no `--format csv` on `netmon run`, because the
recorder writes JSONL (the evidence) and CSV is derived from it on demand, so the two cannot
disagree:

```sh
umask 077                                     # a run is your browsing history
netmon query --min-severity medium --format csv > leaks.csv
```

A CSV cell beginning `'` is a **neutralised formula**: spreadsheets execute cells starting
`=`/`+`/`-`/`@`, and netmon records DNS names and HTTP paths verbatim off the wire. Strip the
apostrophe to recover the original.

**The systemd recorder writes as the `netmon` user into `/var/log/netmon` (mode `0700`)**, so
its runs need root to read:

```sh
sudo netmon audit -o /var/log/netmon --min-severity high
```

## 7. Continuous monitoring (systemd)

`install.sh --enable-service` sets this all up: a dedicated non-root `netmon` user,
`/var/log/netmon` (mode `0700`), and the unit below at `/etc/systemd/system/netmon.service`.
Drive it with `netmon service {start,stop,status,enable,disable,logs}` (thin
`systemctl`/`journalctl` wrappers) or `systemctl` directly.

```ini
[Unit]
Description=netmon passive network recorder
After=network.target

[Service]
User=netmon
ExecStart=/opt/netmon/.venv/bin/netmon run --headless --log -q -o /var/log/netmon --rotate-mb 256 --rotate-keep 4
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/log/netmon
Restart=on-failure
# Defence-in-depth for a long-lived raw-socket process storing browsing history.
# AF_PACKET is the capture socket itself; AF_NETLINK backs glibc/scapy interface
# enumeration (the 60s local-address refresh); AF_UNIX is asyncio's own signal
# socketpair (asyncio.run creates it at startup); AF_INET/AF_INET6 back scapy's
# ioctl-based interface queries. @system-service includes ioctl and @network-io
# (verified on systemd 257). /proc/net stays readable under ProtectProc=invisible
# (it is /proc/self/net).
RestrictAddressFamilies=AF_PACKET AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallFilter=@system-service
SystemCallArchitectures=native
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectProc=invisible
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
PrivateDevices=yes
# Above the documented worst case (~100 MB of bounded tables + interpreter + the
# 50k-packet queue): reclaim pressure at High gives an operator-visible warning
# window; the hard Max kills a leak instead of the host swapping.
MemoryHigh=384M
MemoryMax=512M

[Install]
WantedBy=multi-user.target
```

To wire it up by hand instead:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now netmon      # or: netmon service enable
netmon service logs                     # structlog JSON: capture_started, stats, capture_stopped
```

`--headless --log` is required: the recorder must persist (`--log`) and must not try
to open a TUI without a tty (`--headless`). `AmbientCapabilities` makes setcap (section 3B) unnecessary for the service — it runs unprivileged with exactly one capability.

`--rotate-mb N` bounds a single run's files in-flight, dumpcap-style: each JSONL
(and the `--pcap` evidence file) rolls to a numbered archive at N MB — the active
file keeps its canonical name — and only the newest `--rotate-keep` archives
survive, oldest deleted. `netmon query` reads active + archives as one timeline.
Off by default (`--rotate-mb 0`); the unit above bounds a healthy long-lived
recorder to roughly `(keep+1) × N MB` per output file. A restart still opens a
fresh run directory; prune old runs:

```sh
find /var/log/netmon -maxdepth 1 -name 'run-*' -mtime +30 -exec rm -r {} +
```

## 8. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `insufficient_privileges` at startup | No root/CAP_NET_RAW — section 3. After `netmon update`/`uv sync` rebuilds `.venv` (e.g. Python upgraded), a `--setcap` grant is on the old interpreter — re-run `sudo bash install.sh --setcap`. |
| `netmon run` prompts for a sudo password | Expected without `--setcap`: the launcher re-execs under sudo to get `CAP_NET_RAW`. Run `sudo bash install.sh --setcap` for a passwordless TUI, or use the systemd recorder for unattended capture. |
| `netmon update` refuses: "working tree has local changes" | You edited files under `/opt/netmon`. `sudo git -C /opt/netmon stash` (or discard) then retry; update does a `--ff-only` pull and won't clobber local edits. |
| `sudo: uv: command not found` | Use `sudo $(command -v uv) run netmon.py`, or the `netmon` launcher (which execs the venv directly, no uv on PATH needed). |
| `python -m venv` fails, or `No module named pip` | Debian ships `venv`/`ensurepip` separately: `apt install python3-venv` (or `python3.13-venv`). The installer checks for this up front and refuses such an interpreter by name rather than failing here — if you hit it, you built the venv by hand. |
| install.sh: "no usable Python, no uv, and no curl" | The host cannot run netmon (needs ≥ 3.13) and offers no way to get an interpreter. Install either: `apt install python3.13 python3.13-venv` then re-run with `--pip`, or `apt install uv` / `pipx install uv`. |
| Passwordless TUI stopped working after a distro Python upgrade | The pip path copies the interpreter into `/opt/netmon/.venv`, so a system upgrade leaves that copy — and its `--setcap` grant — stale. Re-run `sudo bash install.sh --setcap`. |
| Starts, but zero packets in `stats` | Wrong `-i` name (check `ip link`); or a too-narrow `--bpf` expression. |
| `--bpf` raises an error | `tcpdump` not installed — scapy needs it to compile the filter. |
| `userspace_dropped` > 0 in stats | Consumer can't keep up (very busy link). Narrow with `--bpf` or `-i`, and use `-q`. |
| `kernel_dropped` > 0 in stats | The kernel shed packets before netmon read them — the run under-reports by at least that many packets; treat the record as incomplete. Same remedies: `--bpf`, `-i`, `-q`. |
| Flows show `direction: "transit"` | Neither endpoint is a local IP — broadcast/multicast from other LAN devices, or you're capturing a mirrored/bridged port. Normal. |
| `non_ip:<layer>` fates in the coverage summary | Frames that decoded to no IP header, named by their deepest decoded layer (`non_ip:Ether` = unknown ethertype, `non_ip:Raw` = an unmapped link type in a replayed pcap). Raw-IP links (`tun*`/`wg*`/`ppp*`) and cooked captures decode normally; IP-in-IP/6in4/4in6 flows report the inner endpoints, GRE/ESP stay on the outer flow. |
| Flow has no `hostname` | The DNS lookup happened before this run started, or the app used DoH. Correlate `remote_ip` manually. |
| DNS queries only show `dst: 127.0.0.53` | systemd-resolved stub on loopback — those are your apps' real queries. If no matching upstream `udp/53` appears on a physical interface, the upstream leg is inside a VPN tunnel (e.g. Tailscale MagicDNS): your ISP does not see that DNS. |
| The leaks panel is empty | No **known-shape** disclosure was recorded — not an assurance that nothing leaked. netmon has no baseline and no notion of "unusual"; see the README's *What this tool does NOT show you*. |
| A CSV cell starts with `'` | A neutralised formula. Excel/LibreOffice execute cells beginning `=`/`+`/`-`/`@`, and DNS names come off the wire verbatim; the apostrophe is the spreadsheet's own literal-text marker. Strip it to recover the original. |
| Nothing in `http.jsonl` | Expected — nearly everything is HTTPS now. It only catches plaintext HTTP. |
| No SNI for QUIC/HTTP-3 flows (`service: "quic"`) | netmon decrypts `udp/443` client Initials and logs the SNI to `tls.jsonl` with `transport: "quic"`. A QUIC flow with no SNI means QUIC on a non-443 port, ECH in use, or the Initial wasn't captured. |
| No SNI for some TCP HTTPS traffic | Encrypted Client Hello (ECH) genuinely hides it — a leak *prevented*, not a gap; see README limitations. |

## 9. Ops notes

- Purely passive: sends nothing, modifies nothing; promiscuous mode is off (you see this host's traffic plus broadcast/multicast).
- The logs themselves are the sensitive artifact — they are your browsing history. Each run directory is created owner-only (`0700`) and every `*.jsonl`/`summary.json` is `0600`, so other local users can't read captured traffic. The **output root** (e.g. `logs/`, or a `-o` path) keeps whatever mode it already had — if it predates this and is world-listable, `chmod 700` it yourself so run-directory timestamps aren't enumerable. Still: prune old runs and don't sync them to shared storage.
- Memory is bounded — every per-key structure evicts: the flow-dedup table is an LRU capped at 200k five-tuples (an idle flow can age out and re-emit one `flow` event; an active one never does), the IP→hostname ledger is an LRU capped at 64k entries, and the DNS/SNI/host tallies cap at 50k keys each (past that, only the hottest keys keep exact counts, so `top_*` lists stay right but `unique_*` totals become estimates). Worst case is on the order of 100 MB of tables on a pathological link, tens of MB in practice. JSONL files are flushed per line, so a crash loses at most the final summary (re-derivable from the JSONL with `jq`).
