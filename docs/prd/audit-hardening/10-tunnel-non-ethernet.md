# Slice 10 — Tunnel / non-Ethernet honest accounting

Labels: ready-for-agent

## Parent
`00-PRD-audit-hardening.md` — Harden the leak audit.

## What to build
Capture-all opens every working interface, including `tun*`/`wg*`/`ppp*` VPN and
tunnel interfaces whose frames have no Ethernet header. `_process` requires
`getlayer(IP)/IPv6` and buckets everything else as `non_ip`, so tunnel traffic —
a prime leak-audit target — produces zero events and is silently counted as
`non_ip`. Relatedly, IP-in-IP / 6in4 (`net = getlayer(IP) or getlayer(IPv6)`
picks the *outer* header while `getlayer(TCP)` returns the *inner* ports),
mislabelling the flow and hiding the inner peer. At minimum, recognise the
link-layer type so tunnel L3 payloads are decoded (or, if out of scope to decode,
give them an honest fate instead of `non_ip`); and pick the correct header for
tunnelled packets so the flow reflects the real endpoints.

## Acceptance criteria
- [ ] A capture on a non-Ethernet link (Linux cooked / raw-IP tunnel) decodes the
      IP payload and produces events, or is accounted under an honest, named fate —
      not silently `non_ip`.
- [ ] An IP-in-IP / 6in4 packet's flow reflects the inner protocol's real endpoints,
      or is explicitly documented as out of scope with an honest fate.
- [ ] Tests drive a non-Ethernet-framed and a tunnelled packet through `process`.
- [ ] README/RUNBOOK note what tunnel/link types are now handled.

## Blocked by
None — can start immediately. IP-layer defragmentation stays out of scope.
