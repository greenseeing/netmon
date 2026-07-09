# Slice 4 — Refresh local addresses during a run

Labels: ready-for-agent

## Parent
`00-PRD-audit-hardening.md` — Harden the leak audit.

## What to build
`local_addresses()` (`netmon.py` ~1057) is read once at session construction and
frozen into `PacketProcessor.local_ips`. The address-class flow model (`c15c122`)
made this matter less — private addresses are local regardless — but a
**globally-addressed** host (a public-IP server, or un-NAT'd IPv6) whose own
address is global still depends on `local_ips` to classify its egress as
`outbound`; an RFC 4941 IPv6 privacy-address rotation or a DHCP renewal mid-run
adds a new own address that is absent from the frozen set, so that traffic
misclassifies as `transit`. Refresh `local_ips` periodically during a run (re-read
`local_addresses()` on a cadence that works in both headless and `--tui` modes) so
newly-assigned own addresses are recognised.

## Acceptance criteria
- [ ] `PacketProcessor` exposes a refresh that re-reads the host's current addresses
      and updates `local_ips` without dropping in-flight state.
- [ ] The refresh runs on a bounded cadence in headless, `-q`, systemd, and `--tui`
      modes (note: `stats_loop` is disabled under `--tui`).
- [ ] A test: after a new own address appears, a flow sourced from it classifies as
      `outbound`, not `transit`.
- [ ] No measurable per-packet cost regression (refresh is periodic, not per-packet).

## Blocked by
None — depends on the address-class model already shipped in `c15c122`.
