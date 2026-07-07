# Slice 6 — DNS on non-standard ports

Labels: ready-for-agent

## Parent
`00-PRD-capture-gaps.md` — Close the remaining capture gaps.

## What to build
Recognise plaintext DNS by its message layer regardless of UDP/TCP port, so a
local forwarder or dnscrypt-proxy listening on a custom port (e.g. 5300/5335) or
a split-horizon resolver is parsed like port-53 DNS instead of falling through to
a bare flow. Recognition keys on the DNS layer/shape, with the port as a hint.

## Acceptance criteria
- [ ] A DNS query and response on a non-standard port are parsed identically to port 53.
- [ ] Recognition does not depend on the port literal.
- [ ] Standard port-53 and mDNS/5353 behaviour is unchanged.
- [ ] Tests drive `process(pkt)` with DNS on a custom port and assert the query/answer events.

## Blocked by
- Slice 1 (DNS response outcomes) — shares the DNS parsing path.
