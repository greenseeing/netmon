# Slice 9 — systemd sandboxing hardening

Labels: ready-for-agent

## Parent
`00-PRD-audit-hardening.md` — Harden the leak audit.

## What to build
The `netmon.service` unit dropped by `install.sh` (and mirrored in
`docs/RUNBOOK.md`) already has `User`, `Ambient/BoundingSet=CAP_NET_RAW`,
`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, and
`ReadWritePaths`. For a long-running process holding raw-socket capability and
storing browsing history, add the standard modern sandboxing directives as
defence-in-depth: `RestrictAddressFamilies=AF_PACKET AF_INET AF_INET6 AF_UNIX`,
`SystemCallFilter=@system-service`, `SystemCallArchitectures=native`,
`ProtectKernelTunables`/`ProtectKernelModules`/`ProtectKernelLogs`,
`ProtectControlGroups`, `ProtectProc=invisible`, `RestrictNamespaces`,
`LockPersonality`, `MemoryDenyWriteExecute`, `RestrictSUIDSGID`,
`RestrictRealtime`, `PrivateDevices`, and a `MemoryMax=` bounding the documented
worst-case footprint.

## Acceptance criteria
- [ ] The unit gains the directives above without breaking `CAP_NET_RAW` capture
      (AF_PACKET is allowed; the service still records).
- [ ] `MemoryMax=` is set to a value above the documented worst case.
- [ ] `install.sh` and the `docs/RUNBOOK.md` unit stay in sync.
- [ ] Verified on the target host: the service starts, captures, and `systemd-analyze
      security netmon.service` improves.

## Blocked by
None — can start immediately.
