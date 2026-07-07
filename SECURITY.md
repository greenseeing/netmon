# Security Policy

## Supported versions

netmon is pre-1.0. Only the latest release on the default branch receives
security fixes.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |
| < 0.1   | ❌        |

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for an
unpatched vulnerability.

Use GitHub's private vulnerability reporting: open the repository's **Security**
tab and choose **Report a vulnerability**. This opens a private advisory visible
only to the maintainers.

Include, where you can: affected version/commit, a minimal reproduction, and the
impact you observed. Expect an initial acknowledgement within a few days.

## Scope notes

netmon is a **passive** capture tool: it opens raw `AF_PACKET` sockets and reads
traffic, it never transmits. It requires `CAP_NET_RAW` (or root) to run. The most
relevant hardening surface is its parsing of untrusted packet bytes (DNS, TLS,
QUIC, HTTP) and its handling of the log directory — reports touching memory-safety
or path handling in those paths are especially welcome.
