"""Passive network monitor: DNS, TLS SNI, HTTP hosts, and flows to timestamped JSONL logs."""

import argparse
import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
from collections import Counter, OrderedDict
from collections.abc import AsyncGenerator, Callable, Mapping
from contextlib import aclosing
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, NamedTuple, Protocol, TextIO, cast

import structlog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, Field
from scapy.config import conf
from scapy.interfaces import get_working_ifaces
from scapy.layers.dns import (
    DNS,
    DNSQR,
    DNSRR,
    DNSRROPT,
    EDNS0ClientSubnet,
    dnsqtypes,
    dnstypes,
)
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import (
    ICMPv6ND_RA,
    ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptRDNSS,
    IPv6,
)
from scapy.layers.l2 import ARP
from scapy.layers.llmnr import LLMNRQuery
from scapy.layers.netbios import NBNSQueryRequest
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer
from scapy.utils import PcapReader

log = structlog.get_logger()

SERVICE_BY_PORT: dict[tuple[str, int], str] = {
    ("tcp", 21): "ftp",
    ("tcp", 22): "ssh",
    ("tcp", 25): "smtp",
    ("tcp", 53): "dns-tcp",
    ("tcp", 80): "http",
    ("tcp", 110): "pop3",
    ("tcp", 143): "imap",
    ("tcp", 443): "https",
    ("tcp", 465): "smtps",
    ("tcp", 587): "smtp-submission",
    ("tcp", 853): "dot",
    ("tcp", 993): "imaps",
    ("tcp", 995): "pop3s",
    ("tcp", 8080): "http-alt",
    ("tcp", 8443): "https-alt",
    ("tcp", 22000): "syncthing",
    ("udp", 53): "dns",
    ("udp", 67): "dhcp",
    ("udp", 68): "dhcp",
    ("udp", 123): "ntp",
    ("udp", 443): "quic",
    ("udp", 500): "ike",
    ("udp", 853): "doq",
    ("udp", 1194): "openvpn",
    ("udp", 1900): "ssdp",
    ("udp", 3478): "stun",
    ("udp", 4500): "ipsec-nat-t",
    ("udp", 5351): "nat-pmp",
    ("udp", 5353): "mdns",
    ("udp", 21027): "syncthing-disc",
    ("udp", 22000): "syncthing",
    ("udp", 41641): "tailscale",
    ("udp", 51820): "wireguard",
}

HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
)

# OS/browser connectivity checks: cleartext GETs an ISP can use to fingerprint
# the device and vendor even though the rest of that device's traffic is TLS.
CAPTIVE_PORTAL_HOSTS = frozenset(
    {
        "captive.apple.com",
        "connectivitycheck.gstatic.com",
        "connectivitycheck.android.com",
        "clients3.google.com",
        "www.msftconnecttest.com",
        "www.msftncsi.com",
        "detectportal.firefox.com",
        "connectivity-check.ubuntu.com",
        "network-test.debian.org",
    }
)

# Light per-service annotations for flows that are themselves a disclosure the
# reader would otherwise miss: NTP betrays the device clock/OS, and STARTTLS
# mail ports carry auth and content in cleartext before the TLS upgrade.
SERVICE_NOTES: dict[str, str] = {
    "ntp": "clock sync — reveals device/OS presence",
    "smtp": "STARTTLS mail — auth/content may precede TLS",
    "smtp-submission": "STARTTLS mail — auth/content may precede TLS",
    "imap": "STARTTLS mail — auth/content may precede TLS",
    "pop3": "STARTTLS mail — auth/content may precede TLS",
}


DNS_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
}

# RA-advertised recursive resolvers have no hostname on the wire; seed the ledger
# with this role label so later flows to them read as the network's own DNS.
RA_RDNSS_NAME = "rdnss"


def dns_rcode(code: Any) -> str:
    return DNS_RCODES.get(int(code), str(int(code)))


class Event(BaseModel):
    ts: str
    kind: str


class DnsQueryEvent(Event):
    kind: Literal["dns_query"] = "dns_query"
    src: str
    dst: str
    transport: str
    qname: str
    qtype: str


class DnsAnswerEvent(Event):
    kind: Literal["dns_answer"] = "dns_answer"
    resolver: str
    qname: str
    rtype: str
    value: str
    ttl: int
    rcode: str = "NOERROR"
    # Which response section carried the record: answer, authority (SOA/NS
    # provenance for a referral/negative answer), or additional (glue).
    section: str = "answer"


class DnsEcsEvent(Event):
    # EDNS Client Subnet: the resolver forwards a truncated form of the client's
    # own IP prefix to the authoritative server — a location leak the operator
    # would otherwise never see, since it rides inside the OPT pseudo-record.
    kind: Literal["dns_ecs"] = "dns_ecs"
    src: str
    dst: str
    qname: str
    client_subnet: str


class DnsResponseEvent(Event):
    # A response with no answer section: the rcode is the disclosure
    # (NXDOMAIN/NODATA/SERVFAIL/REFUSED) — the host asked and was refused or
    # told nothing, an outcome that would otherwise vanish as no_disclosure.
    kind: Literal["dns_response"] = "dns_response"
    resolver: str
    qname: str
    qtype: str
    rcode: str


class DnsHttpsEvent(Event):
    # An HTTPS/SVCB (type 65/64) answer: the SvcParams disclose target IPs
    # (ipv4hint/ipv6hint), the negotiated protocol (alpn), and whether ECH is
    # offered — all before any connection is opened.
    kind: Literal["dns_https"] = "dns_https"
    resolver: str
    qname: str
    rtype: str
    priority: int
    target: str
    alpn: list[str] = Field(default_factory=list)
    port: int | None = None
    ipv4hint: list[str] = Field(default_factory=list)
    ipv6hint: list[str] = Field(default_factory=list)
    ech: bool = False
    ttl: int
    section: str = "answer"


class TlsSniEvent(Event):
    kind: Literal["tls_sni"] = "tls_sni"
    src: str
    dst: str
    dport: int
    sni: str
    transport: str = "tcp"
    # Cleartext ALPN from the ClientHello (h2/http/1.1/h3): survives ECH because
    # it rides the outer hello, and helps fingerprint the client software.
    alpn: list[str] = Field(default_factory=list)
    # Encrypted Client Hello present: `sni` is the public cover name, not the
    # real destination — the true hostname was hidden from the ISP.
    ech: bool = False


class HttpEvent(Event):
    kind: Literal["http"] = "http"
    src: str
    dst: str
    dport: int
    method: str
    host: str | None
    path: str
    user_agent: str | None
    tag: str | None = None


Birth = Literal["observed", "pre-existing", "datagram"]


class FlowEvent(Event):
    kind: Literal["flow"] = "flow"
    proto: str
    direction: str
    scope: str
    # "pre-existing" flags a TCP connection already open when we first saw it —
    # no opening SYN on the wire — the durable channels worth inventorying.
    birth: Birth
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    service: str
    hostname: str | None
    note: str | None = None


class ArpEvent(Event):
    # LAN host discovery: who-has (a host resolving a peer) and is-at (the
    # IP↔MAC binding that answers it) — every device announcing itself on-link.
    kind: Literal["arp"] = "arp"
    op: str
    sender_ip: str
    sender_mac: str
    target_ip: str
    target_mac: str | None = None


class Icmp6RaEvent(Event):
    # What the network advertises to every IPv6 host: the on-link prefix(es),
    # the router itself, and the recursive DNS servers (RDNSS) it hands out.
    kind: Literal["icmp6_ra"] = "icmp6_ra"
    router: str
    prefixes: list[str] = Field(default_factory=list)
    rdnss: list[str] = Field(default_factory=list)


class LlmnrEvent(Event):
    kind: Literal["llmnr"] = "llmnr"
    src: str
    dst: str
    qname: str
    qtype: str


class NbnsEvent(Event):
    kind: Literal["nbns"] = "nbns"
    src: str
    dst: str
    qname: str


KIND_TO_FILE = {
    "dns_query": "dns.jsonl",
    "dns_answer": "dns.jsonl",
    "dns_https": "dns.jsonl",
    "dns_response": "dns.jsonl",
    "dns_ecs": "dns.jsonl",
    "tls_sni": "tls.jsonl",
    "http": "http.jsonl",
    "flow": "flows.jsonl",
    "arp": "arp.jsonl",
    "icmp6_ra": "icmp6.jsonl",
    "llmnr": "llmnr.jsonl",
    "nbns": "nbns.jsonl",
}


def iso(ts: float) -> str:
    # Local wall-clock time with the local UTC offset (e.g. ...+08:00): netmon reports in
    # the timezone of whoever runs it — the feed, the detail pane, and the JSONL record
    # all read from this one authority. The offset keeps every timestamp unambiguous.
    return datetime.fromtimestamp(float(ts)).astimezone().isoformat(timespec="milliseconds")


# --- Live dashboard (--tui) presentation model -------------------------------
# All of this is Textual-free so it unit-tests as plain Python; netmon_tui.py is
# the only place that imports Textual. The rule matches the rest of the tool: one
# authority per fact — the feed's per-kind colour, direction glyph, and the
# HOST/NAME and DETAIL projections of an Event all live here, once.

# One truecolor style token per emitted kind, so a row is recognisable by colour
# at a glance. An invariant test asserts every KIND_TO_FILE key is covered.
KIND_STYLE: dict[str, str] = {
    "dns_query": "cyan",
    "dns_answer": "blue",
    "dns_https": "blue",
    "dns_response": "blue",
    "dns_ecs": "magenta",
    "tls_sni": "green",
    "http": "yellow",
    "flow": "white",
    "arp": "bright_black",
    "icmp6_ra": "magenta",
    "llmnr": "red",
    "nbns": "red",
}

# Client-originated disclosures leave the host (→ what you leak); resolver replies
# come back (←). Flows carry their own direction; link-scope frames get a dot.
_CLIENT_KINDS = frozenset({"dns_query", "tls_sni", "http", "dns_ecs", "llmnr", "nbns"})
_SERVER_KINDS = frozenset({"dns_answer", "dns_response", "dns_https"})
_FLOW_GLYPH = {"outbound": "→", "inbound": "←", "transit": "↔"}


# Dispatch on event.kind (the stable string discriminator), never on class identity.
# Running netmon.py as a script makes its Event classes `__main__.*`, while netmon_tui
# imports the `netmon.*` copies — so isinstance / class-pattern matching silently misses
# every event and blanks the HOST/DETAIL cells. cast is a runtime no-op, so it keeps
# mypy's field typing without depending on which module copy built the event.
def event_direction(event: Event) -> str:
    if event.kind == "flow":
        return _FLOW_GLYPH.get(cast(FlowEvent, event).direction, "·")
    if event.kind in _CLIENT_KINDS:
        return "→"
    if event.kind in _SERVER_KINDS:
        return "←"
    return "·"


_NAME_KINDS = frozenset(
    {"dns_query", "dns_answer", "dns_response", "dns_https", "dns_ecs", "llmnr", "nbns"}
)


def event_host(event: Event) -> str:
    # The single most identifying name for the row, pulled to the front column.
    match event.kind:
        case "tls_sni":
            return cast(TlsSniEvent, event).sni or "(ech)"
        case "http":
            http = cast(HttpEvent, event)
            return http.host or http.dst
        case "flow":
            flow = cast(FlowEvent, event)
            return flow.hostname or flow.remote_ip
        case "icmp6_ra":
            return cast(Icmp6RaEvent, event).router
        case "arp":
            return cast(ArpEvent, event).target_ip
        case k if k in _NAME_KINDS:
            return cast(DnsQueryEvent, event).qname  # every name-kind shares `qname`
        case _:
            return ""


def event_detail(event: Event) -> str:
    # The compact remainder that doesn't fit HOST/NAME, per kind.
    match event.kind:
        case "dns_query" | "llmnr":
            return cast(DnsQueryEvent, event).qtype
        case "nbns":
            return "name-query"
        case "dns_answer":
            a = cast(DnsAnswerEvent, event)
            base = f"{a.rtype} {a.value} ttl={a.ttl}"
            return base if a.section == "answer" else f"{base} {a.section}"
        case "dns_response":
            r = cast(DnsResponseEvent, event)
            return f"{r.qtype} {r.rcode}"
        case "dns_https":
            h = cast(DnsHttpsEvent, event)
            parts = [h.rtype]
            if h.alpn:
                parts.append("alpn=" + ",".join(h.alpn))
            if h.ech:
                parts.append("ech")
            hints = h.ipv4hint + h.ipv6hint
            if hints:
                parts.append("hints=" + ",".join(hints))
            return " ".join(parts)
        case "dns_ecs":
            return f"ecs {cast(DnsEcsEvent, event).client_subnet}"
        case "tls_sni":
            s = cast(TlsSniEvent, event)
            parts = [s.transport]
            if s.alpn:
                parts.append(",".join(s.alpn))
            if s.ech:
                parts.append("ech")
            return " ".join(parts)
        case "http":
            p = cast(HttpEvent, event)
            base = f"{p.method} {p.path}"
            return f"{base} [{p.tag}]" if p.tag else base
        case "flow":
            f = cast(FlowEvent, event)
            base = f"{f.service} {f.scope} {f.remote_ip}:{f.remote_port} {f.birth}"
            return f"{base} ({f.note})" if f.note else base
        case "arp":
            p2 = cast(ArpEvent, event)
            return f"{p2.op} {p2.sender_ip}={p2.sender_mac}"
        case "icmp6_ra":
            ra = cast(Icmp6RaEvent, event)
            parts = []
            if ra.prefixes:
                parts.append("pfx=" + ",".join(ra.prefixes))
            if ra.rdnss:
                parts.append("rdnss=" + ",".join(ra.rdnss))
            return " ".join(parts)
        case _:
            return ""


def event_to_cells(event: Event) -> list[str]:
    # TIME | KIND | DIR | HOST/NAME | DETAIL. Time is the HH:MM:SS.mmm slice of the ISO
    # ts the event already carries, which iso() renders in the host's local timezone.
    return [
        event.ts[11:23],
        event.kind,
        event_direction(event),
        event_host(event),
        event_detail(event),
    ]


class RateBucketer:
    # Events-per-second over a sliding window, for the feed's rate sparkline — the
    # processor has counts but no time axis. Buckets are keyed by integer second
    # and trimmed to the window so memory is bounded regardless of run length.
    def __init__(self, window: int = 60) -> None:
        self.window = window
        self._buckets: OrderedDict[int, int] = OrderedDict()

    def tick(self, now: float) -> None:
        sec = int(now)
        self._buckets[sec] = self._buckets.get(sec, 0) + 1
        cutoff = sec - self.window + 1
        while self._buckets and next(iter(self._buckets)) < cutoff:
            self._buckets.popitem(last=False)

    def series(self, now: float) -> list[float]:
        sec = int(now)
        start = sec - self.window + 1
        return [float(self._buckets.get(s, 0)) for s in range(start, sec + 1)]


class DashboardModel:
    # The Textual-free view state the processor doesn't keep: a bounded ring of the
    # most recent events (whole Event retained so the detail pane can show every
    # field) plus the events/sec bucketer. Per-kind counts, top hosts and coverage
    # are read straight off the PacketProcessor at render time — never duplicated
    # here. The substring `filter` is a view: add_event never drops, so toggling a
    # filter re-reveals events already in the ring.
    def __init__(
        self, cap: int = 1000, rate_window: int = 60, clock: Callable[[], float] = time.time
    ) -> None:
        self.cap = cap
        self._clock = clock
        self.rate = RateBucketer(rate_window)
        self.filter: str | None = None
        self._recent: OrderedDict[str, Event] = OrderedDict()
        self._seq = 0
        self._added: list[tuple[str, Event]] = []
        self._evicted: list[str] = []

    def add_event(self, event: Event) -> None:
        self.rate.tick(self._clock())
        key = str(self._seq)
        self._seq += 1
        self._recent[key] = event
        self._added.append((key, event))
        while len(self._recent) > self.cap:
            old_key, _ = self._recent.popitem(last=False)
            self._evicted.append(old_key)

    def drain_new(self) -> tuple[list[tuple[str, Event]], list[str]]:
        added, evicted = self._added, self._evicted
        self._added, self._evicted = [], []
        return added, evicted

    def recent(self, n: int) -> list[tuple[str, Event]]:
        return list(self._recent.items())[-n:]

    def newest_first(self) -> list[tuple[str, Event]]:
        # For a btop-style feed the latest event belongs at the top, so the ring is
        # walked from the most recent backwards.
        return list(self._recent.items())[::-1]

    def event_by_key(self, key: str) -> Event | None:
        return self._recent.get(key)

    def rate_series(self) -> list[float]:
        return self.rate.series(self._clock())

    def passes(self, event: Event) -> bool:
        if not self.filter:
            return True
        needle = self.filter.lower()
        return (
            needle in event.kind
            or needle in event_host(event).lower()
            or needle in event_detail(event).lower()
        )


EXT_SERVER_NAME = 0x0000
EXT_ALPN = 0x0010
EXT_ENCRYPTED_CLIENT_HELLO = 0xFE0D


class TlsClientHello(NamedTuple):
    sni: str | None
    ech: bool
    alpn: list[str]


def _parse_alpn(msg: bytes, pos: int, elen: int) -> list[str]:
    # ALPN extension body (RFC 7301): a 2-byte list length then length-prefixed
    # protocol IDs. Bounded by the extension's own length so a malformed inner
    # length can't walk past it.
    limit = min(pos + elen, len(msg))
    if pos + 2 > limit:
        return []
    p = pos + 2
    protocols: list[str] = []
    while p < limit:
        n = msg[p]
        p += 1
        if p + n > limit:
            break
        protocols.append(msg[p : p + n].decode("ascii", "replace"))
        p += n
    return protocols


def parse_handshake_client_hello(msg: bytes) -> TlsClientHello | None:
    # `msg` begins at the TLS handshake header: type(1) + length(3) + body.
    # Used for both TLS-over-TCP (after stripping the record header) and QUIC
    # CRYPTO streams (which carry handshake messages with no record layer).
    if len(msg) < 40 or msg[0] != 0x01:
        return None
    if len(msg) < 4 + int.from_bytes(msg[1:4]):
        return None  # handshake message not yet complete
    try:
        pos = 4 + 2 + 32  # handshake header + client_version + random
        pos += 1 + msg[pos]  # session_id
        pos += 2 + int.from_bytes(msg[pos : pos + 2])  # cipher_suites
        pos += 1 + msg[pos]  # compression_methods
        ext_end = pos + 2 + int.from_bytes(msg[pos : pos + 2])
        pos += 2
        sni: str | None = None
        ech = False
        alpn: list[str] = []
        while pos + 4 <= min(ext_end, len(msg)):
            etype = int.from_bytes(msg[pos : pos + 2])
            elen = int.from_bytes(msg[pos + 2 : pos + 4])
            pos += 4
            if etype == EXT_SERVER_NAME:
                name_len = int.from_bytes(msg[pos + 3 : pos + 5])
                if pos + 5 + name_len <= len(msg):
                    name = msg[pos + 5 : pos + 5 + name_len]
                    sni = name.decode("ascii", "replace") if name else None
            elif etype == EXT_ALPN:
                alpn = _parse_alpn(msg, pos, elen)
            elif etype == EXT_ENCRYPTED_CLIENT_HELLO:
                ech = True
            pos += elen
    except IndexError:
        return None
    if sni is None and not ech:
        return None
    return TlsClientHello(sni=sni, ech=ech, alpn=alpn)


def parse_client_hello(payload: bytes) -> TlsClientHello | None:
    # TLS record type 22 (handshake) wrapping a ClientHello (handshake type 1).
    if len(payload) < 44 or payload[0] != 0x16 or payload[5] != 0x01:
        return None
    # Wait for the whole record: a ClientHello split across TCP segments (now
    # common with post-quantum key shares) arrives incomplete.
    if len(payload) < 5 + int.from_bytes(payload[3:5]):
        return None
    return parse_handshake_client_hello(payload[5:])


QUIC_V1 = 0x00000001
QUIC_V2 = 0x6B3343CF
INITIAL_SALTS = {
    QUIC_V1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    QUIC_V2: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
}
INITIAL_PACKET_TYPE = {QUIC_V1: 0, QUIC_V2: 1}
RETRY_PACKET_TYPE = {QUIC_V1: 3, QUIC_V2: 0}  # RFC 9369 §3.2 permutes v2 types


def _is_quic_long_header(datagram: bytes) -> bool:
    # Cheap framing gate so QUIC is recognised by its long-header form on any
    # UDP datagram, not by port: fixed high bit set and a version we can key.
    return (
        len(datagram) >= 5
        and bool(datagram[0] & 0x80)
        and int.from_bytes(datagram[1:5], "big") in INITIAL_SALTS
    )


def _hkdf_expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    # TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1) with empty context.
    full = b"tls13 " + label
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + b"\x00"
    out = bytearray()
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return bytes(out[:length])


def derive_initial_keys(dcid: bytes, version: int) -> tuple[bytes, bytes, bytes]:
    # RFC 9001 §5.2: Initial keys come from the client's Destination Connection
    # ID and a public per-version salt — no secret input, so any observer can
    # derive them. Returns (key, iv, hp) for the client's Initial packets.
    initial_secret = hmac.new(INITIAL_SALTS[version], dcid, hashlib.sha256).digest()
    client_secret = _hkdf_expand_label(initial_secret, b"client in", 32)
    return (
        _hkdf_expand_label(client_secret, b"quic key", 16),
        _hkdf_expand_label(client_secret, b"quic iv", 12),
        _hkdf_expand_label(client_secret, b"quic hp", 16),
    )


def header_protection_mask(hp_key: bytes, sample: bytes) -> bytes:
    enc = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor()
    return enc.update(sample) + enc.finalize()


def packet_nonce(iv: bytes, packet_number: int) -> bytes:
    pn = packet_number.to_bytes(len(iv), "big")
    return bytes(a ^ b for a, b in zip(iv, pn, strict=True))


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    first = data[pos]
    length = 1 << (first >> 6)
    value = first & 0x3F
    for i in range(1, length):
        value = (value << 8) | data[pos + i]
    return value, pos + length


class _QuicPacket(NamedTuple):
    version: int
    dcid: bytes
    is_initial: bool
    first_off: int
    pn_offset: int
    end: int


def _parse_long_header(data: bytes, off: int) -> _QuicPacket | None:
    if off + 7 > len(data) or not (data[off] & 0x80):
        return None
    version = int.from_bytes(data[off + 1 : off + 5], "big")
    if version not in INITIAL_SALTS:
        return None
    ptype = (data[off] & 0x30) >> 4
    if ptype == RETRY_PACKET_TYPE[version]:  # Retry has no Length field
        return None
    try:
        pos = off + 5
        dcid_len = data[pos]
        pos += 1
        dcid = data[pos : pos + dcid_len]
        pos += dcid_len
        scid_len = data[pos]
        pos += 1 + scid_len
        is_initial = ptype == INITIAL_PACKET_TYPE[version]
        if is_initial:
            token_len, pos = _read_varint(data, pos)
            pos += token_len
        length, pos = _read_varint(data, pos)
        end = min(pos + length, len(data))
        return _QuicPacket(version, dcid, is_initial, off, pos, end)
    except IndexError:
        return None


def _decrypt_initial(
    data: bytes, pkt: _QuicPacket, key: bytes, iv: bytes, hp: bytes
) -> bytes | None:
    sample_off = pkt.pn_offset + 4
    sample = data[sample_off : sample_off + 16]
    if len(sample) < 16:
        return None
    mask = header_protection_mask(hp, sample)
    first = data[pkt.first_off] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    pn_bytes = bytes(data[pkt.pn_offset + i] ^ mask[1 + i] for i in range(pn_len))
    header = bytearray(data[pkt.first_off : pkt.pn_offset + pn_len])
    header[0] = first
    header[pkt.pn_offset - pkt.first_off :] = pn_bytes
    payload = data[pkt.pn_offset + pn_len : pkt.end]
    nonce = packet_nonce(iv, int.from_bytes(pn_bytes, "big"))
    try:
        return AESGCM(key).decrypt(nonce, payload, bytes(header))
    except Exception:
        return None


def _crypto_fragments(plaintext: bytes) -> list[tuple[int, bytes]]:
    frags: list[tuple[int, bytes]] = []
    pos = 0
    n = len(plaintext)
    try:
        while pos < n:
            ftype = plaintext[pos]
            pos += 1
            if ftype in (0x00, 0x01):  # PADDING, PING
                continue
            if ftype == 0x06:  # CRYPTO
                offset, pos = _read_varint(plaintext, pos)
                length, pos = _read_varint(plaintext, pos)
                frags.append((offset, plaintext[pos : pos + length]))
                pos += length
                continue
            if ftype in (0x02, 0x03):  # ACK / ACK_ECN
                pos = _skip_ack(plaintext, pos, ecn=ftype == 0x03)
                continue
            break  # unknown frame type — stop scanning
    except IndexError:
        pass
    return frags


def _skip_ack(data: bytes, pos: int, ecn: bool) -> int:
    _, pos = _read_varint(data, pos)  # largest acknowledged
    _, pos = _read_varint(data, pos)  # ack delay
    count, pos = _read_varint(data, pos)  # ack range count
    _, pos = _read_varint(data, pos)  # first ack range
    for _ in range(count):
        _, pos = _read_varint(data, pos)  # gap
        _, pos = _read_varint(data, pos)  # ack range length
    if ecn:
        for _ in range(3):  # ECT0, ECT1, ECN-CE counts
            _, pos = _read_varint(data, pos)
    return pos


def _reassemble(chunks: dict[int, bytes]) -> bytes:
    # Concatenate offset-keyed fragments contiguously from zero; stops at the
    # first gap, so an incomplete stream yields only its complete prefix.
    out = bytearray()
    pos = 0
    while pos in chunks:
        out += chunks[pos]
        pos += len(chunks[pos])
    return bytes(out)


class QuicReassembler:
    # Decrypt QUIC Initial packets and reassemble the CRYPTO stream (keyed by
    # the client's Destination Connection ID) until the ClientHello is whole.
    # Post-quantum ClientHellos span multiple Initials, and Initials coalesce
    # with later packets in one datagram — both are handled here. Initial keys
    # are publicly derivable, so a byte cap bounds memory against a flood of
    # valid-but-never-completing Initials.
    def __init__(
        self, max_conns: int = 2048, per_conn_cap: int = 65536, total_cap: int = 8_000_000
    ) -> None:
        self.max_conns = max_conns
        self.per_conn_cap = per_conn_cap
        self.total_cap = total_cap
        self.cleared = 0
        self.decrypt_failures = 0
        self._crypto: dict[bytes, dict[int, bytes]] = {}
        self._total = 0

    def add(self, datagram: bytes) -> TlsClientHello | None:
        off = 0
        result: TlsClientHello | None = None
        while off + 1 < len(datagram):
            pkt = _parse_long_header(datagram, off)
            if pkt is None:
                break
            if pkt.is_initial:
                hello = self._consume_initial(datagram, pkt)
                if hello is not None:
                    result = hello
            if pkt.end <= off:
                break
            off = pkt.end
        return result

    def _consume_initial(self, datagram: bytes, pkt: _QuicPacket) -> TlsClientHello | None:
        key, iv, hp = derive_initial_keys(pkt.dcid, pkt.version)
        plaintext = _decrypt_initial(datagram, pkt, key, iv, hp)
        if plaintext is None:
            self.decrypt_failures += 1
            return None
        fragments = _crypto_fragments(plaintext)
        if not fragments:
            return None
        buf = self._crypto.setdefault(pkt.dcid, {})
        conn_size = sum(len(v) for v in buf.values())
        for offset, chunk in fragments:
            if offset not in buf and conn_size < self.per_conn_cap and self._total < self.total_cap:
                buf[offset] = chunk
                conn_size += len(chunk)
                self._total += len(chunk)
        hello = parse_handshake_client_hello(_reassemble(buf))
        if hello is not None:
            self._total -= sum(len(v) for v in buf.values())
            self._crypto.pop(pkt.dcid, None)
        elif len(self._crypto) > self.max_conns or self._total > self.total_cap:
            self.cleared += len(self._crypto)
            self._crypto.clear()
            self._total = 0
        return hello


def redact_query_string(path: str) -> str:
    head, sep, _ = path.partition("?")
    return f"{head}?<redacted>" if sep else head


def _http_tag(host: str | None) -> str | None:
    if not host:
        return None
    name, sep, port = host.rpartition(":")  # tolerate a Host: header carrying :port
    hostname = name if sep and port.isdigit() else host
    return "captive-portal" if hostname.lower() in CAPTIVE_PORTAL_HOSTS else None


def parse_http_request(payload: bytes) -> tuple[str, str, str | None, str | None] | None:
    if not payload.startswith(HTTP_METHODS):
        return None
    # Wait for the full header block; a request split across segments is incomplete.
    if b"\r\n\r\n" not in payload:
        return None
    head = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    lines = head.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) < 3 or not parts[2].startswith("HTTP/"):
        return None
    host = user_agent = None
    for line in lines[1:]:
        name, _, value = line.partition(":")
        match name.lower():
            case "host":
                host = value.strip()
            case "user-agent":
                user_agent = value.strip()
    return parts[0], parts[1], host, user_agent


DNS_TYPE_SVCB = 64
DNS_TYPE_HTTPS = 65
SVCB_KEY_ALPN = 1
SVCB_KEY_PORT = 3
SVCB_KEY_IPV4HINT = 4
SVCB_KEY_ECH = 5
SVCB_KEY_IPV6HINT = 6


class SvcParams(NamedTuple):
    alpn: list[str]
    port: int | None
    ipv4hint: list[str]
    ipv6hint: list[str]
    ech: bool


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_svc_params(rr: Any) -> SvcParams:
    # Read the SvcParamKeys we surface out of a scapy DNSRRHTTPS/DNSRRSVCB
    # record. ech carries an encrypted config blob; only its presence matters.
    alpn: list[str] = []
    port: int | None = None
    ipv4hint: list[str] = []
    ipv6hint: list[str] = []
    ech = False
    for sp in _as_list(getattr(rr, "svc_params", None)):
        if sp.key == SVCB_KEY_ALPN:
            alpn = [
                v.decode("ascii", "replace") if isinstance(v, bytes) else str(v)
                for v in _as_list(sp.value)
            ]
        elif sp.key == SVCB_KEY_PORT:
            port = int(sp.value) if sp.value is not None else None
        elif sp.key == SVCB_KEY_IPV4HINT:
            ipv4hint = [str(v) for v in _as_list(sp.value)]
        elif sp.key == SVCB_KEY_IPV6HINT:
            ipv6hint = [str(v) for v in _as_list(sp.value)]
        elif sp.key == SVCB_KEY_ECH:
            ech = True
    return SvcParams(alpn, port, ipv4hint, ipv6hint, ech)


def rr_list(field: Any) -> list[Any]:
    if field is None:
        return []
    if isinstance(field, list):
        return field
    out = []
    current = field
    while isinstance(current, DNSQR | DNSRR):
        out.append(current)
        current = current.payload
    return out


def question_list(field: Any) -> list[Any]:
    # Questions are DNSQR. Older scapy links a DNS message's sections into one payload
    # chain (qd -> an/ns/ar), so walking qd runs into resource records; filter to DNSQR
    # so a DNSRR never reaches a .qname reader (a crash) or inflates the question count.
    return [q for q in rr_list(field) if isinstance(q, DNSQR)]


def decode_dns_name(value: Any) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return str(value).rstrip(".")


def decode_nbns_name(value: Any) -> str:
    # NBNS names are the decoded NetBIOS name scapy already unpacks, space-padded
    # to 16 chars with a trailing suffix byte; trim to the readable hostname.
    if isinstance(value, bytes):
        value = value.decode("ascii", "replace")
    return str(value).strip().rstrip("\x00").strip()


DNS_TYPE_SOA = 6


def _rdata_value(rr: Any) -> str:
    # SOA carries structured mname/rname rather than a flat rdata; flatten it to
    # the referral's primary NS and responsible mailbox for the answer value.
    if rr.type == DNS_TYPE_SOA:
        return f"{decode_dns_name(rr.mname)} {decode_dns_name(rr.rname)}"
    rdata = rr.rdata
    if isinstance(rdata, list):
        return ",".join(decode_dns_name(v) for v in rdata)
    return decode_dns_name(rdata)


# Sane upper bounds on DNS section counts: real messages carry a handful of
# records, so a header claiming thousands is a non-DNS payload we misread.
_DNS_MAX_QD = 20
_DNS_MAX_RR = 500


def parse_dns_message(payload: bytes) -> DNS | None:
    # Recognise DNS by shape, not port: scapy's DNS() never raises and will
    # round-trip arbitrary bytes, so validate the header counts against the
    # records actually decoded. A payload whose four section counts each match
    # its parsed record list is DNS; anything else (HTTP, QUIC, noise) is not.
    if len(payload) < 12:
        return None
    qd, an, ns, ar = struct.unpack_from(">HHHH", payload, 4)
    if qd > _DNS_MAX_QD or max(an, ns, ar) > _DNS_MAX_RR:
        return None
    try:
        dns = DNS(payload)
    except Exception:
        return None
    if (
        len(question_list(dns.qd)) != qd
        or len(rr_list(dns.an)) != an
        or len(rr_list(dns.ns)) != ns
        or len(rr_list(dns.ar)) != ar
    ):
        return None
    return dns


def _dns_tcp_start(payload: bytes) -> bool:
    # DNS over TCP frames each message with a 2-byte length prefix. Recognise the
    # framing cheaply so the reassembler only claims plausible DNS/TCP streams.
    if len(payload) < 2:
        return False
    length = int.from_bytes(payload[:2], "big")
    if length < 12:
        return False
    if len(payload) >= 14:
        qd, an, ns, ar = struct.unpack_from(">HHHH", payload, 6)
        if qd > _DNS_MAX_QD or max(an, ns, ar) > _DNS_MAX_RR:
            return False
    return True


def local_addresses() -> frozenset[str]:
    ips: set[str] = set()
    for iface in conf.ifaces.values():
        data = getattr(iface, "ips", None)
        if isinstance(data, dict):
            for fam_ips in data.values():
                ips.update(fam_ips)
        for attr in ("ip", "ip6"):
            value = getattr(iface, attr, None)
            if value:
                ips.add(value)
    return frozenset(ips)


def remote_scope(addr: str) -> str:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "lan"
    if ip.is_multicast:
        return "multicast"
    return "internet" if ip.is_global else "lan"


FlowKey = tuple[str, int, str, int]


def _client_stream_start(payload: bytes) -> bool:
    if payload.startswith(HTTP_METHODS):
        return True
    # TLS handshake record (0x16) with the TLS major version (0x03) whose
    # handshake type is ClientHello (0x01): excludes the server->client
    # ServerHello (type 0x02), and the version byte separates a real TLS record
    # from a DNS-over-TCP length prefix that merely happens to start 0x16.
    return (
        payload[:1] == b"\x16"
        and payload[1:2] == b"\x03"
        and (len(payload) < 6 or payload[5] == 0x01)
    )


class _Stream:
    __slots__ = ("base", "chunks", "size")

    def __init__(self, base: int) -> None:
        self.base = base  # TCP sequence number of the first tracked byte
        self.chunks: dict[int, bytes] = {}
        self.size = 0


class TcpReassembler:
    # Reassemble a client->server TCP stream by sequence number so a ClientHello
    # or HTTP request head split across segments parses once whole, regardless
    # of capture order or retransmission. Only flows that open with a
    # ClientHello record or an HTTP method are tracked, which bounds memory on
    # links dominated by encrypted application data.
    def __init__(self, per_flow_cap: int = 65536, total_cap: int = 4_000_000) -> None:
        self.per_flow_cap = per_flow_cap
        self.total_cap = total_cap
        self.cleared = 0
        self._flows: dict[FlowKey, _Stream] = {}
        self._total = 0

    def add(self, key: FlowKey, seq: int, payload: bytes) -> bytes:
        stream = self._flows.get(key)
        if stream is None:
            if not _client_stream_start(payload):
                return b""
            stream = _Stream(seq)
            self._flows[key] = stream
        offset = seq - stream.base
        if offset >= 0 and offset not in stream.chunks and stream.size < self.per_flow_cap:
            chunk = payload[: self.per_flow_cap - stream.size]
            stream.chunks[offset] = chunk
            stream.size += len(chunk)
            self._total += len(chunk)
            if self._total > self.total_cap:
                self.cleared += len(self._flows)
                self._flows.clear()
                self._total = 0
                return b""
        return _reassemble(stream.chunks)

    def drop(self, key: FlowKey) -> None:
        stream = self._flows.pop(key, None)
        if stream is not None:
            self._total -= stream.size


class _DnsStream:
    __slots__ = ("base", "chunks", "emitted", "size")

    def __init__(self, base: int) -> None:
        self.base = base
        self.chunks: dict[int, bytes] = {}
        self.size = 0
        self.emitted = 0  # bytes of the contiguous prefix already yielded


class DnsTcpReassembler:
    # Reassemble length-prefixed DNS over a TCP stream (2-byte length + message),
    # a sibling of TcpReassembler for the other direction of the wire: big
    # answers (AXFR/IXFR, large DNSSEC/TXT RRsets) span segments and would
    # otherwise be parsed only if they fit one. A stream is claimed only when its
    # first bytes frame a plausible DNS message, and it is byte-capped like the
    # other reassemblers so a stalled or hostile stream cannot grow unbounded.
    def __init__(self, per_flow_cap: int = 65536, total_cap: int = 4_000_000) -> None:
        self.per_flow_cap = per_flow_cap
        self.total_cap = total_cap
        self.cleared = 0
        self._flows: dict[FlowKey, _DnsStream] = {}
        self._total = 0

    def tracks(self, key: FlowKey) -> bool:
        return key in self._flows

    def add(self, key: FlowKey, seq: int, payload: bytes) -> list[bytes]:
        stream = self._flows.get(key)
        if stream is None:
            if not _dns_tcp_start(payload):
                return []
            stream = _DnsStream(seq)
            self._flows[key] = stream
        offset = seq - stream.base
        if offset >= 0 and offset not in stream.chunks and stream.size < self.per_flow_cap:
            chunk = payload[: self.per_flow_cap - stream.size]
            stream.chunks[offset] = chunk
            stream.size += len(chunk)
            self._total += len(chunk)
            if self._total > self.total_cap:
                self.cleared += len(self._flows)
                self._flows.clear()
                self._total = 0
                return []
        return self._complete_messages(stream)

    def _complete_messages(self, stream: _DnsStream) -> list[bytes]:
        assembled = _reassemble(stream.chunks)
        messages: list[bytes] = []
        pos = 0
        while pos + 2 <= len(assembled):
            length = int.from_bytes(assembled[pos : pos + 2], "big")
            end = pos + 2 + length
            if end > len(assembled):
                break  # message not yet whole
            if end > stream.emitted:  # only newly-completed messages
                messages.append(assembled[pos + 2 : end])
            pos = end
        stream.emitted = max(stream.emitted, pos)
        return messages

    def drop(self, key: FlowKey) -> None:
        stream = self._flows.pop(key, None)
        if stream is not None:
            self._total -= stream.size


class LruSet[K]:
    # Bounded membership with LRU eviction: re-seeing a key refreshes it, so
    # hot keys survive the cap while idle ones age out — unlike the previous
    # clear-at-cap, which forgot everything at once and re-emitted known flows.
    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.evicted = 0
        self._entries: OrderedDict[K, None] = OrderedDict()

    def add(self, key: K) -> bool:
        if key in self._entries:
            self._entries.move_to_end(key)
            return False
        self._entries[key] = None
        if len(self._entries) > self.cap:
            self._entries.popitem(last=False)
            self.evicted += 1
        return True

    def __len__(self) -> int:
        return len(self._entries)


class NameLedger:
    # The one authority for IP→hostname naming: first observation wins (the
    # DNS answer or SNI that first explained the address), LRU-bounded so CDN
    # sharding and IPv6 churn cannot grow it for the life of the process.
    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.evicted = 0
        self._names: OrderedDict[str, str] = OrderedDict()

    def observe(self, ip: str, name: str) -> None:
        if ip in self._names:
            self._names.move_to_end(ip)
            return
        self._names[ip] = name
        if len(self._names) > self.cap:
            self._names.popitem(last=False)
            self.evicted += 1

    def lookup(self, ip: str) -> str | None:
        name = self._names.get(ip)
        if name is not None:
            self._names.move_to_end(ip)
        return name

    def __len__(self) -> int:
        return len(self._names)


class BoundedCounter:
    # Only most_common(30) is ever read, so when the key population exceeds
    # `cap` the tail is flushed and the current top `keep` survive: hot keys
    # keep exact counts; a cold key seen again recounts from zero. The distinct
    # total keeps counting across flushes (an upper bound: a flushed-then-seen
    # key counts twice), so summary uniques stay honest about scale.
    def __init__(self, cap: int, keep: int | None = None) -> None:
        self.cap = cap
        self.keep = keep if keep is not None else max(30, cap // 10)
        self.distinct_estimate = 0
        self.flushed = 0
        self._counts: Counter[str] = Counter()

    def add(self, key: str) -> None:
        if key not in self._counts:
            self.distinct_estimate += 1
        self._counts[key] += 1
        if len(self._counts) > self.cap:
            kept = dict(self._counts.most_common(self.keep))
            self.flushed += len(self._counts) - len(kept)
            self._counts = Counter(kept)

    def most_common(self, n: int) -> list[tuple[str, int]]:
        return self._counts.most_common(n)

    def __len__(self) -> int:
        return len(self._counts)


FlowTuple = tuple[str, str, int, str, int]

_IP_PROTO_NAMES = {
    1: "icmp",
    2: "igmp",
    47: "gre",
    50: "esp",
    58: "icmpv6",
    89: "ospf",
    132: "sctp",
}


def _ip_proto_name(net: Any) -> str:
    # IPv6 .nh names the next header, which for a packet carrying extension
    # headers is that header rather than the upper-layer protocol — a rare label.
    proto = int(net.nh if isinstance(net, IPv6) else net.proto)
    return _IP_PROTO_NAMES.get(proto, f"ip_proto_{proto}")


class Coverage:
    # The one ledger of packet fate. Every packet the processor sees is tallied
    # under exactly one fate — became an event, deliberately skipped, an IP
    # protocol we don't decode, or handled-but-silent — so a clean event log can
    # never quietly stand in for an unaccounted gap. summary() reads it back
    # alongside the per-structure eviction counts and QUIC decrypt failures.
    def __init__(self) -> None:
        self.packets = 0
        self.fate: Counter[str] = Counter()

    def saw(self) -> None:
        self.packets += 1

    def mark(self, fate: str) -> None:
        self.fate[fate] += 1


class PacketProcessor:
    def __init__(
        self,
        local_ips: frozenset[str],
        redact_query: bool = True,
        name_cap: int = 65_536,
        counter_cap: int = 50_000,
        flow_cap: int = 200_000,
        discovery_cap: int = 65_536,
    ) -> None:
        self.redact_query = redact_query
        self.local_ips = local_ips
        self.reassembler = TcpReassembler()
        self.dns_tcp = DnsTcpReassembler()
        self.quic = QuicReassembler()
        self.names = NameLedger(name_cap)
        self.seen_flows: LruSet[FlowTuple] = LruSet(flow_cap)
        self.arp_seen: LruSet[Any] = LruSet(discovery_cap)
        self.ra_seen: LruSet[Any] = LruSet(discovery_cap)
        self.name_query_seen: LruSet[Any] = LruSet(discovery_cap)
        self.dns_names = BoundedCounter(counter_cap)
        self.sni_names = BoundedCounter(counter_cap)
        self.remote_hosts = BoundedCounter(counter_cap)
        self.event_counts: Counter[str] = Counter()
        self.coverage = Coverage()
        self._lo_recent: dict[int, float] = {}

    def _is_loopback_duplicate(self, pkt: Packet, t: float) -> bool:
        # Linux delivers each loopback frame to raw sockets twice (TX and RX copy)
        if getattr(pkt, "sniffed_on", None) != "lo":
            return False
        h = hash(bytes(pkt))
        last = self._lo_recent.get(h)
        self._lo_recent[h] = t
        if len(self._lo_recent) > 1024:
            self._lo_recent = {k: v for k, v in self._lo_recent.items() if t - v < 0.05}
        return last is not None and t - last < 0.05

    def _tally(self, events: list[Event], empty_fate: str) -> list[Event]:
        for event in events:
            self.event_counts[event.kind] += 1
        self.coverage.mark("event" if events else empty_fate)
        return events

    def process(self, pkt: Packet) -> list[Event]:
        # A passive monitor ingests untrusted, often malformed traffic; scapy accepts
        # many such packets and only raises when a field is read (a truncated record,
        # a header count that lies). One bad packet must never kill the capture loop,
        # so every parse runs under this guard: account the packet as a parse error and
        # move on. The packet is still counted (saw) so the fate ledger stays complete.
        self.coverage.saw()
        try:
            return self._process(pkt)
        except Exception:
            self.coverage.mark("parse_error")
            return []

    def _process(self, pkt: Packet) -> list[Event]:
        t = float(pkt.time)
        if self._is_loopback_duplicate(pkt, t):
            self.coverage.mark("loopback_dup")
            return []
        ts = iso(t)
        net = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if net is None:
            if pkt.haslayer(ARP):
                return self._tally(self._arp_events(ts, pkt[ARP]), "no_disclosure")
            self.coverage.mark("non_ip")
            return []
        events: list[Event] = []
        tcp = pkt.getlayer(TCP)
        udp = pkt.getlayer(UDP)
        is_ra = pkt.haslayer(ICMPv6ND_RA)

        if is_ra:
            events.extend(self._ra_events(ts, net, pkt[ICMPv6ND_RA]))

        if tcp is not None:
            flags = tcp.flags
            key: FlowKey = (net.src, tcp.sport, net.dst, tcp.dport)
            payload = bytes(tcp.payload)
            if payload:
                # Length-prefixed DNS on a client- or server-side stream reassembles
                # separately; everything else feeds the TLS/HTTP reassembler.
                if self.dns_tcp.tracks(key) or (
                    not _client_stream_start(payload) and _dns_tcp_start(payload)
                ):
                    for body in self.dns_tcp.add(key, int(tcp.seq), payload):
                        dns = parse_dns_message(body)
                        if dns is not None:
                            events.extend(self._dns_events(ts, net, dns, "tcp"))
                else:
                    stream = self.reassembler.add(key, int(tcp.seq), payload)
                    hello = parse_client_hello(stream) if stream else None
                    http = None if hello or not stream else parse_http_request(stream)
                    if hello is not None:
                        self.reassembler.drop(key)
                        events.append(self._sni_event(ts, net, tcp.dport, hello, "tcp"))
                    elif http:
                        self.reassembler.drop(key)
                        method, path, host, user_agent = http
                        events.append(
                            HttpEvent(
                                ts=ts,
                                src=net.src,
                                dst=net.dst,
                                dport=tcp.dport,
                                method=method,
                                path=redact_query_string(path) if self.redact_query else path,
                                host=host,
                                user_agent=user_agent,
                                tag=_http_tag(host),
                            )
                        )
            if flags.F or flags.R:
                self.reassembler.drop(key)
                self.dns_tcp.drop(key)
            birth: Birth = "observed" if (flags.S and not flags.A) else "pre-existing"
            events.extend(self._flow_event(ts, net, "tcp", tcp.sport, tcp.dport, birth))
        elif udp is not None:
            datagram = bytes(udp.payload)
            if pkt.haslayer(LLMNRQuery):
                events.extend(self._llmnr_events(ts, net, pkt[LLMNRQuery]))
            elif pkt.haslayer(NBNSQueryRequest):
                events.extend(self._nbns_events(ts, net, pkt[NBNSQueryRequest]))
            else:
                # Recognise DNS by shape on every port, never by scapy's port
                # binding alone: 53/5353 attract non-DNS noise (BitTorrent DHT,
                # QUIC, scans) that scapy will force-decode into a bogus DNS layer.
                # Shape validation is the single gate; it also covers local
                # forwarders / dnscrypt-proxy on custom ports.
                dns = parse_dns_message(datagram)
                if dns is not None:
                    events.extend(self._dns_events(ts, net, dns, "udp"))
                elif _is_quic_long_header(datagram):
                    hello = self.quic.add(datagram)
                    if hello:
                        events.append(self._sni_event(ts, net, udp.dport, hello, "quic"))
            events.extend(self._flow_event(ts, net, "udp", udp.sport, udp.dport, "datagram"))

        if tcp is None and udp is None and not is_ra:
            empty_fate = f"unhandled:{_ip_proto_name(net)}"
        else:
            empty_fate = "no_disclosure"
        return self._tally(events, empty_fate)

    def _sni_event(
        self, ts: str, net: Any, dport: int, hello: TlsClientHello, transport: str
    ) -> TlsSniEvent:
        sni = hello.sni or ""  # ECH-only hello has no cover name; ech still emits
        if sni:
            self.sni_names.add(sni)
            self.names.observe(net.dst, sni)
        return TlsSniEvent(
            ts=ts,
            src=net.src,
            dst=net.dst,
            dport=dport,
            sni=sni,
            transport=transport,
            alpn=hello.alpn,
            ech=hello.ech,
        )

    def _dns_events(self, ts: str, net: Any, dns: Any, transport: str) -> list[Event]:
        events: list[Event] = []
        queries = question_list(dns.qd)
        queried = decode_dns_name(queries[0].qname) if queries else ""
        if dns.qr == 0:
            for q in queries:
                qname = decode_dns_name(q.qname)
                self.dns_names.add(qname)
                events.append(
                    DnsQueryEvent(
                        ts=ts,
                        src=net.src,
                        dst=net.dst,
                        transport=transport,
                        qname=qname,
                        qtype=dnsqtypes.get(q.qtype, str(q.qtype)),
                    )
                )
        else:
            rcode = dns_rcode(dns.rcode)
            answers = rr_list(dns.an)
            # Attribute answers to the queried name, not each RR's own rrname: a
            # CNAME chain's final A record carries the CDN target as its rrname,
            # but the ledger must be seeded with the host the client asked for.
            for rr in answers:
                events.extend(self._record_event(ts, net.src, queried, rr, rcode, "answer"))
            # Authority (SOA/NS provenance for referrals/negatives) and additional
            # (glue A/AAAA, SVCB/HTTPS) carry disclosures under their own names.
            for rr in rr_list(dns.ns):
                name = decode_dns_name(rr.rrname)
                events.extend(self._record_event(ts, net.src, name, rr, rcode, "authority"))
            for rr in rr_list(dns.ar):
                name = decode_dns_name(rr.rrname)
                events.extend(self._record_event(ts, net.src, name, rr, rcode, "additional"))
            # An empty answer section still carries an outcome: record every
            # question with its rcode so NXDOMAIN/NODATA/REFUSED are not dropped.
            if not answers:
                for q in queries:
                    events.append(
                        DnsResponseEvent(
                            ts=ts,
                            resolver=net.src,
                            qname=decode_dns_name(q.qname),
                            qtype=dnsqtypes.get(q.qtype, str(q.qtype)),
                            rcode=rcode,
                        )
                    )
        events.extend(self._ecs_events(ts, net, queried, dns))
        return events

    def _record_event(
        self, ts: str, resolver: str, qname: str, rr: Any, rcode: str, section: str
    ) -> list[Event]:
        if isinstance(rr, DNSRROPT):
            return []  # EDNS OPT is a pseudo-record, surfaced via _ecs_events
        rtype = dnstypes.get(rr.type, str(rr.type))
        if rr.type in (DNS_TYPE_SVCB, DNS_TYPE_HTTPS):
            return [self._svcb_event(ts, resolver, qname, rtype, rr, section)]
        value = _rdata_value(rr)
        if rtype in ("A", "AAAA") and qname:
            self.names.observe(value, qname)
        return [
            DnsAnswerEvent(
                ts=ts,
                resolver=resolver,
                qname=qname,
                rtype=rtype,
                value=value,
                ttl=int(rr.ttl),
                rcode=rcode,
                section=section,
            )
        ]

    def _ecs_events(self, ts: str, net: Any, qname: str, dns: Any) -> list[Event]:
        events: list[Event] = []
        for rr in rr_list(dns.ar):
            if not isinstance(rr, DNSRROPT):
                continue
            for tlv in _as_list(rr.rdata):
                if isinstance(tlv, EDNS0ClientSubnet):
                    subnet = f"{tlv.address}/{int(tlv.source_plen)}"
                    events.append(
                        DnsEcsEvent(
                            ts=ts, src=net.src, dst=net.dst, qname=qname, client_subnet=subnet
                        )
                    )
        return events

    def _svcb_event(
        self, ts: str, resolver: str, qname: str, rtype: str, rr: Any, section: str = "answer"
    ) -> DnsHttpsEvent:
        params = parse_svc_params(rr)
        if qname:
            for ip in params.ipv4hint + params.ipv6hint:
                self.names.observe(ip, qname)
        return DnsHttpsEvent(
            ts=ts,
            resolver=resolver,
            qname=qname or decode_dns_name(rr.rrname),
            rtype=rtype,
            priority=int(rr.svc_priority),
            target=decode_dns_name(rr.target_name),
            alpn=params.alpn,
            port=params.port,
            ipv4hint=params.ipv4hint,
            ipv6hint=params.ipv6hint,
            ech=params.ech,
            ttl=int(rr.ttl),
            section=section,
        )

    def _arp_events(self, ts: str, arp: Any) -> list[Event]:
        op = {1: "who-has", 2: "is-at"}.get(int(arp.op), str(arp.op))
        sender_ip, sender_mac = str(arp.psrc), str(arp.hwsrc)
        target_ip, target_mac = str(arp.pdst), str(arp.hwdst)
        if not self.arp_seen.add((op, sender_ip, sender_mac, target_ip, target_mac)):
            return []
        return [
            ArpEvent(
                ts=ts,
                op=op,
                sender_ip=sender_ip,
                sender_mac=sender_mac,
                target_ip=target_ip,
                target_mac=None if target_mac == "00:00:00:00:00:00" else target_mac,
            )
        ]

    def _ra_events(self, ts: str, net: Any, ra: Any) -> list[Event]:
        prefixes: list[str] = []
        rdnss: list[str] = []
        opt = ra.payload
        while opt:
            if isinstance(opt, ICMPv6NDOptPrefixInfo):
                prefixes.append(f"{opt.prefix}/{int(opt.prefixlen)}")
            elif isinstance(opt, ICMPv6NDOptRDNSS):
                rdnss.extend(str(a) for a in opt.dns)
            opt = opt.payload
        router = str(net.src)
        if not self.ra_seen.add((router, tuple(prefixes), tuple(rdnss))):
            return []
        for addr in rdnss:
            self.names.observe(addr, RA_RDNSS_NAME)
        return [Icmp6RaEvent(ts=ts, router=router, prefixes=prefixes, rdnss=rdnss)]

    def _llmnr_events(self, ts: str, net: Any, llmnr: Any) -> list[Event]:
        if int(llmnr.qr) != 0:
            return []
        events: list[Event] = []
        for q in question_list(llmnr.qd):
            qname = decode_dns_name(q.qname)
            qtype = dnsqtypes.get(q.qtype, str(q.qtype))
            if not self.name_query_seen.add(("llmnr", net.src, qname, qtype)):
                continue
            events.append(LlmnrEvent(ts=ts, src=net.src, dst=net.dst, qname=qname, qtype=qtype))
        return events

    def _nbns_events(self, ts: str, net: Any, nbns: Any) -> list[Event]:
        qname = decode_nbns_name(nbns.QUESTION_NAME)
        if not self.name_query_seen.add(("nbns", net.src, qname)):
            return []
        return [NbnsEvent(ts=ts, src=net.src, dst=net.dst, qname=qname)]

    def _flow_event(
        self, ts: str, net: Any, proto: str, sport: int, dport: int, birth: Birth
    ) -> list[Event]:
        if net.src in self.local_ips:
            direction, local_ip, local_port, remote_ip, remote_port = (
                "outbound",
                net.src,
                sport,
                net.dst,
                dport,
            )
        elif net.dst in self.local_ips:
            direction, local_ip, local_port, remote_ip, remote_port = (
                "inbound",
                net.dst,
                dport,
                net.src,
                sport,
            )
        else:
            direction, local_ip, local_port, remote_ip, remote_port = (
                "transit",
                net.src,
                sport,
                net.dst,
                dport,
            )
        # Transit flows have no local end to normalize against, so dedup on the
        # sorted endpoint pair — otherwise the two directions of one connection
        # hash to different keys and emit twice.
        if direction == "transit":
            (ip_a, port_a), (ip_b, port_b) = sorted(((net.src, sport), (net.dst, dport)))
            key: FlowTuple = (proto, ip_a, port_a, ip_b, port_b)
        else:
            key = (proto, local_ip, local_port, remote_ip, remote_port)
        if not self.seen_flows.add(key):
            return []
        hostname = self.names.lookup(remote_ip)
        scope = remote_scope(remote_ip)
        if scope == "internet":
            self.remote_hosts.add(hostname or remote_ip)
        service = SERVICE_BY_PORT.get(
            (proto, remote_port), SERVICE_BY_PORT.get((proto, local_port), f"{proto}/{remote_port}")
        )
        return [
            FlowEvent(
                ts=ts,
                proto=proto,
                direction=direction,
                scope=scope,
                birth=birth,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                service=service,
                hostname=hostname,
                note=SERVICE_NOTES.get(service),
            )
        ]

    def summary(self) -> dict[str, Any]:
        return {
            "packets": self.coverage.packets,
            "events": dict(self.event_counts),
            "unique_dns_names": self.dns_names.distinct_estimate,
            "unique_sni_names": self.sni_names.distinct_estimate,
            "unique_internet_hosts": self.remote_hosts.distinct_estimate,
            "top_dns_names": dict(self.dns_names.most_common(30)),
            "top_sni_names": dict(self.sni_names.most_common(30)),
            "top_internet_hosts": dict(self.remote_hosts.most_common(30)),
            "coverage": self._coverage(),
        }

    def _coverage(self) -> dict[str, Any]:
        # Reads the packet-fate ledger plus each bounded structure's own record
        # of what it forgot. A `null` hostname or a missing name now has a
        # provenance: the operator can tell "never seen" from "seen then dropped".
        return {
            "packets": self.coverage.packets,
            "fate": dict(self.coverage.fate),
            "evicted": {
                "names": self.names.evicted,
                "flows": self.seen_flows.evicted,
                "arp": self.arp_seen.evicted,
                "router_ads": self.ra_seen.evicted,
                "name_queries": self.name_query_seen.evicted,
                "dns_names": self.dns_names.flushed,
                "sni_names": self.sni_names.flushed,
                "internet_hosts": self.remote_hosts.flushed,
                "tcp_streams": self.reassembler.cleared,
                "dns_tcp_streams": self.dns_tcp.cleared,
                "quic_streams": self.quic.cleared,
            },
            "parse_failed": {
                "quic_initial": self.quic.decrypt_failures,
                "packet": self.coverage.fate["parse_error"],
            },
        }


def open_private_new(path: Path) -> TextIO:
    # O_EXCL | O_NOFOLLOW: never adopt or follow a pre-staged file/symlink at
    # this path. netmon runs as root against a predictably-named run dir, so
    # following a symlink here would be a root arbitrary-write (CWE-59).
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    return os.fdopen(fd, "w", encoding="utf-8")


class Writer(Protocol):
    def write(self, event: Event) -> None: ...
    def write_summary(self, summary: dict[str, Any]) -> None: ...
    def close(self) -> None: ...


class JsonlWriter:
    # The run directory is the user's browsing history — keep it owner-only.
    def __init__(self, out_dir: Path) -> None:
        # Strict create: refuse to adopt a pre-existing (possibly symlinked or
        # foreign-owned) path — mkdir without exist_ok raises FileExistsError.
        out_dir.parent.mkdir(parents=True, exist_ok=True)
        out_dir.mkdir(mode=0o700)
        out_dir.chmod(0o700)
        self.out_dir = out_dir
        self._files: dict[str, TextIO] = {}

    def write(self, event: Event) -> None:
        name = KIND_TO_FILE[event.kind]
        f = self._files.get(name)
        if f is None:
            f = open_private_new(self.out_dir / name)
            self._files[name] = f
        f.write(event.model_dump_json(exclude_none=True) + "\n")
        f.flush()

    def write_summary(self, summary: dict[str, Any]) -> None:
        with open_private_new(self.out_dir / "summary.json") as f:
            f.write(json.dumps(summary, indent=2))

    def close(self) -> None:
        for f in self._files.values():
            f.close()


class NullWriter:
    # Ephemeral capture (`netmon run` without --log): stream to the live TUI only,
    # never touch disk — the DNS/TLS/HTTP record stays in memory and evaporates.
    def write(self, event: Event) -> None: ...
    def write_summary(self, summary: dict[str, Any]) -> None: ...
    def close(self) -> None: ...


# Python's socket module exposes neither constant (verified against
# /usr/include/linux/if_packet.h and man 7 packet).
SOL_PACKET = 263
PACKET_STATISTICS = 6


class CaptureStats(NamedTuple):
    queued: int
    userspace_dropped: int
    kernel_dropped: int | None  # None: this capture source cannot report kernel drops
    kernel_delivered: int | None = None  # tp_packets: the socket vs processor reconciliation


class Capture(Protocol):
    def packets(self) -> AsyncGenerator[Packet]: ...
    def stop(self) -> None: ...
    def stats(self) -> CaptureStats: ...


class LiveCapture:
    # Owns the AF_PACKET sockets instead of letting AsyncSniffer open them:
    # scapy never surfaces the kernel's tp_drops, so a loaded capture would
    # report dropped=0 while missing events — a falsely clean audit. Sockets
    # are passed as {socket: iface} so sniffed_on still carries the interface
    # name (the loopback dedup depends on it).
    def __init__(self, ifaces: list[str], bpf: str | None, queue_size: int = 50_000) -> None:
        self.ifaces = ifaces
        self.bpf = bpf
        self._queue: asyncio.Queue[Packet] = asyncio.Queue(maxsize=queue_size)
        self._stop = asyncio.Event()
        self._sockets: list[Any] = []
        self._userspace_dropped = 0
        self._kernel_dropped: int | None = None
        self._kernel_delivered: int | None = None

    def stop(self) -> None:
        self._stop.set()

    def stats(self) -> CaptureStats:
        for sock in self._sockets:
            try:
                # AttributeError: a libpcap-backed SuperSocket has no .ins
                buf = sock.ins.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
            except (AttributeError, OSError):
                continue
            # Reading PACKET_STATISTICS resets the kernel counters, so each poll
            # returns a delta of (tp_packets, tp_drops). getsockopt folds drops
            # into tp_packets (af_packet.c: `tp_packets += drops`), so the count
            # actually handed to userspace is tp_packets - tp_drops. Keeping it
            # lets the summary reconcile socket delivery against processor.packets.
            total, dropped = struct.unpack("2I", buf)
            self._kernel_dropped = (self._kernel_dropped or 0) + dropped
            self._kernel_delivered = (self._kernel_delivered or 0) + (total - dropped)
        return CaptureStats(
            self._queue.qsize(),
            self._userspace_dropped,
            self._kernel_dropped,
            self._kernel_delivered,
        )

    async def packets(self) -> AsyncGenerator[Packet]:
        loop = asyncio.get_running_loop()

        def on_packet(pkt: Packet) -> None:
            def enqueue() -> None:
                try:
                    self._queue.put_nowait(pkt)
                except asyncio.QueueFull:
                    self._userspace_dropped += 1

            loop.call_soon_threadsafe(enqueue)

        sniffer: AsyncSniffer | None = None
        try:
            for iface in self.ifaces:
                self._sockets.append(conf.L2listen(iface=iface, filter=self.bpf, promisc=False))
            sniffer = AsyncSniffer(
                opened_socket=dict(zip(self._sockets, self.ifaces, strict=True)),
                prn=on_packet,
                store=False,
            )
            sniffer.start()
            while not (self._stop.is_set() and self._queue.empty()):
                try:
                    yield await asyncio.wait_for(self._queue.get(), timeout=0.5)
                except TimeoutError:
                    continue
            sniffer.stop(join=True)
            while not self._queue.empty():  # packets that raced in during stop
                yield self._queue.get_nowait()
        finally:
            if sniffer is not None and sniffer.running:
                sniffer.stop(join=True)
            self.stats()  # final tp_drops harvest before the sockets close
            for sock in self._sockets:
                sock.close()


class ReplayCapture:
    # Second Capture implementation: feeds packets from a pcap file — a
    # deterministic, privilege-free source for tests and offline analysis.
    def __init__(self, path: Path) -> None:
        self.path = path
        self._stop = asyncio.Event()

    def stop(self) -> None:
        self._stop.set()

    def stats(self) -> CaptureStats:
        return CaptureStats(
            queued=0, userspace_dropped=0, kernel_dropped=None, kernel_delivered=None
        )

    async def packets(self) -> AsyncGenerator[Packet]:
        reader = PcapReader(str(self.path))
        try:
            for pkt in reader:
                if self._stop.is_set():
                    break
                yield pkt
        finally:
            reader.close()


def check_capture_privileges() -> None:
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.close()
    except PermissionError:
        log.error("insufficient_privileges", hint="run as root or grant cap_net_raw")
        sys.exit(1)


def _stamp_local_time(_logger: Any, _method: str, event_dict: Any) -> Any:
    # One timestamp authority: log lines carry the same local-with-offset ISO stamp as
    # event ts (structlog's own TimeStamper drops the offset), so a log line and the
    # event it describes are directly comparable.
    event_dict["timestamp"] = iso(time.time())
    return event_dict


def configure_logging(stream: TextIO | None = None) -> None:
    # stream lets --tui redirect structlog off stdout (which Textual owns) into a
    # file, so a stray log line never garbles the compositor.
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            _stamp_local_time,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(20),
        logger_factory=structlog.PrintLoggerFactory(file=stream or sys.stdout),
    )


class CopyResult(StrEnum):
    LOCAL = "local"  # a local clipboard CLI confirmed the copy (exit 0)
    TERMINAL = "terminal"  # OSC 52 emitted to the terminal — best-effort, unconfirmable
    FAILED = "failed"  # no clipboard path available


def _local_clipboard_argv(
    env: Mapping[str, str], which: Callable[[str], str | None]
) -> list[str] | None:
    # The first reachable local clipboard sink, or None. Wayland/X11 are gated on their
    # display env var so we never spawn a tool that will just fail to connect.
    if env.get("WAYLAND_DISPLAY") and (exe := which("wl-copy")):
        return [exe]
    if env.get("DISPLAY"):
        if exe := which("xclip"):
            return [exe, "-selection", "clipboard"]
        if exe := which("xsel"):
            return [exe, "--clipboard", "--input"]
    if exe := which("pbcopy"):
        return [exe]
    if exe := which("clip.exe"):
        return [exe]
    return None


def copy_to_clipboard(
    text: str,
    *,
    env: Mapping[str, str],
    write: Callable[[str], None] | None = None,
    run: Callable[..., Any] = subprocess.run,
    which: Callable[[str], str | None] = shutil.which,
) -> CopyResult:
    # Two layered paths. A local, non-SSH session writes straight to the OS clipboard via
    # a CLI: it bypasses the terminal and any tmux/screen in the way, and its exit code is
    # a real success signal. Otherwise (remote, or no local sink) fall back to OSC 52,
    # which is the only thing that can reach the user's clipboard down an SSH pipe but is
    # unconfirmable — the terminal, or an outer tmux with `set-clipboard on`, decides
    # whether it sticks.
    #
    # `env` selects the branch only; the spawned CLI inherits the real process environment
    # (DISPLAY/XAUTHORITY/PATH), never a stripped-down copy. SSH_CONNECTION/SSH_TTY guard
    # against writing the wrong machine's clipboard, but this is best-effort under sudo: a
    # bare `sudo` (env_reset) drops those vars, so a remote session that kept a local
    # DISPLAY through sudoers could misread as local. The --setcap deployment (no sudo)
    # has no such gap.
    remote = bool(env.get("SSH_CONNECTION") or env.get("SSH_TTY"))
    if not remote and (argv := _local_clipboard_argv(env, which)) is not None:
        try:
            proc = run(argv, input=text.encode(), capture_output=True, timeout=2)
        except (OSError, subprocess.SubprocessError):
            proc = None
        if proc is not None and proc.returncode == 0:
            return CopyResult.LOCAL
    if write is not None:
        payload = base64.b64encode(text.encode()).decode("ascii")
        write(f"\x1b]52;c;{payload}\a")
        return CopyResult.TERMINAL
    return CopyResult.FAILED


@dataclass
class Session:
    # One run's live state, so the headless loop and the --tui App share exactly
    # the same capture/parse/write pipeline and differ only in the per-event sink.
    out_dir: Path
    processor: PacketProcessor
    writer: Writer
    capture: Capture


def persist_enabled(args: argparse.Namespace) -> bool:
    # Single source of truth for "does this run write its DNS/TLS/HTTP record to disk".
    # Privacy-relevant, so both the JSONL writer and the TUI diagnostic log read it here
    # rather than each re-deciding. Absent `log` means a programmatic caller (the tests)
    # that wants files; the CLI sets it — `run` -> False (ephemeral), `run --log`/legacy -> True.
    return getattr(args, "log", True)


def build_session(args: argparse.Namespace) -> Session:
    os.umask(0o077)
    out_dir = Path(args.output) / datetime.now().strftime("run-%Y%m%d-%H%M%S")
    processor = PacketProcessor(local_addresses(), redact_query=not args.keep_query)
    writer: Writer = JsonlWriter(out_dir) if persist_enabled(args) else NullWriter()
    capture: Capture
    if args.read:
        capture = ReplayCapture(Path(args.read))
    else:
        # scapy's iface=None means conf.iface (default route only), not all interfaces
        ifaces = [args.iface] if args.iface else [i.name for i in get_working_ifaces()]
        capture = LiveCapture(ifaces, args.bpf)
    return Session(out_dir, processor, writer, capture)


def announce_start(args: argparse.Namespace, session: Session) -> None:
    if args.read:
        log.info("replay_started", pcap=args.read, output=str(session.out_dir))
    elif isinstance(session.capture, LiveCapture):
        log.info(
            "capture_started",
            ifaces=session.capture.ifaces,
            bpf=args.bpf,
            output=str(session.out_dir),
            local_ips=sorted(session.processor.local_ips),
        )


def log_event(event: Event) -> None:
    log.info(event.kind, **event.model_dump(exclude={"kind"}, exclude_none=True))


async def stats_loop(session: Session) -> None:
    while True:
        await asyncio.sleep(30)
        st = session.capture.stats()
        log.info(
            "stats",
            packets=session.processor.coverage.packets,
            events=dict(session.processor.event_counts),
            queue=st.queued,
            userspace_dropped=st.userspace_dropped,
            kernel_dropped="unavailable" if st.kernel_dropped is None else st.kernel_dropped,
            kernel_delivered=(
                "unavailable" if st.kernel_delivered is None else st.kernel_delivered
            ),
        )


async def consume(session: Session, on_event: Callable[[Event], None]) -> None:
    # The single shared loop. JSONL is written in both modes; only on_event differs
    # (per-event structlog when headless, model.add_event under --tui). The periodic
    # sleep(0) hands the event loop a turn every 64 packets so a burst drained from
    # the queue — or a synchronous pcap replay — cannot starve a co-running TUI
    # compositor or the 30 s stats task.
    n = 0
    async with aclosing(session.capture.packets()) as packets:
        async for pkt in packets:
            for event in session.processor.process(pkt):
                session.writer.write(event)
                on_event(event)
            n += 1
            if n % 64 == 0:
                await asyncio.sleep(0)


def finalize(session: Session) -> dict[str, Any]:
    st = session.capture.stats()
    summary = session.processor.summary()
    summary["capture"] = {
        "userspace_dropped": st.userspace_dropped,
        "kernel_dropped": "unavailable" if st.kernel_dropped is None else st.kernel_dropped,
        "kernel_delivered": (
            "unavailable" if st.kernel_delivered is None else st.kernel_delivered
        ),
    }
    session.writer.write_summary(summary)
    session.writer.close()
    return summary


async def run(args: argparse.Namespace) -> None:
    session = build_session(args)
    tui = getattr(args, "tui", False)  # Namespace in tests may lack .tui — never bare-access
    if not tui:
        announce_start(args, session)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, session.capture.stop)
    # No per-event stdout logging or 30 s stats line under --tui: both would write to
    # stdout, which Textual owns — the dashboard's own panels replace them.
    stats_task = None if tui else asyncio.create_task(stats_loop(session))
    try:
        if tui:
            from netmon_tui import run_dashboard

            await run_dashboard(session, args)
        else:
            await consume(session, log_event if not args.quiet else (lambda _e: None))
    finally:
        if stats_task is not None:
            stats_task.cancel()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(sig)
        # Runs on every exit path (quit, signal, exception): summary + coverage +
        # JSONL are flushed and the capture generator's own finally already harvested
        # the last tp_drops and closed the sockets via aclosing() in consume().
        summary = finalize(session)
        log.info(
            "capture_stopped",
            **{k: v for k, v in summary.items() if not k.startswith("top_")},
        )


def _add_capture_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("-i", "--iface", default=None, help="interface to capture (default: all)")
    p.add_argument("--bpf", default=None, help="BPF capture filter, e.g. 'not port 22'")
    p.add_argument(
        "-r",
        "--read",
        default=None,
        metavar="PCAP",
        help="replay packets from a pcap file instead of capturing live",
    )
    p.add_argument("-o", "--output", default="logs", help="output directory (default: logs)")
    p.add_argument("-q", "--quiet", action="store_true", help="no per-event stdout logging")
    p.add_argument(
        "--keep-query",
        action="store_true",
        help="log full HTTP request paths incl. query strings (may contain credentials)",
    )


def _legacy_parser() -> argparse.ArgumentParser:
    # The historical flat form (python netmon.py [flags]) — kept byte-for-byte so the
    # systemd unit, docs, and existing muscle memory keep working unchanged.
    p = argparse.ArgumentParser(
        description="Passive network monitor: logs DNS, TLS SNI, HTTP hosts, and flows as JSONL"
    )
    _add_capture_flags(p)
    p.add_argument(
        "--tui",
        action="store_true",
        help="live btop-style dashboard instead of stdout logs (JSONL still written)",
    )
    return p


def _run_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netmon run", description="live btop-style TUI dashboard (ephemeral unless --log)"
    )
    _add_capture_flags(p)
    p.add_argument(
        "--headless",
        action="store_true",
        help="no dashboard; classic per-event stdout logging",
    )
    p.add_argument(
        "--log",
        action="store_true",
        help="persist the JSONL record (and TUI diagnostics) to the output dir",
    )
    return p


def _install_dir() -> Path:
    return Path(__file__).resolve().parent


def cmd_update(argv: list[str]) -> int:
    # git pull + uv sync against this checkout. No raw socket, so no privileges needed
    # for the git/uv work itself (restarting the service does need root — see below).
    dir_ = _install_dir()
    git, uv = shutil.which("git"), shutil.which("uv")
    if not git or not uv:
        print("netmon update needs both git and uv on PATH", file=sys.stderr)
        return 1

    def git_(*a: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [git, "-C", str(dir_), *a], text=True, capture_output=True, check=False
        )

    if git_("rev-parse", "--is-inside-work-tree").returncode != 0:
        print(f"{dir_} is not a git checkout — reinstall via install.sh", file=sys.stderr)
        return 1
    if git_("status", "--porcelain").stdout.strip():
        print(
            "refusing to update: working tree has local changes (git stash first)",
            file=sys.stderr,
        )
        return 1
    old = git_("rev-parse", "--short", "HEAD").stdout.strip()
    pull = git_("pull", "--ff-only", "origin", "main")
    if pull.returncode != 0:
        print(pull.stderr.strip() or "git pull failed", file=sys.stderr)
        return 1
    sync = subprocess.run(
        [uv, "sync", "--extra", "tui", "--no-dev"], cwd=dir_, text=True, check=False
    )
    if sync.returncode != 0:
        print("uv sync failed", file=sys.stderr)
        return 1
    new = git_("rev-parse", "--short", "HEAD").stdout.strip()
    systemctl = shutil.which("systemctl")
    if systemctl and subprocess.run(
        [systemctl, "is-active", "--quiet", "netmon.service"], check=False
    ).returncode == 0:
        subprocess.run([systemctl, "restart", "netmon.service"], check=False)
        print("restarted netmon.service")
    print(f"netmon updated {old} -> {new}" if old != new else f"already up to date ({new})")
    return 0


def cmd_service(argv: list[str]) -> int:
    # Thin systemctl/journalctl passthrough for the background recorder unit.
    actions = {"start", "stop", "restart", "status", "enable", "disable", "logs"}
    if len(argv) != 1 or argv[0] not in actions:
        print(f"usage: netmon service {{{'|'.join(sorted(actions))}}}", file=sys.stderr)
        return 2
    action = argv[0]
    if action == "logs":
        tool = shutil.which("journalctl")
        cmd = [tool, "-u", "netmon.service", "-f"] if tool else []
    else:
        tool = shutil.which("systemctl")
        cmd = [tool, action, "netmon.service"] if tool else []
    if not cmd:
        print("systemd not available on this host", file=sys.stderr)
        return 1
    return subprocess.run(cmd, check=False).returncode


def _parse_run_args(argv: list[str]) -> argparse.Namespace:
    args = _run_parser().parse_args(argv)
    args.tui = not args.headless  # `run` shows the dashboard unless --headless
    return args


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] == "update":
        sys.exit(cmd_update(argv[1:]))
    if argv and argv[0] == "service":
        sys.exit(cmd_service(argv[1:]))
    if argv and argv[0] == "run":
        args = _parse_run_args(argv[1:])
    else:
        args = _legacy_parser().parse_args(argv)
    # Textual's driver reads raw stdin even when only stdout is a tty, so `--tui <file`
    # would parse file bytes as keystrokes — require both ends to be a real terminal.
    if getattr(args, "tui", False) and not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("--tui requires an interactive terminal (stdin and stdout)", file=sys.stderr)
        sys.exit(2)
    if not args.read:
        check_capture_privileges()
    configure_logging()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
