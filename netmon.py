"""Passive network monitor: DNS, TLS SNI, HTTP hosts, and flows to timestamped JSONL logs."""

import argparse
import asyncio
import base64
import contextlib
import csv
import errno
import hashlib
import hmac
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import string
import struct
import subprocess
import sys
import time
from collections import Counter, OrderedDict
from collections.abc import AsyncGenerator, Callable, Iterator, Mapping
from contextlib import aclosing
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum, StrEnum, auto
from pathlib import Path
from typing import Annotated, Any, BinaryIO, Literal, NamedTuple, Protocol, TextIO, cast

import structlog
from cryptography import x509
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, Field, TypeAdapter
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
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrRouting,
)
from scapy.layers.l2 import ARP
from scapy.layers.llmnr import LLMNRQuery
from scapy.layers.netbios import NBNSQueryRequest
from scapy.packet import Packet, Padding, Raw
from scapy.sendrecv import AsyncSniffer
from scapy.utils import PcapReader, PcapWriter

log = structlog.get_logger()

SERVICE_BY_PORT: dict[tuple[str, int], str] = {
    ("tcp", 21): "ftp",
    ("tcp", 22): "ssh",
    ("tcp", 23): "telnet",
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


# A hostname is a type, not a str. TLS SNI (RFC 6066 §3) and a certificate SAN dNSName
# (RFC 6125 §6.4) are the same grammar, and both name a server in the ledger and the feed
# — so what counts as a name is decided once, here, at the parse seam.
#
# The rule is an allowlist, which is what makes it a bound on ciphertext rather than a
# denylist chasing bad bytes: control characters, U+FFFD and binary are excluded by
# construction. It validates and does not normalise — case and IP literals pass through
# as sent, because netmon reports what the client did, not what the RFC wanted.
#
# DNS qnames deliberately do NOT pass through this: `_dmarc.x`, `1.0.0.10.in-addr.arpa`
# and mDNS instance labels are a wider grammar, and an LDH gate there would delete real
# telemetry. Nor is NameLedger typed on it — the ledger also holds qnames and the
# RA_RDNSS_NAME role marker, so the guarantee is a parse-seam one, not a ledger invariant.
_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
_HOSTNAME_RE = re.compile(rf"{_LABEL}(?:\.{_LABEL})*")
MAX_HOSTNAME_LEN = 253  # RFC 1035 §2.3.4: 255 wire octets -> 253 presentation characters


class Hostname(str):
    __slots__ = ()

    def __new__(cls, value: str) -> "Hostname":
        assert _HOSTNAME_RE.fullmatch(value), value  # bypassed parse(): programmer error
        return super().__new__(cls, value)

    @classmethod
    def parse(cls, raw: str) -> "Hostname | None":
        name = raw[:-1] if raw.endswith(".") else raw
        if not 1 <= len(name) <= MAX_HOSTNAME_LEN or not _HOSTNAME_RE.fullmatch(name):
            return None
        return cls(name)


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
    # None-typed fields default to None so a record the writer emits with
    # exclude_none=True (dropping the absent key) round-trips back through query.
    host: str | None = None
    path: str
    user_agent: str | None = None
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
    hostname: str | None = None  # absent (exclude_none) when unresolved; round-trips via query
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


# Parse a recorded JSONL line back into its concrete Event subclass, keyed on the
# `kind` discriminator every event carries. `netmon query` reads records this way so
# it can reuse event_host()'s one authority for "the identifying name of an event"
# instead of re-deriving per-kind host logic against raw dicts.
_AnyEvent = Annotated[
    DnsQueryEvent
    | DnsAnswerEvent
    | DnsEcsEvent
    | DnsResponseEvent
    | DnsHttpsEvent
    | TlsSniEvent
    | HttpEvent
    | FlowEvent
    | ArpEvent
    | Icmp6RaEvent
    | LlmnrEvent
    | NbnsEvent,
    Field(discriminator="kind"),
]
EVENT_ADAPTER: TypeAdapter[Event] = TypeAdapter(_AnyEvent)


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


# A terminal is an interpreter, and wire text is not ours to run. Rich and Textual strip
# only BEL/BS/VT/FF/CR, so neither a Text nor a Content stops an \x1b[2J in an HTTP path
# from driving the operator's cursor, a \n in a User-Agent from forging a line in the
# detail pane, or a U+202E in a DNS name from rendering moc.live.knab as bank.evil.com —
# hostname spoofing inside the tool whose whole job is naming the host that was contacted.
#
# Map, never drop: deleting the byte lies by omission, and the auditor needs to see it was
# there. Every substitution is one cell wide, so column widths are untouched. U+FFFD is
# left alone — it is already printable, and it is the parser's honest mark of a byte that
# would not decode.
#
# The JSONL record needs none of this: it goes through JSONRenderer / model_dump_json, and
# JSON escapes control bytes losslessly. The TUI and the clipboard are the only two places
# where wire text becomes raw bytes on a terminal.
_UNRENDERABLE: dict[int, str] = (
    {c: chr(0x2400 + c) for c in range(0x20)}  # C0 -> Unicode Control Pictures
    | {0x7F: "␡"}  # DEL
    | dict.fromkeys(range(0x80, 0xA0), "�")  # C1: 8-bit CSI/OSC in some terminals
    | dict.fromkeys(
        (
            0x2028,  # line separator: breaks a row exactly as \n does
            0x2029,
            0xFEFF,
            *range(0x200B, 0x2010),  # zero-width and directional marks
            *range(0x202A, 0x202F),  # bidi embeddings, incl. RIGHT-TO-LEFT OVERRIDE
            *range(0x2066, 0x206A),  # bidi isolates
        ),
        "�",
    )
)


def printable(value: str) -> str:
    # Applies to one wire field, never to an assembled block: the layout's own newlines are
    # added after this, which is what stops a wire \n from forging a line of its own.
    return value.translate(_UNRENDERABLE)


# A spreadsheet is an interpreter too, and the same rule applies: wire text is not ours to
# run. Excel and LibreOffice evaluate any cell whose first character is = + - @, so a DNS name
# of `=cmd|'/C calc'!A0`, recorded faithfully off the wire, becomes a command on the auditor's
# machine the moment they open the export.
#
# Same posture as printable(): map, never drop. A leading apostrophe is the spreadsheet's own
# "this cell is literal text" marker, so the original character stays visible and one strip
# recovers it — whereas deleting it would lie by omission about what was on the wire.
#
# frozenset, NOT a str: `"" in "=+-@"` is True, so a str membership test would stamp an
# apostrophe onto every empty cell in the file. There is a test.
_CSV_FORMULA_LEADERS = frozenset("=+-@")


def csv_cell(value: str) -> str:
    # printable() runs first and is idempotent, so a cell can never contain a newline: a row
    # is always one physical line, which keeps the export greppable and safe to `cat` on its
    # way to a terminal.
    text = printable(value)
    return f"'{text}" if text[:1] in _CSV_FORMULA_LEADERS else text


# --- Event classification ----------------------------------------------------
# Shared by the capture core, the dashboard's filter, and `netmon query`: three closed
# vocabularies and the total projections onto them. "Total" is the point — scope and
# direction used to be FlowEvent fields, so `query --scope internet` matched flows and
# nothing else, even though the DNS query and the SNI *are* the disclosure. Every kind has
# a peer at the other end, so every kind can be classified, and the filter predicate becomes
# a plain product of three set memberships with no per-kind special cases.

_CGNAT4 = ipaddress.ip_network("100.64.0.0/10")


def remote_scope(addr: str) -> str:
    # The reachability class of an address, finer than internet/lan so the feed can
    # tell carrier-NAT and link-local apart from a real private LAN. `_endpoint_is_local`
    # reads this to decide flow direction; the summary credits only `internet`.
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "lan"
    if ip.is_multicast:
        return "multicast"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "linklocal"
    if ip.version == 4 and ip in _CGNAT4:
        return "cgnat"  # RFC 6598 carrier-grade NAT: neither your LAN nor the internet
    return "internet" if ip.is_global else "lan"


# The three vocabularies a filter is built from, and the order their checkboxes are drawn
# in. KIND_VALUES is derived from KIND_TO_FILE rather than typed out again — a thirteenth
# kind must never be filterable-but-invisible, or invisible-but-filterable.
KIND_VALUES: tuple[str, ...] = tuple(sorted(KIND_TO_FILE))
DIRECTION_VALUES: tuple[str, ...] = ("outbound", "inbound", "local", "transit")
SCOPE_VALUES: tuple[str, ...] = ("internet", "cgnat", "lan", "linklocal", "loopback", "multicast")

# Client-originated disclosures leave the host (→ what you leak); resolver replies come
# back (←). Flows carry their own direction; link-scope frames are neither.
_CLIENT_KINDS = frozenset({"dns_query", "tls_sni", "http", "dns_ecs", "llmnr", "nbns"})
_SERVER_KINDS = frozenset({"dns_answer", "dns_response", "dns_https"})


# Dispatch on event.kind (the stable string discriminator), never on class identity.
# Running netmon.py as a script makes its Event classes `__main__.*`, while netmon_tui
# imports the `netmon.*` copies — so isinstance / class-pattern matching silently misses
# every event. Here that would not blank a cell, it would pass every event through every
# filter: a filter that looks like it does nothing. cast is a runtime no-op, so it keeps
# mypy's field typing without depending on which module copy built the event.
def event_remote_addr(event: Event) -> str:
    # The address of whoever is at the other end — the one authority for "who is not us".
    # Total over KIND_TO_FILE; a coverage test pins that.
    match event.kind:
        case "dns_query" | "dns_ecs" | "llmnr" | "nbns" | "tls_sni" | "http":
            return cast(DnsQueryEvent, event).dst  # every client kind shares `dst`
        case "dns_answer" | "dns_response" | "dns_https":
            return cast(DnsAnswerEvent, event).resolver
        case "flow":
            return cast(FlowEvent, event).remote_ip
        case "arp":
            return cast(ArpEvent, event).target_ip
        case "icmp6_ra":
            return cast(Icmp6RaEvent, event).router
        case _:
            return ""


def event_scope(event: Event) -> str:
    # Derived, never read off FlowEvent.scope: remote_scope() is the single authority, and a
    # flow's recorded scope *is* remote_scope(remote_ip) by construction (_flow_event), so
    # the two cannot disagree — a coherence test pins that. Deriving is what makes scope
    # total across all twelve kinds instead of a field only one of them carries.
    return remote_scope(event_remote_addr(event))


def event_direction_name(event: Event) -> str:
    if event.kind == "flow":
        direction = cast(FlowEvent, event).direction
        return direction if direction in DIRECTION_VALUES else "local"
    if event.kind in _CLIENT_KINDS:
        return "outbound"
    if event.kind in _SERVER_KINDS:
        return "inbound"
    return "local"  # arp / icmp6_ra: link-scope frames, which is what the "·" glyph means


# --- Leak findings -----------------------------------------------------------
# What each recorded event DISCLOSES, rated. Not alerts, not detections: netmon has no
# baseline, no threat intel and no notion of "unusual", and the README says so. The one rule
# that governs every rule below is:
#
#     A rule may only claim what the event's own fields prove.
#
# That bans the IDS shapes outright (novelty, beaconing, rare ports, volume — none of which
# a single event can evidence) and it equally bans over-claiming, which is the subtler
# failure: netmon never reads an SMTP payload, so it must not say credentials leaked.
#
# Findings are NEVER persisted per-event. assess() is a projection, like event_host — the
# JSONL stays raw evidence and severity stays recomputable interpretation, so improving a
# rule re-reads every run already on disk (including runs recorded before this existed) with
# no schema change, no migration, and nothing that can drift.


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# StrEnum compares LEXICALLY -- "high" < "low" < "medium" -- which is not severity order. A
# bare `>=` between two Severity values is a silent bug that would quietly mis-rank the whole
# panel, so every comparison goes through this map instead.
SEVERITY_RANK: dict[Severity, int] = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2}


class Rule(StrEnum):
    CLEARTEXT_HTTP = "cleartext-http"
    CLEARTEXT_DNS = "cleartext-dns"
    INTERNAL_NAME_ESCAPED = "internal-name-escaped"
    MDNS_BROADCAST = "mdns-broadcast"
    LAN_NAME_BROADCAST = "lan-name-broadcast"
    WPAD_BROADCAST = "wpad-broadcast"
    ECS_SUBNET = "ecs-subnet"
    PLAINTEXT_SERVICE = "plaintext-service"


class Finding(NamedTuple):
    # A NamedTuple, not a pydantic model: pydantic is reserved for things that came off the
    # wire. This is interpretation, and it never round-trips through a file.
    #
    # The diagnosis is three fields rather than one prose blob, because the panel wants the
    # subject and the detail pane wants the explanation, and splitting them later would mean
    # parsing our own sentences back apart.
    rule: Rule
    severity: Severity
    subject: str  # the aggregation key: the resolver, the host, the name, the device
    leaked: str  # what crossed the wire
    to: str  # and to whom
    advice: str  # what the operator can do about it


# How much a flow to each cleartext-capable service costs you. SERVICE_NOTES stays the one
# authority for the prose; this is the one authority for the severity, and a test pins that
# neither grows a key the other -- or SERVICE_BY_PORT -- has never heard of.
#
# ftp is HIGH because the protocol puts USER/PASS on the wire by design. The mail ports are
# MEDIUM, and the reason is the whole discipline in miniature: netmon does not read their
# payload, so it cannot know whether the client upgraded with STARTTLS before authenticating.
# Rating them HIGH would be claiming a credential leak nobody observed.
#
# `dns` is deliberately absent: the DnsQueryEvent is the authority for that disclosure, and
# listing it here too would count every plaintext lookup twice, once as a flow and once as a
# query.
SERVICE_LEAK: dict[str, Severity] = {
    "ftp": Severity.HIGH,
    "telnet": Severity.HIGH,
    "smtp": Severity.MEDIUM,
    "smtp-submission": Severity.MEDIUM,
    "imap": Severity.MEDIUM,
    "pop3": Severity.MEDIUM,
    "ntp": Severity.LOW,
    "http": Severity.LOW,
    "http-alt": Severity.LOW,
}

_STARTTLS_ADVICE = (
    "this port carries auth in cleartext unless the client upgrades with STARTTLS, and "
    "netmon cannot see whether it did — re-run with --pcap and open the flow in tshark to "
    "settle it"
)

# A name that was only ever meant for your own network. Leaking one to a public resolver
# hands over your internal topology — hostnames, naming scheme, sometimes the org chart.
_INTERNAL_SUFFIXES = (".local", ".internal", ".home.arpa", ".lan", ".corp", ".home")
_PRIVATE_PTR = ("in-addr.arpa", "ip6.arpa")

# Off-LAN scopes: a disclosure that reaches one of these has left your network.
_OFF_NET = frozenset({"internet", "cgnat"})

_DEMOTE = {
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.LOW,
}


def _ptr_address(name: str) -> str | None:
    # Rebuild the address a reverse-lookup name is asking about. Both forms reverse their
    # labels, but they do NOT reconstruct the same way, and treating them alike is a trap:
    # in-addr.arpa reverses four octets and rejoins them with dots, while ip6.arpa reverses
    # THIRTY-TWO nibbles that must be regrouped into hextets and joined with colons. Joining
    # nibbles with dots yields a string no parser accepts, remote_scope() then falls back to
    # "lan" for anything unparseable, and every public IPv6 PTR gets branded an escaped
    # internal name — a HIGH finding on ordinary reverse DNS, which is precisely the
    # cry-wolf failure the rules exist to avoid.
    if name.endswith(".in-addr.arpa"):
        labels = name.removesuffix(".in-addr.arpa").split(".")
        return ".".join(reversed(labels)) if len(labels) == 4 else None
    if name.endswith(".ip6.arpa"):
        nibbles = name.removesuffix(".ip6.arpa").split(".")
        if len(nibbles) != 32 or not all(n in string.hexdigits and len(n) == 1 for n in nibbles):
            return None  # a partial or malformed PTR proves nothing
        digits = "".join(reversed(nibbles))
        return ":".join(digits[i : i + 4] for i in range(0, 32, 4))
    return None


def _is_internal_name(qname: str) -> bool:
    name = qname.rstrip(".").casefold()
    if not name:
        return False
    if name.endswith(_INTERNAL_SUFFIXES):
        return True
    if "." not in name:
        return True  # a single label: a bare machine name, meaningless outside your LAN
    if name.endswith(_PRIVATE_PTR):
        # A reverse lookup only leaks topology if the address it asks about is private. An
        # address we cannot reconstruct proves nothing, so it is not a finding: silence beats
        # a false HIGH.
        addr = _ptr_address(name)
        return addr is not None and remote_scope(addr) not in _OFF_NET
    return False


def _ecs_prefix_len(client_subnet: str) -> int:
    # A resolver advertising a /0 is explicitly telling the authoritative side "do not use my
    # client's subnet". That is a leak PREVENTED, and flagging it would invert the truth the
    # tool exists to report.
    _, _, plen = client_subnet.partition("/")
    try:
        return int(plen)
    except ValueError:
        return 0


def assess(event: Event) -> Finding | None:
    # The fourth projection, beside event_direction / event_host / event_detail — same
    # dispatch on .kind, never isinstance, for the same reason (see event_remote_addr).
    #
    # At most ONE finding per event, never a list: the rule says what class of disclosure it
    # is and the severity says what it cost, so one-per-event makes double-counting
    # structurally impossible rather than a convention someone has to remember.
    scope = event_scope(event)
    if scope == "loopback":
        # A host talking to itself discloses nothing to anyone. This is not a nicety: the
        # single most common HTTP event on a developer's machine is a 127.0.0.1 REST call to
        # their own daemon, and a panel that screams about it is a panel nobody reads twice.
        return None

    match event.kind:
        case "http":
            http = cast(HttpEvent, event)
            host = http.host or http.dst
            if http.tag == "captive-portal":
                severity = Severity.LOW
            elif http.method in ("POST", "PUT", "PATCH"):
                severity = Severity.HIGH  # a body crossed the wire, in the clear
            else:
                severity = Severity.MEDIUM
            if scope not in _OFF_NET:
                severity = _DEMOTE[severity]
            agent = f", and identified this client as {http.user_agent}" if http.user_agent else ""
            return Finding(
                rule=Rule.CLEARTEXT_HTTP,
                severity=severity,
                subject=host,
                leaked=f"an unencrypted {http.method} for {host}{http.path}{agent}",
                to=f"{http.dst} and every hop in between ({scope})",
                advice="anyone on the path read this in full — prefer https for this host",
            )

        case "dns_query":
            query = cast(DnsQueryEvent, event)
            if scope == "multicast":
                return Finding(
                    rule=Rule.MDNS_BROADCAST,
                    severity=Severity.LOW,
                    subject=query.src,
                    leaked=f"a multicast lookup for {query.qname}",
                    to="every device on the local network",
                    advice="normal for service discovery; it tells your LAN what this device "
                    "is looking for",
                )
            if scope in _OFF_NET and _is_internal_name(query.qname):
                return Finding(
                    rule=Rule.INTERNAL_NAME_ESCAPED,
                    severity=Severity.HIGH,
                    subject=query.qname,
                    leaked=f"the internal name {query.qname}, which only means something "
                    "inside your network",
                    to=f"the public resolver {query.dst}",
                    advice="a search-domain or split-horizon DNS misconfiguration is leaking "
                    "your internal topology — fix the resolver config",
                )
            return Finding(
                rule=Rule.CLEARTEXT_DNS,
                severity=Severity.MEDIUM if scope in _OFF_NET else Severity.LOW,
                # The RESOLVER, not the name: one busy resolver is then one row with a count,
                # instead of a thousand rows that bury every other finding.
                subject=query.dst,
                leaked=f"every name this host looks up, in cleartext (e.g. {query.qname})",
                to=f"the resolver {query.dst} and every hop to it ({scope})",
                advice="use encrypted DNS (DoH/DoT) so the names are not readable on the path",
            )

        case "llmnr" | "nbns":
            name = cast(LlmnrEvent, event).qname
            if name.casefold().startswith("wpad"):
                return Finding(
                    rule=Rule.WPAD_BROADCAST,
                    severity=Severity.HIGH,
                    subject=name,
                    leaked="a broadcast asking the LAN who serves this host's proxy config",
                    to="every device on the local network",
                    advice="any device that answers becomes this host's web proxy — disable "
                    "WPAD, and disable LLMNR/NBNS",
                )
            return Finding(
                rule=Rule.LAN_NAME_BROADCAST,
                severity=Severity.MEDIUM,
                subject=name,
                leaked=f"a legacy name broadcast for {name}, naming this host to the LAN",
                to="every device on the local network",
                advice="LLMNR/NBNS are spoofable and answer to anyone — disable them if you "
                "do not need them",
            )

        case "dns_ecs":
            ecs = cast(DnsEcsEvent, event)
            if _ecs_prefix_len(ecs.client_subnet) == 0:
                return None  # /0 = "do not use my client's subnet": a leak prevented
            return Finding(
                rule=Rule.ECS_SUBNET,
                severity=Severity.MEDIUM,
                subject=ecs.client_subnet,
                leaked=f"your own network prefix {ecs.client_subnet}, inside the DNS lookup "
                f"for {ecs.qname}",
                to="the authoritative nameservers for every name you resolve",
                advice="EDNS Client Subnet is coarse geolocation of you — a resolver that "
                "sends /0 (or DoH to one that does) stops it",
            )

        case "flow":
            flow = cast(FlowEvent, event)
            severity = SERVICE_LEAK.get(flow.service, Severity.LOW)
            if flow.service not in SERVICE_LEAK:
                return None
            if scope not in _OFF_NET:
                severity = _DEMOTE[severity]
            where = flow.hostname or flow.remote_ip
            starttls = flow.service in ("smtp", "smtp-submission", "imap", "pop3")
            return Finding(
                rule=Rule.PLAINTEXT_SERVICE,
                severity=severity,
                subject=f"{flow.service} {where}",
                leaked=SERVICE_NOTES.get(
                    flow.service, f"a cleartext-capable {flow.service} channel was opened"
                ),
                to=f"{where}:{flow.remote_port} ({scope})",
                advice=_STARTTLS_ADVICE
                if starttls
                else "this service carries its content in the clear — prefer its TLS port",
            )

    return None


class FindingLedger:
    # Bounded and honest about it, like every other table here. Aggregates by
    # (rule, subject) with a count, which is what makes the highest-volume TRUE finding
    # readable: plaintext DNS to one resolver is a single row reading x1432, not 1432 rows
    # burying everything else.
    def __init__(self, cap: int = 500) -> None:
        self.cap = cap
        self.evicted = 0
        self._counts: dict[tuple[str, str], int] = {}
        self._findings: dict[tuple[str, str], Finding] = {}

    def add(self, finding: Finding) -> bool:
        key = (str(finding.rule), finding.subject)
        first = key not in self._counts
        self._counts[key] = self._counts.get(key, 0) + 1
        self._findings[key] = finding
        if len(self._counts) > self.cap:
            # Drop the lowest-severity, least-seen key — never a HIGH while a LOW survives.
            victim = min(
                self._counts,
                key=lambda k: (SEVERITY_RANK[self._findings[k].severity], self._counts[k]),
            )
            del self._counts[victim]
            del self._findings[victim]
            self.evicted += 1
        return first

    def top(self, n: int) -> list[tuple[Finding, int]]:
        rows = [(self._findings[k], c) for k, c in self._counts.items()]
        rows.sort(key=lambda r: (-SEVERITY_RANK[r[0].severity], -r[1]))
        return rows[:n]

    def by_severity(self) -> dict[str, int]:
        out: Counter[str] = Counter()
        for key, count in self._counts.items():
            out[str(self._findings[key].severity)] += count
        return dict(out)

    def summary(self, top: int = 30) -> dict[str, Any]:
        return {
            "by_severity": self.by_severity(),
            "by_rule": dict(
                Counter(
                    {
                        str(rule): sum(
                            c for k, c in self._counts.items() if self._findings[k].rule == rule
                        )
                        for rule in {f.rule for f in self._findings.values()}
                    }
                )
            ),
            "top": [
                {
                    "rule": str(f.rule),
                    "severity": str(f.severity),
                    "subject": f.subject,
                    "count": c,
                    "leaked": f.leaked,
                    "to": f.to,
                    "advice": f.advice,
                }
                for f, c in self.top(top)
            ],
            "evicted": self.evicted,
        }

    def __len__(self) -> int:
        return len(self._counts)


# --- Live dashboard (--tui) presentation model -------------------------------
# All of this is Textual-free so it unit-tests as plain Python; netmon_tui.py is
# the only place that imports Textual. The rule matches the rest of the tool: one
# authority per fact — the feed's per-kind colour, direction glyph, and the
# HOST/NAME and DETAIL projections of an Event all live here, once.

# One style and one single-cell glyph per severity, so the leaks panel aligns in a
# fixed-width column. An invariant test asserts every Severity is covered.
SEVERITY_STYLE: dict[Severity, str] = {
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim white",
}
SEVERITY_GLYPH: dict[Severity, str] = {
    Severity.HIGH: "!",
    Severity.MEDIUM: "•",
    Severity.LOW: "·",
}

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

_DIRECTION_GLYPH = {"outbound": "→", "inbound": "←", "transit": "↔", "local": "·"}


def event_direction(event: Event) -> str:
    # The glyph for the DIR cell. event_direction_name is the authority for *which* way;
    # this only says how to draw it, so the feed and the filter can never disagree.
    return _DIRECTION_GLYPH[event_direction_name(event)]


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
    #
    # The one presentation projection of an event, so the one place the wire-derived cells
    # are made safe to show. Deliberately not inside event_host/event_detail: those also
    # back DashboardModel.passes and `query --host`, where scrubbing would change what
    # matches, not just what is drawn.
    return [
        event.ts[11:23],
        event.kind,
        event_direction(event),
        printable(event_host(event)),
        printable(event_detail(event)),
    ]


CSV_COLUMNS = ("ts", "kind", "direction", "host", "detail")


def event_to_csv_row(event: Event) -> list[str]:
    # The same five projections the live feed shows. CSV is not a new idea about what an event
    # looks like flattened — event_to_cells already IS that idea, already scrubbed, already
    # tested per kind — so this re-serialises it rather than inventing a second schema that
    # could disagree with the first.
    #
    # Two changes the medium demands: the full ISO timestamp (the feed slices the date off
    # because it is a view of *now*; an exported run spans midnight and gets sorted in a
    # spreadsheet), and a formula-neutralised cell.
    #
    # The header is a projection, not a schema: a thirteenth event kind adds rows, never
    # columns, so nobody's pivot table breaks. Lossy by design — CSV is the dashboard's view,
    # the JSONL is the evidence.
    _, *rest = event_to_cells(event)
    return [csv_cell(cell) for cell in (event.ts, *rest)]


def event_to_detail(event: Event) -> str:
    # The detail pane's text, and the exact text `y` yanks — one authority, so what is
    # copied is what is on screen. Every field is scrubbed as a leaf, before the layout
    # adds its own newlines.
    data = event.model_dump(exclude_none=True)
    lines = [f"{event.kind}   {event.ts}"]
    lines += [f"  {k}: {printable(str(v))}" for k, v in data.items() if k not in ("kind", "ts")]
    return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class EventFilter:
    # The one filter, shared by the live feed and `netmon query` — there used to be two, with
    # different vocabularies and different semantics, agreeing on nothing but event_host().
    #
    # Each dimension holds THE SET OF VALUES THAT PASS: OR within a dimension, AND across
    # them. The defaults are the full vocabularies, so "unset" needs no special case in the
    # predicate and a checkbox group maps 1:1 onto a set — including the empty set, which
    # passes nothing. That is what "I ticked zero kinds" says, and reinterpreting it as "all"
    # would be the tool quietly overruling the operator. `host` is likewise the identity when
    # empty, since "" is a substring of everything.
    #
    # Display-only, on the TUI side: nothing here reaches the Writer or the pcap sink, and
    # add_event never drops, so re-ticking a box re-reveals events already captured.
    kinds: frozenset[str] = frozenset(KIND_VALUES)
    directions: frozenset[str] = frozenset(DIRECTION_VALUES)
    scopes: frozenset[str] = frozenset(SCOPE_VALUES)
    host: str = ""
    # The leak dimensions. None (not "the full set") means unconstrained, because unlike kind
    # or scope, most events have NO finding — so "filter by rule" has to mean "only events
    # that have one", while "don't filter by rule" must still pass the events that don't.
    min_severity: Severity | None = None
    rules: frozenset[str] | None = None

    def matches(self, event: Event) -> bool:
        if not (
            event.kind in self.kinds
            and event_direction_name(event) in self.directions
            and event_scope(event) in self.scopes
            and self.host.casefold() in event_host(event).casefold()
        ):
            return False
        if self.min_severity is None and self.rules is None:
            return True
        finding = assess(event)
        if finding is None:
            return False  # asked for leaks; this event is not one
        if (
            self.min_severity is not None
            and SEVERITY_RANK[finding.severity] < SEVERITY_RANK[self.min_severity]
        ):
            return False  # ranked, never compared as strings — see SEVERITY_RANK
        return self.rules is None or str(finding.rule) in self.rules

    def is_unconstrained(self) -> bool:
        # EVERY dimension, including the leak ones. Omitting them would let a filter that
        # hides most of the feed still report itself as "all" — the exact mistake the border
        # label exists to prevent.
        return (
            len(self.kinds) == len(KIND_VALUES)
            and len(self.directions) == len(DIRECTION_VALUES)
            and len(self.scopes) == len(SCOPE_VALUES)
            and not self.host
            and self.min_severity is None
            and self.rules is None
        )

    def label(self) -> str:
        # For the feed's border. A filtered feed must never be mistaken for a quiet network,
        # so this says what is hidden — counts only, to fit: "kind 3/12 · scope 1/6".
        if self.is_unconstrained():
            return "all"
        parts = [
            f"{name} {len(chosen)}/{len(whole)}"
            for name, chosen, whole in (
                ("kind", self.kinds, KIND_VALUES),
                ("dir", self.directions, DIRECTION_VALUES),
                ("scope", self.scopes, SCOPE_VALUES),
            )
            if len(chosen) != len(whole)
        ]
        if self.host:
            parts.append(f"host~{printable(self.host)}")
        if self.min_severity is not None:
            parts.append(f"leak>={self.min_severity}")
        if self.rules is not None:
            parts.append(f"rule {len(self.rules)}/{len(Rule)}")
        return " · ".join(parts)


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
    # here. The `filter` is a view: add_event never drops, so toggling a filter
    # re-reveals events already in the ring.
    def __init__(
        self, cap: int = 1000, rate_window: int = 60, clock: Callable[[], float] = time.time
    ) -> None:
        self.cap = cap
        self._clock = clock
        self.rate = RateBucketer(rate_window)
        self.filter: EventFilter = EventFilter()
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
        return self.filter.matches(event)


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


SNI_HOST_NAME = 0x00


def _parse_server_name(msg: bytes, pos: int, elen: int) -> Hostname | None:
    # server_name extension body (RFC 6066 §3): a 2-byte list length, then each entry as
    # name_type(1) + host_name_length(2) + host_name. Bounded by the extension's own
    # length, exactly as _parse_alpn is — reading `nlen` against len(msg) instead is what
    # let a coincidental 0x0000 extension in ciphertext hand back 200 bytes as an "SNI".
    limit = min(pos + elen, len(msg))
    if pos + 2 > limit:
        return None
    list_end = pos + 2 + int.from_bytes(msg[pos : pos + 2])
    if list_end > limit:
        return None  # the list length lies about its own extension
    # Only the first entry is read, and that is the whole rule: host_name(0) is the only
    # name_type RFC 6066 defines, and an undefined type has no defined body — so its length
    # field cannot be trusted to skip it and reach a later entry. Anything but a host_name
    # first is a malformed list, not a list to walk past.
    p = pos + 2
    if p + 3 > list_end or msg[p] != SNI_HOST_NAME:
        return None
    nlen = int.from_bytes(msg[p + 1 : p + 3])
    p += 3
    if p + nlen > list_end:
        return None
    try:
        return Hostname.parse(msg[p : p + nlen].decode("ascii"))
    except UnicodeDecodeError:
        return None


def parse_handshake_client_hello(msg: bytes) -> TlsClientHello | None:
    # `msg` begins at the TLS handshake header: type(1) + length(3) + body.
    # Used for both TLS-over-TCP (after stripping the record header) and QUIC
    # CRYPTO streams (which carry handshake messages with no record layer).
    if len(msg) < 40 or msg[0] != 0x01:
        return None
    body_end = 4 + int.from_bytes(msg[1:4])
    if len(msg) < body_end:
        return None  # handshake message not yet complete
    # Clip to this handshake message's own declared length so a lying extension/SNI
    # length field cannot read past it into a concatenated following record's bytes.
    msg = msg[:body_end]
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
                sni = _parse_server_name(msg, pos, elen)
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


TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01
TLS_SERVER_HELLO = 0x02
TLS_MAX_RECORD = 16384  # RFC 8446 §5.1: TLSPlaintext.length MUST NOT exceed 2^14


def _handshake_record_length(payload: bytes, pos: int = 0) -> int | None:
    # The one authority for "is this a TLS handshake record header, and how long is its
    # body". legacy_record_version is 0x0300-0x0303, a record may not exceed 2^14, and a
    # zero-length handshake fragment is forbidden (RFC 8446 §5.1) — bounds a ciphertext
    # byte pair has to clear before it can pose as the opening of a ClientHello.
    if pos + 5 > len(payload):
        return None
    if payload[pos] != TLS_HANDSHAKE or payload[pos + 1] != 0x03 or payload[pos + 2] > 0x03:
        return None
    length = int.from_bytes(payload[pos + 3 : pos + 5])
    return length if 1 <= length <= TLS_MAX_RECORD else None


def _handshake_record_spans(payload: bytes) -> Iterator[tuple[int, int]]:
    # Yield each consecutive complete TLS handshake record as its body's (start, end)
    # offsets — the one authoritative record walk. Stops at the first non-handshake
    # record or one whose declared length has not fully arrived.
    pos = 0
    while (length := _handshake_record_length(payload, pos)) is not None:
        end = pos + 5 + length
        if end > len(payload):
            return
        yield pos + 5, end
        pos = end


def _reassemble_handshake_records(payload: bytes) -> bytes:
    # Concatenate the payloads of consecutive TLS handshake records into one
    # handshake byte stream, stripping each 5-byte record header. A ClientHello over
    # the 16384-byte record limit (post-quantum key shares increasingly force this) is
    # fragmented across records; reading past the first record's payload would otherwise
    # dissect the next record's 5-byte header as handshake body and shift every SNI/ALPN
    # offset.
    out = bytearray()
    for start, end in _handshake_record_spans(payload):
        out += payload[start:end]
    return bytes(out)


class Scan(Enum):
    INCOMPLETE = auto()  # keep buffering: more bytes could still complete the message
    IMPOSSIBLE = auto()  # no future byte can make this stream disclose anything


# A hello we could never assemble is a hello we can never parse, so the give-up bound is
# the reassembler's own per-flow cap, not an invented number — TcpReassembler takes its
# default from here. Stated twice, they could drift apart, and a per_flow_cap raised to
# fit a larger post-quantum hello would start declaring legitimate streams IMPOSSIBLE
# before their buffer was even full: an auditor silently missing a real disclosure.
MAX_CLIENT_HELLO = 65536


def parse_client_hello(payload: bytes) -> TlsClientHello | Scan:
    # Three answers, not two. A stream that has not disclosed a ClientHello either has not
    # finished arriving or provably never will, and collapsing those into None is what let
    # a false-anchored ciphertext flow re-parse a growing 64 KB buffer on every segment
    # until FIN — squatting on the LRU budget that genuine pending ClientHellos need.
    if _handshake_record_length(payload) is None:
        return Scan.INCOMPLETE if len(payload) < 5 else Scan.IMPOSSIBLE
    if len(payload) >= 6 and payload[5] != TLS_CLIENT_HELLO:
        return Scan.IMPOSSIBLE
    # Reassemble consecutive handshake records first, so a ClientHello fragmented across
    # records (common with post-quantum key shares) is dissected as one message.
    handshake = _reassemble_handshake_records(payload)
    hello = parse_handshake_client_hello(handshake)
    if hello is not None:
        return hello
    if len(handshake) >= 4:
        declared = 4 + int.from_bytes(handshake[1:4])
        if declared > MAX_CLIENT_HELLO or len(handshake) >= declared:
            return Scan.IMPOSSIBLE  # unassemblable, or complete and it disclosed nothing
    if _cleartext_handshake_over(payload):
        return Scan.IMPOSSIBLE
    return Scan.INCOMPLETE


TLS_HANDSHAKE_CERTIFICATE = 0x0B


def _cleartext_handshake_over(payload: bytes) -> bool:
    # True once a record of a different content type follows the handshake records:
    # the cipher spec is changing (or already changed), so no further cleartext
    # handshake bytes can arrive on this stream.
    pos = 0
    for _, end in _handshake_record_spans(payload):
        pos = end
    return pos < len(payload) and payload[pos] != 0x16


def is_wildcard_name(name: str) -> bool:
    return name.startswith("*.")


def _certificate_name(raw: str) -> str | None:
    # A leaf SAN dNSName is the same grammar as an SNI (RFC 6125 §6.4), except that it may
    # be a wildcard. The wildcard is kept — a caller prefers a concrete SAN over one, so
    # the marker has to survive — which is why this returns a str: `*.example.com` names a
    # set of servers, so it is a pattern, not a Hostname.
    base = raw[2:] if is_wildcard_name(raw) else raw
    return raw if Hostname.parse(base) is not None else None


def _leaf_san_dns_names(body: bytes) -> list[str]:
    # Certificate message body (RFC 5246 §7.4.2): a 3-byte chain length, then each
    # certificate as 3-byte length + DER. Only the leaf (first) names this server.
    try:
        leaf_len = int.from_bytes(body[3:6])
        der = body[6 : 6 + leaf_len]
        if len(der) < leaf_len:
            return []
        cert = x509.load_der_x509_certificate(der)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = san.value.get_values_for_type(x509.DNSName)
    except Exception:
        # Untrusted DER off the wire: a malformed or SAN-less certificate discloses
        # nothing, and must never take down the capture loop.
        return []
    return [name for raw in names if (name := _certificate_name(raw)) is not None]


def extract_certificate_sans(payload: bytes) -> list[str] | None:
    # Walk the server's cleartext handshake flight for the TLS 1.2 Certificate
    # message and return the leaf's SAN DNS names. None means the flight is still
    # arriving — keep buffering. A list (possibly empty) is terminal: the caller can
    # stop buffering, because either the certificate was read or none can follow —
    # TLS 1.3 encrypts it, and a resumed TLS 1.2 handshake never sends one.
    hs = _reassemble_handshake_records(payload)
    pos = 0
    while pos + 4 <= len(hs):
        mlen = int.from_bytes(hs[pos + 1 : pos + 4])
        if pos + 4 + mlen > len(hs):
            break  # this handshake message has not fully arrived
        if hs[pos] == TLS_HANDSHAKE_CERTIFICATE:
            return _leaf_san_dns_names(hs[pos + 4 : pos + 4 + mlen])
        pos += 4 + mlen
    return [] if _cleartext_handshake_over(payload) else None


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
                # Skip a zero-length CRYPTO frame: it carries no data, and storing an
                # empty chunk both spun _reassemble forever and squatted its offset so
                # the real fragment there was rejected (a network-triggerable vector).
                if length:
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
    # first gap, so an incomplete stream yields only its complete prefix. Fragments
    # are keyed at exact offsets and matched exactly — an overlapping segment at an
    # off-boundary offset is skipped, which the DnsTcpReassembler's sliding window
    # relies on to drop straddling junk rather than blend it into the yielded tail.
    out = bytearray()
    pos = 0
    while chunks.get(pos):  # an empty chunk carries no bytes -> treat as the end, never spin
        out += chunks[pos]
        pos += len(chunks[pos])
    return bytes(out)


def _reassemble_merged(chunks: dict[int, bytes]) -> bytes:
    # Overlap-tolerant variant for the one-shot TCP client stream (ClientHello / HTTP
    # request head): walk fragments in offset order, building the contiguous prefix and
    # stopping at the first gap. Overlaps resolve first-data-wins — a fragment starting
    # within the bytes already assembled contributes only the tail that extends them —
    # so a retransmit repacketized at a different boundary merges cleanly instead of
    # truncating the stream early (the classic segment-overlap evasion). Unlike
    # _reassemble this must not feed a sliding window: it blends overlaps, so the caller
    # parses the whole result once and drops the stream.
    out = bytearray()
    for off in sorted(chunks):
        if off > len(out):
            break  # a genuine gap: the rest is not yet contiguous
        seg = chunks[off]
        if off + len(seg) > len(out):
            out += seg[len(out) - off :]
    return bytes(out)


def _crypto_size(buf: dict[int, bytes]) -> int:
    return sum(len(v) for v in buf.values())


class _HasSize(Protocol):
    size: int


def _stream_size(stream: _HasSize) -> int:
    return stream.size


def _evict_oldest[K, S](
    streams: OrderedDict[K, S],
    total: int,
    total_cap: int,
    size: Callable[[S], int],
    max_items: int | None = None,
) -> tuple[int, int]:
    # Evict least-recently-updated streams until back within the byte (and optional
    # count) cap, matching the LruSet/NameLedger pattern the rest of the codebase uses:
    # a burst of new streams ages out idle ones instead of wiping every in-flight
    # ClientHello/CRYPTO stream at once (which dropped many SNIs together, and for QUIC
    # was attacker-triggerable via publicly-derivable Initial keys). The most-recently-
    # touched stream — the one being processed — is at the tail and always kept: eviction
    # pops from the front and stops at the last entry. Returns the new total and the
    # number evicted, which the caller folds into its `cleared` coverage counter.
    evicted = 0
    while len(streams) > 1 and (
        total > total_cap or (max_items is not None and len(streams) > max_items)
    ):
        _, old = streams.popitem(last=False)
        total -= size(old)
        evicted += 1
    return total, evicted


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
        # A single stream can grow to per_conn_cap, so the total budget must hold at
        # least one; otherwise LRU could never bring a lone oversized stream under cap.
        assert total_cap >= per_conn_cap, "total_cap must hold at least one per-conn buffer"
        self.max_conns = max_conns
        self.per_conn_cap = per_conn_cap
        self.total_cap = total_cap
        self.cleared = 0
        self.decrypt_failures = 0
        self._crypto: OrderedDict[bytes, dict[int, bytes]] = OrderedDict()
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
        self._crypto.move_to_end(pkt.dcid)  # this connection is the one being processed
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
        self._total, evicted = _evict_oldest(
            self._crypto, self._total, self.total_cap, _crypto_size, self.max_conns
        )
        self.cleared += evicted
        return hello


def redact_query_string(path: str) -> str:
    head, sep, _ = path.partition("?")
    return f"{head}?<redacted>" if sep else head


def _http_tag(host: str | None) -> str | None:
    if not host:
        return None
    name, sep, port = host.rpartition(":")  # tolerate a Host: header carrying :port
    hostname = Hostname.parse(name if sep and port.isdigit() else host)
    if hostname is None:
        return None
    return "captive-portal" if hostname.lower() in CAPTIVE_PORTAL_HOSTS else None


class HttpRequest(NamedTuple):
    method: str
    path: str
    host: str | None
    user_agent: str | None


def parse_http_request(payload: bytes) -> HttpRequest | None:
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
    return HttpRequest(parts[0], parts[1], host, user_agent)


MAX_HTTP_HEAD = 16384  # 4x the usual server limit: a cookie-heavy request must still parse


def scan_client_stream(stream: bytes) -> TlsClientHello | HttpRequest | Scan:
    # The one question a buffered client stream is asked: what has it disclosed, and if
    # nothing, can it still? The reassembler decides whether its anchor still holds; this
    # decides whether the grammar can ever be satisfied. PacketProcessor only composes.
    if _http_request_start(stream) is not StreamStart.REJECTED:
        request = parse_http_request(stream)
        if request is not None:
            return request
        return Scan.IMPOSSIBLE if len(stream) > MAX_HTTP_HEAD else Scan.INCOMPLETE
    return parse_client_hello(stream)


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


def _looks_like_dns(payload: bytes) -> bool:
    # The cheap shape gate: a 12-byte header whose four section counts sit within
    # sane bounds. Necessary but not sufficient for DNS — a datagram that passes
    # this yet fails the full parse is DNS we could not decode, not mere noise,
    # and the caller counts it as such instead of losing it silently.
    if len(payload) < 12:
        return False
    qd, an, ns, ar = struct.unpack_from(">HHHH", payload, 4)
    return qd <= _DNS_MAX_QD and max(an, ns, ar) <= _DNS_MAX_RR


def parse_dns_message(payload: bytes) -> DNS | None:
    # Recognise DNS by shape, not port: scapy's DNS() never raises and will
    # round-trip arbitrary bytes, so validate the header counts against the
    # records actually decoded. A payload whose four section counts each match
    # its parsed record list is DNS; anything else (HTTP, QUIC, noise) is not.
    if not _looks_like_dns(payload):
        return None
    qd, an, ns, ar = struct.unpack_from(">HHHH", payload, 4)
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
    # conf.ifaces caches its enumeration at import; reload so a mid-run refresh sees
    # addresses assigned since boot-time (an RFC 4941 rotation, a DHCP renewal). A
    # failed reload keeps the cached view — stale beats dead for a passive monitor.
    # Safe to call off the event loop only because LiveCapture's packet hot path
    # never consults conf.ifaces after its sockets are opened; keep it that way.
    with contextlib.suppress(Exception):
        conf.ifaces.reload()
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


FlowKey = tuple[str, int, str, int]


class StreamStart(Enum):
    OPENS = auto()  # confirmed: these bytes open a stream worth tracking
    UNDECIDED = auto()  # consistent so far, too few bytes to confirm
    REJECTED = auto()  # provably not an opening


_TLS_RECORD_PREFIX = b"\x16\x03"


def _tls_hello_start(payload: bytes, handshake_type: bytes) -> StreamStart:
    # A prefix too short to carry the handshake type is UNDECIDED, never OPENS. A
    # ClientHello whose first TCP segment is three bytes must still anchor, or an attacker
    # segments their way past the monitor — but the guess has to be confirmed once the
    # bytes that settle it arrive. Trusting it forever is what let mid-stream ciphertext
    # anchor a flow and then pose as a ClientHello for the rest of the connection.
    if not (payload.startswith(_TLS_RECORD_PREFIX) or _TLS_RECORD_PREFIX.startswith(payload)):
        return StreamStart.REJECTED
    if not payload:
        return StreamStart.REJECTED
    if len(payload) < 6:
        return StreamStart.UNDECIDED
    if _handshake_record_length(payload) is None or payload[5:6] != handshake_type:
        return StreamStart.REJECTED
    return StreamStart.OPENS


def _http_request_start(payload: bytes) -> StreamStart:
    if payload.startswith(HTTP_METHODS):
        return StreamStart.OPENS
    if payload and any(method.startswith(payload) for method in HTTP_METHODS):
        return StreamStart.UNDECIDED
    return StreamStart.REJECTED


def _client_stream_start(payload: bytes) -> StreamStart:
    http = _http_request_start(payload)
    if http is not StreamStart.REJECTED:
        return http
    return _tls_hello_start(payload, b"\x01")


def _server_stream_start(payload: bytes) -> StreamStart:
    # The mirror gate for the server->client direction: a TLS handshake record whose
    # first handshake message is a ServerHello opens the flight that carries the TLS 1.2
    # Certificate in cleartext.
    return _tls_hello_start(payload, b"\x02")


class _Stream:
    __slots__ = ("base", "chunks", "confirmed", "size")

    def __init__(self, base: int, confirmed: bool) -> None:
        self.base = base  # TCP sequence number of the first tracked byte
        self.chunks: dict[int, bytes] = {}
        self.confirmed = confirmed
        self.size = 0


class TcpReassembler:
    # Reassemble one direction of a TCP stream by sequence number so a message
    # split across segments parses once whole, regardless of capture order or
    # retransmission. Only flows whose opening bytes pass the `start` anchor gate
    # (client direction: ClientHello record or HTTP method; server direction:
    # ServerHello record) are tracked, which bounds memory on links dominated by
    # encrypted application data.
    def __init__(
        self,
        per_flow_cap: int = MAX_CLIENT_HELLO,
        total_cap: int = 4_000_000,
        pending_cap: int = 262144,
        start: Callable[[bytes], StreamStart] = _client_stream_start,
    ) -> None:
        # A single stream can grow to per_flow_cap, so the total budget must hold at
        # least one; otherwise LRU could never bring a lone oversized stream under cap.
        assert total_cap >= per_flow_cap, "total_cap must hold at least one per-flow buffer"
        self.per_flow_cap = per_flow_cap
        self.total_cap = total_cap
        self.pending_cap = pending_cap
        self.start = start
        self.cleared = 0
        self._flows: OrderedDict[FlowKey, _Stream] = OrderedDict()
        self._total = 0
        # Segments seen before their flow's opening ClientHello/HTTP segment: a capture
        # that reorders the first two segments would otherwise drop the pre-anchor bytes
        # and lose the SNI. Held by absolute seq until the opening segment anchors the
        # stream and absorbs them. Byte-bounded with LRU eviction so the firehose of
        # non-opening segments (every server->client packet) cannot exhaust memory.
        self._pending: OrderedDict[FlowKey, dict[int, bytes]] = OrderedDict()
        self._pending_total = 0

    def tracks(self, key: FlowKey) -> bool:
        return key in self._flows

    def add(self, key: FlowKey, seq: int, payload: bytes) -> bytes:
        stream = self._flows.get(key)
        if stream is None:
            opening = self.start(payload)
            if opening is StreamStart.REJECTED:
                self._hold_pending(key, seq, payload)
                return b""
            stream = _Stream(seq, confirmed=opening is StreamStart.OPENS)
            self._flows[key] = stream
            # Store the verified opening segment's bytes before absorbing pending: the
            # anchor is authoritative, so unverified buffered data can only fill the
            # gaps it leaves, never pre-empt offset 0 (a segment-overlap evasion).
            self._store(stream, seq, payload)
            self._absorb_pending(key, stream)
        else:
            self._store(stream, seq, payload)
        merged = _reassemble_merged(stream.chunks)
        if not stream.confirmed:
            # A prefix too short to settle the question anchored this stream on a guess.
            # Put the question to the gate again now that more bytes are in hand, against
            # the contiguous prefix rather than one segment (a gap simply leaves the
            # anchor provisional). A disconfirmed guess gives the flow back.
            opening = self.start(merged)
            if opening is StreamStart.REJECTED:
                self.drop(key)
                return b""
            stream.confirmed = opening is StreamStart.OPENS
        self._flows.move_to_end(key)  # this stream is the one being processed
        self._total, evicted = _evict_oldest(self._flows, self._total, self.total_cap, _stream_size)
        self.cleared += evicted
        return merged

    def _store(self, stream: _Stream, seq: int, payload: bytes) -> None:
        offset = seq - stream.base
        if offset >= 0 and offset not in stream.chunks and stream.size < self.per_flow_cap:
            chunk = payload[: self.per_flow_cap - stream.size]
            stream.chunks[offset] = chunk
            stream.size += len(chunk)
            self._total += len(chunk)

    def _hold_pending(self, key: FlowKey, seq: int, payload: bytes) -> None:
        buf = self._pending.get(key)
        if buf is None:
            buf = self._pending[key] = {}
        self._pending.move_to_end(key)
        if seq not in buf:
            buf[seq] = payload
            self._pending_total += len(payload)
        while self._pending_total > self.pending_cap and self._pending:
            _, old = self._pending.popitem(last=False)  # evict least-recently-seen flow
            self._pending_total -= sum(len(v) for v in old.values())

    def _absorb_pending(self, key: FlowKey, stream: _Stream) -> None:
        buf = self._pending.pop(key, None)
        if buf is None:
            return
        self._pending_total -= sum(len(v) for v in buf.values())
        # Absorb in offset order so the earliest (SNI-bearing prefix) bytes win the
        # per-flow cap over a later-offset segment that arrived first.
        for pending_seq in sorted(buf):
            self._store(stream, pending_seq, buf[pending_seq])

    def drop(self, key: FlowKey) -> None:
        stream = self._flows.pop(key, None)
        if stream is not None:
            self._total -= stream.size
        buf = self._pending.pop(key, None)
        if buf is not None:
            self._pending_total -= sum(len(v) for v in buf.values())


class _DnsStream:
    __slots__ = ("base", "chunks", "size")

    def __init__(self, base: int) -> None:
        self.base = base  # TCP sequence of the first byte still buffered
        self.chunks: dict[int, bytes] = {}
        self.size = 0


class DnsTcpReassembler:
    # Reassemble length-prefixed DNS over a TCP stream (2-byte length + message),
    # a sibling of TcpReassembler for the other direction of the wire: big
    # answers (AXFR/IXFR, large DNSSEC/TXT RRsets) span segments and would
    # otherwise be parsed only if they fit one. A stream is claimed only when its
    # first bytes frame a plausible DNS message. The buffer is a sliding window:
    # each whole message is dropped once yielded, so per_flow_cap bounds only the
    # in-flight (partial) message — a long-lived DoT connection multiplexing a
    # device's whole lookup stream cannot exhaust the cap and fall silent.
    # per_flow_cap must exceed the largest single length-prefixed DNS/TCP message
    # (2-byte length + 65535-byte body = 65537), or that message would stall the
    # window at the cap and never complete; 128 KiB holds one such message plus
    # out-of-order slack while still bounding a stalled or hostile stream.
    def __init__(self, per_flow_cap: int = 131072, total_cap: int = 4_000_000) -> None:
        # A single stream can grow to per_flow_cap, so the total budget must hold at
        # least one; otherwise LRU could never bring a lone oversized stream under cap.
        assert total_cap >= per_flow_cap, "total_cap must hold at least one per-flow buffer"
        self.per_flow_cap = per_flow_cap
        self.total_cap = total_cap
        self.cleared = 0
        self._flows: OrderedDict[FlowKey, _DnsStream] = OrderedDict()
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
        self._flows.move_to_end(key)  # this stream is the one being processed
        offset = seq - stream.base
        if offset >= 0 and offset not in stream.chunks and stream.size < self.per_flow_cap:
            chunk = payload[: self.per_flow_cap - stream.size]
            stream.chunks[offset] = chunk
            stream.size += len(chunk)
            self._total += len(chunk)
            self._total, evicted = _evict_oldest(
                self._flows, self._total, self.total_cap, _stream_size
            )
            self.cleared += evicted
        assembled = _reassemble(stream.chunks)
        messages, consumed = self._complete_messages(assembled)
        if consumed:
            self._compact(stream, consumed, assembled)
        return messages

    def _complete_messages(self, assembled: bytes) -> tuple[list[bytes], int]:
        messages: list[bytes] = []
        pos = 0
        while pos + 2 <= len(assembled):
            length = int.from_bytes(assembled[pos : pos + 2], "big")
            end = pos + 2 + length
            if end > len(assembled):
                break  # message not yet whole
            messages.append(assembled[pos + 2 : end])
            pos = end
        return messages, pos

    def _compact(self, stream: _DnsStream, consumed: int, assembled: bytes) -> None:
        # Slide the window past the bytes already yielded as whole messages. `assembled`
        # is the canonical, gap-free prefix, so its unconsumed remainder is the whole
        # truth for that region — carried as one chunk at offset 0. Only genuine
        # segments *beyond* the first gap survive, re-keyed to the advanced base; every
        # chunk inside the prefix (a duplicate or an overlapping out-of-order segment)
        # is dropped rather than blended in, so it cannot collide onto offset 0 and
        # overwrite the real tail.
        boundary = len(assembled)
        retained: dict[int, bytes] = {}
        tail = assembled[consumed:]
        if tail:
            retained[0] = tail
        for off, chunk in stream.chunks.items():
            if off >= boundary:
                retained[off - consumed] = chunk
        new_size = sum(len(c) for c in retained.values())
        self._total -= stream.size - new_size
        stream.chunks = retained
        stream.size = new_size
        stream.base += consumed

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
    # The one authority for IP→hostname naming: last observation wins, so a shared
    # or CDN edge address re-attributes to the site the client most recently
    # resolved to it (temporal locality) instead of staying pinned to the first
    # name forever. LRU-bounded so CDN sharding and IPv6 churn cannot grow it for
    # the life of the process. The per-flow name is a best-effort hint — the
    # authoritative per-connection SNI lives in tls.jsonl.
    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.evicted = 0
        self._names: OrderedDict[str, str] = OrderedDict()

    def observe(self, ip: str, name: str) -> None:
        if ip in self._names:
            self._names[ip] = name  # re-attribute a reused IP to the newest name
            self._names.move_to_end(ip)
            return
        self._names[ip] = name
        if len(self._names) > self.cap:
            self._names.popitem(last=False)
            self.evicted += 1

    def observe_if_absent(self, ip: str, name: str) -> None:
        # A weak/placeholder name (e.g. an RA's RDNSS marker) only fills a gap: it
        # must never overwrite a real DNS/SNI name under last-wins, though a real
        # name observed later may still replace it.
        if ip not in self._names:
            self.observe(ip, name)

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


_IPV6_EXT_HDRS = (
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrRouting,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
)


def _innermost_net(net: Any) -> Any:
    # IPIP / 6in4 / 4in6: scapy nests the tunnelled header as the payload while
    # getlayer(TCP/UDP) already returns the innermost ports — descend so the flow's
    # endpoints are the real peers, not the tunnel's. Walks through v6 extension
    # headers and stops at any other encapsulation (GRE, ESP): there the outer flow
    # IS the honest record — the inner is out of decode scope. A fragmented layer
    # at ANY depth also stops the descent: a first-fragment dissects fully but
    # cannot vouch for a complete inner packet, and stopping there attributes both
    # fragments of the same tunnelled datagram to the same (fragmented) layer.
    while not _is_ip_fragment(net):
        nxt = net.payload
        while isinstance(nxt, _IPV6_EXT_HDRS):
            nxt = nxt.payload
        if not isinstance(nxt, (IP, IPv6)):
            break
        net = nxt
    return net


def _last_decoded_layer(pkt: Packet) -> str:
    # Name a frame by the deepest layer scapy decoded (skipping raw padding), so a
    # non-IP frame is accounted as what it was (LLC/STP/EAPOL/...), never a blank.
    layer = pkt.lastlayer()
    while isinstance(layer, (Raw, Padding)) and layer.underlayer is not None:
        layer = layer.underlayer
    return type(layer).__name__


def _is_ip_fragment(net: Any) -> bool:
    # A fragmented datagram cannot be decoded whole: the first fragment carries a
    # truncated L4 payload and later fragments carry no L4 header at all. Reassembly
    # itself stays a documented out-of-scope gap; the caller skips payload dissection
    # on a fragment and still records the flow, so the disclosure the fragment does
    # carry (endpoints) survives while its unreadable content is not mis-parsed.
    if isinstance(net, IP):
        return bool(net.flags.MF) or net.frag != 0
    # Walk only the outer header's own extension-header chain: a fragment header
    # quoted inside an ICMPv6 error's original packet must not flag the error itself.
    layer = net.payload
    while isinstance(layer, _IPV6_EXT_HDRS):
        if isinstance(layer, IPv6ExtHdrFragment):
            return True
        layer = layer.payload
    return False


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
        finding_cap: int = 500,
    ) -> None:
        self.redact_query = redact_query
        self.local_ips = local_ips
        self.reassembler = TcpReassembler()
        self.certs = TcpReassembler(start=_server_stream_start)
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
        self.findings = FindingLedger(finding_cap)
        self.tls_sni_cleartext = 0
        self.tls_sni_ech = 0
        self.coverage = Coverage()
        self.dns_parse_failures = 0
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
        # The single walk every emitted event already takes, so findings are tallied
        # identically under the dashboard, headless, replay and the systemd recorder —
        # the recorder being the one with no dashboard, and so the one that depends
        # entirely on the summary. consume(), the writers and KIND_TO_FILE are untouched.
        for event in events:
            self.event_counts[event.kind] += 1
            if event.kind == "tls_sni":
                # Counters, not a rule: a cleartext-SNI *rule* would fire on nearly every
                # flow, and an alert that always fires carries no information. The ratio is
                # the useful form of the same fact — how much of this run was ECH-protected.
                if cast(TlsSniEvent, event).ech:
                    self.tls_sni_ech += 1
                else:
                    self.tls_sni_cleartext += 1
            if (finding := assess(event)) is not None:
                self.findings.add(finding)
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
            self.coverage.mark(f"non_ip:{_last_decoded_layer(pkt)}")
            return []
        # A fragment's payload is truncated (first) or absent (later), so its L4
        # content cannot be dissected — but a first fragment still carries the L4
        # header, so the flow disclosure it bears is recorded below; only the
        # unreadable payload is skipped, and a fragment that yields no event lands
        # under the ip_fragment fate rather than no_disclosure/unhandled.
        # A whole header may be a tunnel (IPIP, 6in4, 4in6): the flow's real
        # endpoints are the innermost header's, and the descent stops at the first
        # fragmented layer — which is then the one this packet is accounted to.
        net = _innermost_net(net)
        fragmented = _is_ip_fragment(net)
        events: list[Event] = []
        cert_san = False
        tcp = pkt.getlayer(TCP)
        udp = pkt.getlayer(UDP)
        is_ra = pkt.haslayer(ICMPv6ND_RA)

        if is_ra:
            events.extend(self._ra_events(ts, net, pkt[ICMPv6ND_RA]))

        if tcp is not None:
            flags = tcp.flags
            key: FlowKey = (net.src, tcp.sport, net.dst, tcp.dport)
            payload = bytes(tcp.payload)
            if payload and not fragmented:
                # Length-prefixed DNS on a client- or server-side stream reassembles
                # separately; everything else feeds the TLS/HTTP reassemblers —
                # client direction first, then the server's certificate flight.
                if self.dns_tcp.tracks(key) or (
                    not self.reassembler.tracks(key)
                    and not self.certs.tracks(key)
                    and _client_stream_start(payload) is StreamStart.REJECTED
                    and _server_stream_start(payload) is StreamStart.REJECTED
                    and _dns_tcp_start(payload)
                ):
                    for body in self.dns_tcp.add(key, int(tcp.seq), payload):
                        dns = parse_dns_message(body)
                        if dns is not None:
                            events.extend(self._dns_events(ts, net, dns, "tcp"))
                        elif _looks_like_dns(body):
                            self.dns_parse_failures += 1
                else:
                    stream = self.reassembler.add(key, int(tcp.seq), payload)
                    found = scan_client_stream(stream) if stream else Scan.INCOMPLETE
                    if isinstance(found, TlsClientHello):
                        self.reassembler.drop(key)
                        events.append(self._sni_event(ts, net, tcp.dport, found, "tcp"))
                    elif isinstance(found, HttpRequest):
                        self.reassembler.drop(key)
                        events.append(
                            HttpEvent(
                                ts=ts,
                                src=net.src,
                                dst=net.dst,
                                dport=tcp.dport,
                                method=found.method,
                                path=redact_query_string(found.path)
                                if self.redact_query
                                else found.path,
                                host=found.host,
                                user_agent=found.user_agent,
                                tag=_http_tag(found.host),
                            )
                        )
                    else:
                        if found is Scan.IMPOSSIBLE:
                            self.reassembler.drop(key)
                        if not self.reassembler.tracks(key):
                            # Not the client's opening flight: try the server->client
                            # direction, where a TLS 1.2 certificate names this server
                            # even when no SNI was ever captured. A key mid-ClientHello
                            # is skipped — it can never be the server's flight, and
                            # buffering it again would let bulk client traffic evict
                            # genuinely pending server segments.
                            flight = self.certs.add(key, int(tcp.seq), payload)
                            sans = extract_certificate_sans(flight) if flight else None
                            if sans is not None:
                                self.certs.drop(key)
                                if sans:
                                    # One name per server IP, wildcards last: a concrete
                                    # SAN paints the sharper picture. Fills gaps only —
                                    # never overwrites a DNS/SNI-learned name.
                                    concrete = [s for s in sans if not is_wildcard_name(s)]
                                    self.names.observe_if_absent(net.src, (concrete or sans)[0])
                                    cert_san = True
            if flags.F or flags.R:
                self.reassembler.drop(key)
                self.certs.drop(key)
                self.dns_tcp.drop(key)
            birth: Birth = "observed" if (flags.S and not flags.A) else "pre-existing"
            events.extend(self._flow_event(ts, net, "tcp", tcp.sport, tcp.dport, birth))
        elif udp is not None:
            if not fragmented:
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
                    elif _looks_like_dns(datagram):
                        self.dns_parse_failures += 1  # DNS by shape, undecodable whole
            events.extend(self._flow_event(ts, net, "udp", udp.sport, udp.dport, "datagram"))

        if fragmented:
            empty_fate = "ip_fragment"
        elif tcp is None and udp is None and not is_ra:
            empty_fate = f"unhandled:{_ip_proto_name(net)}"
        elif cert_san:
            # A certificate that named its server disclosed something even though no
            # event was emitted — never bookkeep it as no_disclosure.
            empty_fate = "cert_san"
        else:
            empty_fate = "no_disclosure"
        return self._tally(events, empty_fate)

    def _sni_event(
        self, ts: str, net: Any, dport: int, hello: TlsClientHello, transport: str
    ) -> TlsSniEvent:
        sni = hello.sni or ""  # ECH-only hello has no cover name; ech still emits
        if sni:
            # DNS is case-insensitive (RFC 4343), so the counter keys on the folded name
            # or it buckets Example.com and example.com apart. The event keeps the bytes
            # as sent: the index normalises, the record does not.
            self.sni_names.add(sni.lower())
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
            self.names.observe_if_absent(addr, RA_RDNSS_NAME)
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

    def refresh_local_ips(self, ips: frozenset[str]) -> None:
        # Address rotation (RFC 4941 privacy addresses, a DHCP renewal) adds own
        # addresses mid-run; a frozen set would misclassify their egress as transit.
        # Replaces the set atomically — reassembly, ledgers, and seen flows are
        # untouched. An empty set is a failed enumeration, never the new truth:
        # keeping the last-known addresses beats flipping every own flow to transit.
        if ips:
            self.local_ips = ips

    def _endpoint_is_local(self, ip: str) -> bool:
        # Local = an address on this host OR one that is structurally on-link
        # (private/link-local/loopback). The own-IP half keeps a globally-addressed
        # host (public IP, un-NAT'd IPv6) classifying its own egress as outbound; the
        # address-class half lets a mirror/SPAN deployment classify LAN peers it does
        # not own. Carrier NAT and the internet are deliberately not local.
        return ip in self.local_ips or remote_scope(ip) in ("loopback", "linklocal", "lan")

    def _flow_event(
        self, ts: str, net: Any, proto: str, sport: int, dport: int, birth: Birth
    ) -> list[Event]:
        src_local = self._endpoint_is_local(net.src)
        # A multicast destination is link-scoped, so a flow to it stays on the LAN.
        dst_local = self._endpoint_is_local(net.dst) or remote_scope(net.dst) == "multicast"
        if src_local and dst_local:
            direction, local_ip, local_port, remote_ip, remote_port = (
                "local",
                net.src,
                sport,
                net.dst,
                dport,
            )
        elif src_local:
            direction, local_ip, local_port, remote_ip, remote_port = (
                "outbound",
                net.src,
                sport,
                net.dst,
                dport,
            )
        elif dst_local:
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
        # 'local' and 'transit' flows have no single local end to normalize against, so
        # they dedup on the sorted endpoint pair — otherwise the two legs of one
        # connection (incl. a loopback host talking to itself) hash to different keys
        # and emit twice.
        if direction in ("local", "transit"):
            (ip_a, port_a), (ip_b, port_b) = sorted(((net.src, sport), (net.dst, dport)))
            key: FlowTuple = (proto, ip_a, port_a, ip_b, port_b)
        else:
            key = (proto, local_ip, local_port, remote_ip, remote_port)
        if not self.seen_flows.add(key):
            return []
        hostname = self.names.lookup(remote_ip)
        scope = remote_scope(remote_ip)
        # A 'local' flow's remote end is a LAN/loopback address — or, for a self-connect
        # on a globally-routable own IP, this host itself — so it must never be credited
        # as a top internet host, even when its scope resolves to "internet".
        if scope == "internet" and direction != "local":
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
            # The headless recorder has no dashboard, so this is the only surface its
            # findings have. An empty block means no known-shape disclosure was recorded —
            # never that nothing leaked (see the README's "does NOT show you").
            "findings": self.findings.summary(),
            "tls_sni_cleartext": self.tls_sni_cleartext,
            "tls_sni_ech": self.tls_sni_ech,
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
                "findings": self.findings.evicted,
                "tcp_streams": self.reassembler.cleared,
                "cert_streams": self.certs.cleared,
                "dns_tcp_streams": self.dns_tcp.cleared,
                "quic_streams": self.quic.cleared,
            },
            "parse_failed": {
                "quic_initial": self.quic.decrypt_failures,
                "dns": self.dns_parse_failures,
                "packet": self.coverage.fate["parse_error"],
            },
        }


def _open_private_fd(path: Path) -> int:
    # O_EXCL | O_NOFOLLOW: never adopt or follow a pre-staged file/symlink at
    # this path. netmon runs as root against a predictably-named run dir, so
    # following a symlink here would be a root arbitrary-write (CWE-59).
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)


def open_private_new(path: Path) -> TextIO:
    return os.fdopen(_open_private_fd(path), "w", encoding="utf-8")


def open_private_new_bytes(path: Path) -> BinaryIO:
    return os.fdopen(_open_private_fd(path), "wb")


def _reraise_symlink_refusal(exc: OSError) -> None:
    # The O_EXCL|O_NOFOLLOW refusal of a pre-staged file/symlink (CWE-59) surfaces
    # as EEXIST/ELOOP. It must never be swallowed by the disk-full degrade path, so
    # it re-raises here while ENOSPC and its kin fall through to be counted.
    if exc.errno in (errno.EEXIST, errno.ELOOP):
        raise exc


def _rotation_archives(directory: Path, stem: str, suffix: str) -> list[Path]:
    # Ordered oldest-first by sequence NUMBER: a lexical sort misorders the ring
    # once the counter outgrows its zero padding (100000 < 99999 lexically) and
    # would prune the newest archives. Non-numeric middles are not ours — skip.
    found = []
    for path in directory.glob(f"{stem}.*.{suffix}"):
        seq_text = path.name[len(stem) + 1 : -(len(suffix) + 1)]
        if seq_text.isdigit():
            found.append((int(seq_text), path))
    return [path for _, path in sorted(found)]


def _roll_archive(path: Path, seq: int, keep: int) -> None:
    # Rename the full active file to its numbered archive and prune the ring.
    # rename inside the 0700 run dir preserves the 0600 mode and cannot be
    # symlink-swapped by an outsider. A failed prune only leaves the ring briefly
    # over-bound; the next roll retries it.
    stem, _, suffix = path.name.partition(".")
    path.rename(path.with_name(f"{stem}.{seq:05d}.{suffix}"))
    with contextlib.suppress(OSError):
        archives = _rotation_archives(path.parent, stem, suffix)
        for old in archives[: max(0, len(archives) - keep)]:
            old.unlink()


def _log_write_failure(event: str, exc: Exception, **fields: str) -> None:
    # The --tui --log path redirects structlog onto a file inside the run dir — the
    # same disk these sinks use — so logging a write failure can itself hit ENOSPC.
    # The failure report must never re-crash the run it exists to keep up.
    with contextlib.suppress(OSError):
        log.error(event, error=str(exc), **fields)


class Writer(Protocol):
    write_failures: int

    def write(self, event: Event) -> None: ...
    def write_summary(self, summary: dict[str, Any]) -> None: ...
    def close(self) -> None: ...


class JsonlWriter:
    # The run directory is the user's browsing history — keep it owner-only.
    # rotate_bytes > 0 rolls each output file dumpcap-style at that size: the
    # active file always keeps its canonical name (tail -f and `netmon query`
    # read it live), the full file moves to a numbered archive, and archives
    # beyond rotate_keep are deleted oldest-first.
    def __init__(self, out_dir: Path, rotate_bytes: int = 0, rotate_keep: int = 10) -> None:
        self.out_dir = out_dir
        self.rotate_bytes = rotate_bytes
        self.rotate_keep = rotate_keep
        self._files: dict[str, TextIO] = {}
        self._written: dict[str, int] = {}
        self._rolled: dict[str, int] = {}
        self.write_failures = 0
        self._degraded = False
        try:
            # Strict create: refuse to adopt a pre-existing (possibly symlinked or
            # foreign-owned) path — mkdir without exist_ok raises FileExistsError.
            out_dir.parent.mkdir(parents=True, exist_ok=True)
            out_dir.mkdir(mode=0o700)
            out_dir.chmod(0o700)
        except OSError as exc:
            # A pre-existing or symlinked run dir (EEXIST/ELOOP) is a deliberate
            # refusal and must propagate; a disk already full at startup instead
            # degrades to a no-op writer, so the run still captures and reports its
            # emptiness rather than crash-looping under systemd before it begins.
            _reraise_symlink_refusal(exc)
            self._degraded = True
            _log_write_failure("run_dir_create_failed", exc, out_dir=str(self.out_dir))

    def write(self, event: Event) -> None:
        # A full disk (the always-on recorder's own failure mode: it fills the disk
        # with history) must degrade the record, not crash the run into a systemd
        # restart loop. On the first OSError we stop writing and count every dropped
        # event, so `persistence.events_dropped` in the summary marks the record as
        # incomplete — an honest gap, not a silent one. Degrade is one-way: retrying
        # each event under sustained ENOSPC would only churn exceptions.
        if self._degraded:
            self.write_failures += 1
            return
        try:
            name = KIND_TO_FILE[event.kind]
            f = self._files.get(name)
            if f is None:
                f = open_private_new(self.out_dir / name)
                self._files[name] = f
            line = event.model_dump_json(exclude_none=True) + "\n"
            f.write(line)
            f.flush()
        except OSError as exc:
            _reraise_symlink_refusal(exc)
            self._degraded = True
            self.write_failures += 1
            _log_write_failure("jsonl_write_failed", exc, out_dir=str(self.out_dir))
            return
        if self.rotate_bytes:
            self._written[name] = self._written.get(name, 0) + len(line.encode())
            if self._written[name] >= self.rotate_bytes:
                self._rotate(name)

    def _rotate(self, name: str) -> None:
        # Housekeeping, separate from the write: the event that triggered the roll
        # is already on disk, so a failure here must never count it as dropped —
        # the ledger only claims loss that happened. It still degrades: the active
        # file was closed, and the O_EXCL reopen would mistake our own leftover for
        # a symlink attack.
        f = self._files.pop(name, None)
        if f is not None:
            with contextlib.suppress(OSError):
                f.close()
        self._written[name] = 0
        seq = self._rolled.get(name, 0) + 1
        try:
            _roll_archive(self.out_dir / name, seq, self.rotate_keep)
        except OSError as exc:
            self._degraded = True
            _log_write_failure("jsonl_rotate_failed", exc, out_dir=str(self.out_dir))
            return
        self._rolled[name] = seq

    def write_summary(self, summary: dict[str, Any]) -> None:
        try:
            with open_private_new(self.out_dir / "summary.json") as f:
                f.write(json.dumps(summary, indent=2))
        except OSError as exc:
            _reraise_symlink_refusal(exc)
            _log_write_failure("summary_write_failed", exc, out_dir=str(self.out_dir))

    def close(self) -> None:
        for f in self._files.values():
            with contextlib.suppress(OSError):
                f.close()  # a buffered final flush can itself hit ENOSPC


class NullWriter:
    # Ephemeral capture (`netmon run` without --log): stream to the live TUI only,
    # never touch disk — the DNS/TLS/HTTP record stays in memory and evaporates.
    write_failures = 0

    def write(self, event: Event) -> None: ...
    def write_summary(self, summary: dict[str, Any]) -> None: ...
    def close(self) -> None: ...


class PcapSink:
    # Opt-in raw-packet evidence file (`--pcap`): preserves the wire bytes the derived
    # JSONL cannot — cert timing, JA3/JA4, exact packet sizes — so a finding can be
    # re-opened in tshark/Wireshark for the signals netmon deliberately does not
    # compute. Same owner-only (0600), symlink-refusing (CWE-59), degrade-not-crash
    # discipline as JsonlWriter; pairs with slice-08 rotation to stay bounded.
    def __init__(self, path: Path, rotate_bytes: int = 0, rotate_keep: int = 10) -> None:
        self.path = path
        self.rotate_bytes = rotate_bytes
        self.rotate_keep = rotate_keep
        self._written = 0
        self._rolled = 0
        self.write_failures = 0
        self._degraded = False
        self._writer: PcapWriter | None = None
        try:
            # Linktype is inferred from the first packet's link layer, so a mixed or
            # non-Ethernet capture is written faithfully.
            self._writer = PcapWriter(open_private_new_bytes(path))
        except OSError as exc:
            _reraise_symlink_refusal(exc)
            self._degraded = True
            _log_write_failure("pcap_create_failed", exc, path=str(path))

    def write(self, pkt: Packet) -> None:
        if self._degraded or self._writer is None:
            self.write_failures += 1
            return
        try:
            self._writer.write(pkt)
        except OSError as exc:
            # A full disk degrades the evidence file, not the run: on the first OSError
            # we stop and count every dropped packet so `persistence.pcap_dropped` marks
            # the capture as incomplete rather than silently truncated. Degrade is
            # one-way — retrying under sustained ENOSPC only churns exceptions.
            self._degraded = True
            self.write_failures += 1
            _log_write_failure("pcap_write_failed", exc, path=str(self.path))
            return
        except Exception as exc:
            # A packet scapy cannot serialize (a link type it never registered — Raw
            # frames from tun/tunnel captures or an exotic -r pcap raise KeyError before
            # any bytes are written) must not crash the capture loop. Skip it and count
            # the drop, keeping the sink open for the well-formed packets around it —
            # the same malformed-packet discipline as PacketProcessor.process.
            self.write_failures += 1
            _log_write_failure("pcap_write_skipped", exc, path=str(self.path))
            return
        if self.rotate_bytes:
            # wirelen is set on sniffed/replayed packets; the fallback serialize
            # only runs for hand-built ones. The cap is approximate (per-record
            # header overhead uncounted) — rotation needs a bound, not a byte.
            self._written += 16 + (getattr(pkt, "wirelen", None) or len(bytes(pkt)))
            if self._written >= self.rotate_bytes:
                self._rotate()

    def _rotate(self) -> None:
        # Same ring discipline as JsonlWriter._rotate, and the same honesty rule:
        # the packet that triggered the roll is already written, so a housekeeping
        # failure degrades without counting it as dropped. The reopen keeps the
        # O_EXCL|O_NOFOLLOW discipline — a pre-staged file/symlink at the canonical
        # name must crash-stop (CWE-59), never masquerade as a full disk.
        if self._writer is not None:
            with contextlib.suppress(OSError):
                self._writer.close()
        self._written = 0
        try:
            _roll_archive(self.path, self._rolled + 1, self.rotate_keep)
            self._rolled += 1
            self._writer = PcapWriter(open_private_new_bytes(self.path))
        except OSError as exc:
            _reraise_symlink_refusal(exc)
            self._degraded = True
            self._writer = None
            _log_write_failure("pcap_rotate_failed", exc, path=str(self.path))

    def close(self) -> None:
        if self._writer is not None:
            with contextlib.suppress(OSError):
                self._writer.close()  # a buffered final flush can itself hit ENOSPC


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
            # A packet handed over while join() blocked the loop thread scheduled
            # its enqueue via call_soon_threadsafe but could not run it; give the
            # loop one turn so those land, or they are lost after the drain —
            # silently, since an uncontended put_nowait counts no drop.
            await asyncio.sleep(0)
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
    pcap_sink: PcapSink | None = None


def persist_enabled(args: argparse.Namespace) -> bool:
    # Single source of truth for "does this run write to the run dir". Privacy-relevant,
    # so the JSONL writer, the TUI diagnostic log, and the pcap sink read it here rather
    # than each re-deciding. Absent `log` means a programmatic caller (the tests) that
    # wants files; the CLI sets it — `run` -> False (ephemeral), `run --log`/legacy -> True.
    # `--pcap` writes raw evidence to disk, so it persists the run regardless of `--log`.
    return getattr(args, "log", True) or bool(getattr(args, "pcap", False))


def build_session(args: argparse.Namespace) -> Session:
    os.umask(0o077)
    out_dir = Path(args.output) / datetime.now().strftime("run-%Y%m%d-%H%M%S")
    processor = PacketProcessor(local_addresses(), redact_query=not args.keep_query)
    # Clamp, never trust: a negative cap would roll on every write and a zero keep
    # would delete each archive the moment it is created.
    rotate_bytes = max(0, int(getattr(args, "rotate_mb", 0) or 0)) * 1_000_000
    rotate_keep = max(1, int(getattr(args, "rotate_keep", 10) or 10))
    # persist_enabled() is True whenever --pcap is set, so the writer creates the run
    # dir before the pcap sink opens capture.pcap inside it.
    writer: Writer = (
        JsonlWriter(out_dir, rotate_bytes=rotate_bytes, rotate_keep=rotate_keep)
        if persist_enabled(args)
        else NullWriter()
    )
    pcap_sink = (
        PcapSink(out_dir / "capture.pcap", rotate_bytes=rotate_bytes, rotate_keep=rotate_keep)
        if getattr(args, "pcap", False)
        else None
    )
    capture: Capture
    if args.read:
        capture = ReplayCapture(Path(args.read))
    else:
        # scapy's iface=None means conf.iface (default route only), not all interfaces
        ifaces = [args.iface] if args.iface else [i.name for i in get_working_ifaces()]
        capture = LiveCapture(ifaces, args.bpf)
    return Session(out_dir, processor, writer, capture, pcap_sink)


def announce_start(args: argparse.Namespace, session: Session) -> None:
    evidence = str(session.pcap_sink.path) if session.pcap_sink is not None else None
    if args.read:
        log.info("replay_started", pcap=args.read, output=str(session.out_dir), evidence=evidence)
    elif isinstance(session.capture, LiveCapture):
        log.info(
            "capture_started",
            ifaces=session.capture.ifaces,
            bpf=args.bpf,
            output=str(session.out_dir),
            local_ips=sorted(session.processor.local_ips),
            evidence=evidence,
        )


def log_event(event: Event) -> None:
    log.info(event.kind, **event.model_dump(exclude={"kind"}, exclude_none=True))


async def stats_loop(session: Session, interval: float = 30.0) -> None:
    while True:
        await asyncio.sleep(interval)
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


async def refresh_local_ips_loop(session: Session, interval: float = 60.0) -> None:
    # Unlike stats_loop this also runs under --tui (it touches no stdout) — the
    # classification must stay correct in every live mode. local_addresses() does
    # blocking interface I/O, so it runs in the default executor off the event loop.
    while True:
        await asyncio.sleep(interval)
        try:
            ips = await asyncio.get_running_loop().run_in_executor(None, local_addresses)
            session.processor.refresh_local_ips(ips)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # A refresh hiccup must not silently kill the loop for the rest of the
            # run — direction classification would quietly freeze on the old set.
            _log_write_failure("local_ips_refresh_failed", exc)


async def consume(session: Session, on_event: Callable[[Event], None]) -> None:
    # The single shared loop. JSONL is written in both modes; only on_event differs
    # (per-event structlog when headless, model.add_event under --tui). The periodic
    # sleep(0) hands the event loop a turn every 64 packets so a burst drained from
    # the queue — or a synchronous pcap replay — cannot starve a co-running TUI
    # compositor or the 30 s stats task.
    n = 0
    async with aclosing(session.capture.packets()) as packets:
        async for pkt in packets:
            if session.pcap_sink is not None:
                session.pcap_sink.write(pkt)  # every captured packet, as raw evidence
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
        "kernel_delivered": ("unavailable" if st.kernel_delivered is None else st.kernel_delivered),
    }
    # A non-zero events_dropped means the record could not be fully written (a full
    # disk, a read-only remount, a quota) and is incomplete — surfaced so a truncated
    # log is never mistaken for a quiet one. The precise cause is in the error log.
    summary["persistence"] = {"events_dropped": session.writer.write_failures}
    if session.pcap_sink is not None:
        # A non-zero pcap_dropped means the raw evidence file is incomplete (same
        # full-disk fate as events_dropped) — surfaced so it is never mistaken for whole.
        summary["persistence"]["pcap_dropped"] = session.pcap_sink.write_failures
    session.writer.write_summary(summary)
    session.writer.close()
    if session.pcap_sink is not None:
        session.pcap_sink.close()
    return summary


async def run(args: argparse.Namespace) -> None:
    read = getattr(args, "read", None)
    if read and not Path(read).is_file():
        # A missing -r target must fail cleanly before any run dir is created, not
        # crash the pcap reader mid-run with a traceback.
        log.error("pcap_not_found", path=read, hint="check the -r/--read path")
        sys.exit(1)
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
    # A replay analyses another moment's traffic; only a live capture tracks the
    # host's current addresses.
    refresh_task = None if read else asyncio.create_task(refresh_local_ips_loop(session))
    try:
        if tui:
            from netmon_tui import run_dashboard

            await run_dashboard(session, args)
        else:
            await consume(session, log_event if not args.quiet else (lambda _e: None))
    finally:
        if stats_task is not None:
            stats_task.cancel()
        if refresh_task is not None:
            refresh_task.cancel()
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
    p.add_argument(
        "--rotate-mb",
        type=int,
        default=0,
        help="roll each output file (JSONL and --pcap) at this many MB (0 = never)",
    )
    p.add_argument(
        "--rotate-keep",
        type=int,
        default=10,
        help="rolled archives kept per output file, oldest deleted (default: 10)",
    )
    p.add_argument("-q", "--quiet", action="store_true", help="no per-event stdout logging")
    p.add_argument(
        "--pcap",
        action="store_true",
        help="also save raw packets to capture.pcap for later tshark/Wireshark "
        "analysis (persists the run dir; off by default)",
    )
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


class SyncPlan(NamedTuple):
    # How this install rebuilds itself. `uv sync` installs the project along with its
    # dependencies, so it needs no second step; the pip path installs the two separately.
    builder: str
    deps: list[str]
    project: list[str] | None


def _sync_plan(dir_: Path) -> SyncPlan | None:
    # Which builder made this install — read off the venv itself, not a marker file we would
    # then have to keep honest: `uv sync` does not seed pip into the venv it creates, so a pip
    # in there means the pip/requirements.txt path built this. Updating with the *other*
    # builder would rebuild the venv around a different interpreter and silently drop the
    # cap_net_raw grant sitting on the current one — passwordless capture would simply stop,
    # with nothing said.
    venv = dir_ / ".venv"
    if (venv / "bin" / "pip").exists():
        pip = [str(venv / "bin" / "python3"), "-m", "pip", "install", "--disable-pip-version-check"]
        return SyncPlan(
            builder="pip",
            deps=[*pip, "--require-hashes", "-r", str(dir_ / "requirements.txt")],
            project=[*pip, "--no-deps", "-e", str(dir_)],
        )
    uv = shutil.which("uv")
    if uv:
        return SyncPlan(builder="uv", deps=[uv, "sync", "--extra", "tui", "--no-dev"], project=None)
    return None


def _pyproject_moved(
    git_: Callable[..., subprocess.CompletedProcess[str]], old: str, new: str
) -> bool:
    # Reinstalling the project on every update would reach out to PyPI for the build backend
    # even when nothing changed — a real regression against `uv sync`, which does nothing when
    # nothing moved. Only pyproject can change the *installed* metadata (entry points, deps);
    # the code itself is editable, so the pull alone is enough. A diff we cannot compute means
    # reinstall: a skipped rebuild is a silently stale entry point, a redundant one costs time.
    if old == new:
        return False
    diff = git_("diff", "--name-only", f"{old}..{new}")
    return diff.returncode != 0 or "pyproject.toml" in diff.stdout.split()


def cmd_update(argv: list[str]) -> int:
    # git pull + rebuild this checkout. No raw socket, so no privileges needed for the git and
    # build work itself (restarting the service does need root — see below).
    dir_ = _install_dir()
    git = shutil.which("git")
    if not git:
        print("netmon update needs git on PATH", file=sys.stderr)
        return 1
    # Resolve how we will rebuild BEFORE touching the checkout: an install with no usable
    # builder must fail while it is still consistent, not be left pulled-but-unbuilt.
    plan = _sync_plan(dir_)
    if plan is None:
        print(
            f"netmon update cannot sync this install: no uv on PATH and no pip in {dir_}/.venv"
            " — reinstall via install.sh",
            file=sys.stderr,
        )
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
    new = git_("rev-parse", "--short", "HEAD").stdout.strip()
    sync = subprocess.run(plan.deps, cwd=dir_, text=True, check=False)
    if sync.returncode != 0:
        print(f"{plan.builder} dependency sync failed", file=sys.stderr)
        return 1
    if plan.project is not None and _pyproject_moved(git_, old, new):
        project = subprocess.run(plan.project, cwd=dir_, text=True, check=False)
        if project.returncode != 0:
            print(f"{plan.builder} project install failed", file=sys.stderr)
            return 1
    systemctl = shutil.which("systemctl")
    if (
        systemctl
        and subprocess.run(
            [systemctl, "is-active", "--quiet", "netmon.service"], check=False
        ).returncode
        == 0
    ):
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


def _query_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netmon query",
        description="filter a recorded run's JSONL by kind/direction/scope/host "
        "(read-only; no capture)",
    )
    p.add_argument("run_dir", help="a logs/run-* directory to read")
    p.add_argument(
        "--kind", action="append", choices=KIND_VALUES, help="only these kinds (repeatable)"
    )
    p.add_argument(
        "--direction",
        action="append",
        choices=DIRECTION_VALUES,
        help="only these directions (repeatable)",
    )
    p.add_argument(
        "--scope",
        action="append",
        choices=SCOPE_VALUES,
        help="only events whose peer is in these scopes (repeatable)",
    )
    p.add_argument("--host", default="", help="substring match on the event's host / SNI / qname")
    p.add_argument(
        "--min-severity",
        choices=[str(s) for s in Severity],
        help="only events whose leak finding is at least this severe",
    )
    p.add_argument(
        "--rule",
        action="append",
        choices=[str(r) for r in Rule],
        help="only events matching these leak rules (repeatable)",
    )
    p.add_argument(
        "--format",
        choices=("jsonl", "csv"),
        default="jsonl",
        help="jsonl (default) prints the raw recorded line; csv projects the dashboard's "
        "five columns for a spreadsheet",
    )
    return p


def _filter_from_args(args: argparse.Namespace) -> EventFilter:
    # The one place the CLI's "flag absent means every value" convention is written down.
    # EventFilter itself has no such rule — an empty set there means an empty result, which is
    # what an operator who unticked every box actually asked for.
    return EventFilter(
        kinds=frozenset(args.kind or KIND_VALUES),
        directions=frozenset(args.direction or DIRECTION_VALUES),
        scopes=frozenset(args.scope or SCOPE_VALUES),
        host=args.host,
        min_severity=Severity(args.min_severity) if args.min_severity else None,
        rules=frozenset(args.rule) if args.rule else None,
    )


def _load_run_events(run_dir: Path, kinds: frozenset[str]) -> Iterator[Event]:
    # Read only the file(s) the requested kinds live in — all of them when unfiltered —
    # skipping any a partial run never wrote. A line that will not parse (a truncated
    # tail, a hand-edited file) is skipped, not fatal: a query is a read-only view and
    # must never crash on the record it is inspecting.
    names = {KIND_TO_FILE[k] for k in kinds}
    for name in sorted(names):
        # Rotation (--rotate-mb) rolls a kind's overflow into numbered archives
        # beside the active file; the query reads them all as one record. Reads
        # follow symlinks — a query runs unprivileged on the reader's own run dir,
        # so the write-side CWE-59 discipline does not apply here.
        stem, _, suffix = name.partition(".")
        for path in [*_rotation_archives(run_dir, stem, suffix), run_dir / name]:
            if not path.exists():
                continue
            with path.open(encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        yield EVENT_ADAPTER.validate_json(line)
                    except ValueError:
                        continue


def _event_time(ev: Event) -> datetime:
    # Sort on the parsed instant, not the raw string: two ISO timestamps with different
    # UTC offsets (an always-on run that spans a DST change) misorder under a lexical
    # sort. A naive stamp is read as local; a hand-edited unparseable ts sorts to the
    # epoch rather than crashing the read-only view.
    try:
        dt = datetime.fromisoformat(ev.ts)
    except ValueError:
        return datetime.fromtimestamp(0, tz=UTC)
    return dt if dt.tzinfo is not None else dt.astimezone()


def _open_run_dir(run_dir: Path, prog: str) -> bool:
    if not run_dir.is_dir():
        print(f"netmon {prog}: no such run directory: {run_dir}", file=sys.stderr)
        return False
    # A completed run always leaves summary.json even if it captured nothing, so a
    # zero-event run is recognised (prints nothing) rather than mistaken for a bad path.
    run_files = set(KIND_TO_FILE.values()) | {"summary.json"}
    if not any((run_dir / name).exists() for name in run_files):
        print(f"netmon {prog}: not a netmon run directory: {run_dir}", file=sys.stderr)
        return False
    return True


def _audit_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netmon audit",
        description="re-read a recorded run and report what it disclosed (read-only; no capture)",
    )
    p.add_argument("run_dir", help="a logs/run-* directory to read")
    p.add_argument(
        "--min-severity",
        choices=[str(s) for s in Severity],
        default="low",
        help="report only findings at least this severe (default: low)",
    )
    return p


def cmd_audit(argv: list[str]) -> int:
    # The headless diagnosis surface, and the proof of the whole architecture: findings are
    # recomputed from the record, so this works on a run captured BEFORE the rules existed.
    # Nothing was migrated; the evidence was always sufficient.
    args = _audit_parser().parse_args(argv)
    run_dir = Path(args.run_dir)
    if not _open_run_dir(run_dir, "audit"):
        return 1
    floor = SEVERITY_RANK[Severity(args.min_severity)]
    ledger = FindingLedger(cap=1000)
    for event in _load_run_events(run_dir, frozenset(KIND_VALUES)):
        finding = assess(event)
        if finding is not None and SEVERITY_RANK[finding.severity] >= floor:
            ledger.add(finding)
    rows = ledger.top(1000)
    if not rows:
        print(f"no findings at or above {args.min_severity} in {run_dir}")
        # Not an assurance: netmon has no notion of "unusual", so this says no known-shape
        # disclosure was recorded — not that nothing leaked.
        print("(this means no known-shape disclosure was recorded, not that nothing leaked)")
        return 0
    counts = ledger.by_severity()
    tally = ", ".join(f"{counts[s]} {s}" for s in ("high", "medium", "low") if counts.get(s))
    print(f"{run_dir}: {tally}\n")
    for finding, count in rows:
        seen = f" (x{count})" if count > 1 else ""
        print(f"[{str(finding.severity).upper():>6}] {finding.rule}{seen}")
        print(f"         subject: {printable(finding.subject)}")
        print(f"         leaked : {printable(finding.leaked)}")
        print(f"         to     : {printable(finding.to)}")
        print(f"         advice : {finding.advice}\n")
    return 0


def cmd_query(argv: list[str]) -> int:
    args = _query_parser().parse_args(argv)
    run_dir = Path(args.run_dir)
    if not _open_run_dir(run_dir, "query"):
        return 1
    selection = _filter_from_args(args)
    events = [ev for ev in _load_run_events(run_dir, selection.kinds) if selection.matches(ev)]
    events.sort(key=_event_time)  # one timeline across per-kind files
    if args.format == "csv":
        # lineterminator="\n": the excel dialect's default \r\n would leave a stray CR in a
        # piped stream. The header is written even for zero rows — a headerless CSV is not a
        # CSV, and a spreadsheet opening one guesses at the columns.
        out = csv.writer(sys.stdout, lineterminator="\n")
        out.writerow(CSV_COLUMNS)
        for ev in events:
            out.writerow(event_to_csv_row(ev))
        return 0
    for ev in events:
        print(ev.model_dump_json(exclude_none=True))
    return 0


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
    if argv and argv[0] == "query":
        sys.exit(cmd_query(argv[1:]))
    if argv and argv[0] == "audit":
        sys.exit(cmd_audit(argv[1:]))
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
