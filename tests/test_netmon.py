import argparse
import asyncio
import errno
import io
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID
from scapy.config import conf
from scapy.layers.dns import (
    DNS,
    DNSQR,
    DNSRR,
    DNSRRHTTPS,
    DNSRROPT,
    DNSRRSOA,
    DNSRRSVCB,
    EDNS0ClientSubnet,
    SvcParam,
)
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import (
    ICMPv6DestUnreach,
    ICMPv6EchoRequest,
    ICMPv6ND_RA,
    ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptRDNSS,
    IPv6,
    IPv6ExtHdrFragment,
)
from scapy.layers.l2 import ARP, CookedLinux, Ether
from scapy.layers.llmnr import LLMNRQuery
from scapy.layers.netbios import NBNSHeader, NBNSQueryRequest
from scapy.packet import Packet
from scapy.utils import rdpcap, wrpcap

from netmon import (
    DIRECTION_VALUES,
    EVENT_ADAPTER,
    KIND_STYLE,
    KIND_TO_FILE,
    KIND_VALUES,
    MAX_CLIENT_HELLO,
    QUIC_V1,
    QUIC_V2,
    RA_RDNSS_NAME,
    SCOPE_VALUES,
    ArpEvent,
    BoundedCounter,
    CaptureStats,
    DashboardModel,
    DnsAnswerEvent,
    DnsEcsEvent,
    DnsHttpsEvent,
    DnsQueryEvent,
    DnsResponseEvent,
    DnsTcpReassembler,
    Event,
    EventFilter,
    FlowEvent,
    Hostname,
    HttpEvent,
    Icmp6RaEvent,
    JsonlWriter,
    LiveCapture,
    LlmnrEvent,
    LruSet,
    NameLedger,
    NbnsEvent,
    NullWriter,
    PacketProcessor,
    PcapSink,
    QuicReassembler,
    RateBucketer,
    ReplayCapture,
    Scan,
    Session,
    StreamStart,
    TcpReassembler,
    TlsClientHello,
    TlsSniEvent,
    _client_stream_start,
    _dns_tcp_start,
    _legacy_parser,
    _parse_run_args,
    _reassemble,
    _run_parser,
    _server_stream_start,
    announce_start,
    build_session,
    check_capture_privileges,
    cmd_service,
    cmd_update,
    configure_logging,
    derive_initial_keys,
    event_detail,
    event_direction,
    event_direction_name,
    event_host,
    event_remote_addr,
    event_scope,
    event_to_cells,
    event_to_detail,
    extract_certificate_sans,
    finalize,
    header_protection_mask,
    iso,
    local_addresses,
    main,
    packet_nonce,
    parse_client_hello,
    parse_handshake_client_hello,
    parse_http_request,
    printable,
    question_list,
    refresh_local_ips_loop,
    remote_scope,
    run,
    stats_loop,
)

PKT_TIME = 1751500000.123
EXPECTED_ISO = "2025-07-02T23:46:40.123+00:00"


def server_name_entry(name: bytes, name_type: int = 0, declared_len: int | None = None) -> bytes:
    # One ServerName (RFC 6066 §3): name_type(1) + host_name_length(2) + host_name.
    # `name_type` and `declared_len` are open so a test can lie about either.
    declared = len(name) if declared_len is None else declared_len
    return bytes([name_type]) + struct.pack(">H", declared) + name


def server_name_extension(entries: bytes, declared_list_len: int | None = None) -> bytes:
    body = struct.pack(">H", len(entries) if declared_list_len is None else declared_list_len)
    body += entries
    return struct.pack(">H", 0) + struct.pack(">H", len(body)) + body


def sni_extension(name: bytes) -> bytes:
    return server_name_extension(server_name_entry(name))


def padding_extension(size: int) -> bytes:
    return struct.pack(">H", 21) + struct.pack(">H", size) + b"\x00" * size


def ech_extension(size: int = 32) -> bytes:
    # encrypted_client_hello (0xfe0d); only its presence matters to detection.
    return struct.pack(">H", 0xFE0D) + struct.pack(">H", size) + b"\x00" * size


def alpn_extension(*protocols: bytes) -> bytes:
    # application_layer_protocol_negotiation (0x0010): a length-prefixed list of
    # length-prefixed protocol IDs (RFC 7301).
    body = b"".join(bytes([len(p)]) + p for p in protocols)
    proto_list = struct.pack(">H", len(body)) + body
    return struct.pack(">H", 0x10) + struct.pack(">H", len(proto_list)) + proto_list


def build_client_hello(
    extensions: bytes = b"",
    session_id: bytes = b"",
    cipher_suites: bytes = b"\x00\x2f\x00\x35",
    compression: bytes = b"\x00",
) -> bytes:
    body = b"\x03\x03" + b"\x00" * 32
    body += bytes([len(session_id)]) + session_id
    body += struct.pack(">H", len(cipher_suites)) + cipher_suites
    body += bytes([len(compression)]) + compression
    body += struct.pack(">H", len(extensions)) + extensions
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


@pytest.fixture
def processor() -> PacketProcessor:
    return PacketProcessor(local_ips=frozenset())


def local_processor(*local_ips: str) -> PacketProcessor:
    return PacketProcessor(local_ips=frozenset(local_ips))


def make_syn(src: str, dst: str, sport: int, dport: int, flags: str = "S") -> Packet:
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    pkt.time = PKT_TIME
    return pkt


def sni_of(payload: bytes) -> str | None:
    hello = parse_client_hello(payload)
    return hello.sni if isinstance(hello, TlsClientHello) else None


def single_flow(events: list[Event]) -> FlowEvent:
    (flow,) = events
    assert isinstance(flow, FlowEvent)
    return flow


def sample_events() -> list[Event]:
    # One event of every emitted kind — the single authority for "an example of each", so a
    # projection that must be total over KIND_TO_FILE (a cell row, a scope, a CSV line) is
    # tested against the same twelve everywhere. A test below asserts it stays exhaustive.
    return [
        q("x"),
        DnsAnswerEvent(ts=TS, resolver="10.0.0.1", qname="x", rtype="A", value="1.2.3.4", ttl=60),
        DnsResponseEvent(ts=TS, resolver="10.0.0.1", qname="x", qtype="A", rcode="NXDOMAIN"),
        DnsHttpsEvent(
            ts=TS,
            resolver="10.0.0.1",
            qname="x",
            rtype="HTTPS",
            priority=1,
            target=".",
            alpn=["h3"],
            ech=True,
            ttl=60,
        ),
        DnsEcsEvent(ts=TS, src="10.0.0.5", dst="10.0.0.1", qname="x", client_subnet="1.2.3.0/24"),
        TlsSniEvent(ts=TS, src="10.0.0.5", dst="1.2.3.4", dport=443, sni="github.com", alpn=["h2"]),
        HttpEvent(
            ts=TS,
            src="10.0.0.5",
            dst="1.2.3.4",
            dport=80,
            method="GET",
            host="x",
            path="/",
            user_agent=None,
        ),
        FlowEvent(
            ts=TS,
            proto="udp",
            direction="outbound",
            scope="lan",
            birth="datagram",
            local_ip="10.0.0.5",
            local_port=5353,
            remote_ip="224.0.0.251",
            remote_port=5353,
            service="mdns",
            hostname=None,
        ),
        ArpEvent(
            ts=TS,
            op="who-has",
            sender_ip="10.0.0.5",
            sender_mac="aa:bb:cc:dd:ee:ff",
            target_ip="10.0.0.1",
        ),
        Icmp6RaEvent(ts=TS, router="fe80::1", prefixes=["2001:db8::/64"], rdnss=["2001:db8::1"]),
        LlmnrEvent(ts=TS, src="10.0.0.5", dst="224.0.0.252", qname="wpad", qtype="A"),
        NbnsEvent(ts=TS, src="10.0.0.5", dst="10.0.0.255", qname="WORKGROUP"),
    ]


class TestHostname:
    @pytest.mark.parametrize(
        "raw",
        [
            "example.com",
            "a.b.c.example.co.uk",
            "_dmarc.example.com",  # not strictly LDH, but real as an SNI in the wild
            "xn--80ak6aa92e.com",  # punycode A-label: kept as sent, never IDNA-decoded
            "router",  # single-label LAN names are real
            "cdn-1.example.com",
            "Example.COM",  # case is preserved: the record reports what was sent
            "192.0.2.1",  # RFC 6066 forbids it, but a client that sends one is a fact
        ],
    )
    def test_plausible_names_parse(self, raw: str) -> None:
        assert Hostname.parse(raw) == raw

    def test_trailing_dot_is_stripped(self) -> None:
        assert Hostname.parse("example.com.") == "example.com"

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            ".",
            "example..com",  # empty label
            "-lead.example.com",
            "trail-.example.com",
            "ex ample.com",
            "ex\x00ample.com",  # the control bytes the old decode let through verbatim
            "\x03\x00)\x01\x0b\x00",
            "exa�mple.com",  # U+FFFD: the parser's own mark of an undecodable byte
            "héllo.example.com",
            "*.example.com",  # a wildcard is a pattern, not a hostname
            "a" * 64 + ".example.com",  # label over 63
            ("a." * 127) + "example.com",  # name over 253
        ],
    )
    def test_implausible_names_are_rejected(self, raw: str) -> None:
        assert Hostname.parse(raw) is None

    def test_a_parsed_name_serialises_as_a_plain_string(self) -> None:
        # It rides TlsSniEvent.sni: a str subclass so Pydantic needs no adapter for it.
        name = Hostname.parse("example.com")
        assert isinstance(name, str)
        event = TlsSniEvent(ts=EXPECTED_ISO, src="a", dst="b", dport=443, sni=name or "")
        assert json.loads(event.model_dump_json())["sni"] == "example.com"


class TestParseClientHello:
    def test_valid_clienthello_with_grease_before_sni(self) -> None:
        extensions = padding_extension(6) + sni_extension(b"example.com")
        payload = build_client_hello(
            extensions=extensions,
            session_id=b"\xaa" * 4,
            cipher_suites=b"\x00\x2f\x00\x35\xc0\x2b",
        )
        assert sni_of(payload) == "example.com"

    def test_truncated_payload_is_incomplete(self) -> None:
        extensions = padding_extension(6) + sni_extension(b"example.com")
        payload = build_client_hello(extensions=extensions)
        truncated = payload[:50]
        assert len(truncated) >= 44
        assert parse_client_hello(truncated) is Scan.INCOMPLETE

    def test_short_payload_below_minimum_length_is_incomplete(self) -> None:
        assert parse_client_hello(b"\x16\x03\x01\x00\x05\x01") is Scan.INCOMPLETE

    def test_non_tls_payload_is_impossible(self) -> None:
        payload = b"not a tls record at all, just plain bytes"
        assert parse_client_hello(payload) is Scan.IMPOSSIBLE

    def test_non_clienthello_handshake_type_is_impossible(self) -> None:
        extensions = sni_extension(b"example.com")
        payload = bytearray(build_client_hello(extensions=extensions))
        payload[5] = 0x02
        assert parse_client_hello(bytes(payload)) is Scan.IMPOSSIBLE

    def test_clienthello_with_no_extensions_is_impossible(self) -> None:
        # A complete handshake message that disclosed nothing: no later byte can change
        # that, so the flow is given up on rather than buffered to the cap.
        payload = build_client_hello(extensions=b"")
        assert len(payload) >= 44
        assert parse_client_hello(payload) is Scan.IMPOSSIBLE

    def test_record_length_over_the_tls_maximum_is_impossible(self) -> None:
        assert parse_client_hello(b"\x16\x03\x01\xff\xff\x01" + b"\x00" * 64) is Scan.IMPOSSIBLE

    def test_unknown_legacy_version_is_impossible(self) -> None:
        assert parse_client_hello(b"\x16\x03\x09\x00\x40\x01" + b"\x00" * 64) is Scan.IMPOSSIBLE

    def test_no_ech_extension_leaves_flag_false(self) -> None:
        payload = build_client_hello(extensions=sni_extension(b"example.com"))
        hello = parse_client_hello(payload)
        assert isinstance(hello, TlsClientHello)
        assert hello.sni == "example.com"
        assert hello.ech is False


def binary_server_name(size: int = 176) -> bytes:
    # The shape the overnight run hit: bytes lifted straight out of a DoT ciphertext
    # stream, which the parser handed back as an "SNI".
    return random.Random(0).randbytes(size)


class TestServerNameExtension:
    def test_non_host_name_type_yields_no_sni(self) -> None:
        # host_name(0) is the only name_type RFC 6066 defines. An undefined type has no
        # defined body, so its length field cannot be trusted to skip it.
        entry = server_name_entry(b"example.com", name_type=0x01)
        payload = build_client_hello(extensions=server_name_extension(entry))
        assert sni_of(payload) is None

    def test_server_name_list_length_beyond_the_extension_is_rejected(self) -> None:
        entry = server_name_entry(b"example.com")
        ext = server_name_extension(entry, declared_list_len=len(entry) + 64)
        assert sni_of(build_client_hello(extensions=ext)) is None

    def test_name_length_beyond_the_extension_cannot_read_the_next_extension(self) -> None:
        # An over-declared host_name_length must stay inside its own extension: it can
        # neither swallow the ALPN extension that follows nor derail the walk past it.
        lying = server_name_entry(b"safe.example.com", declared_len=200)
        extensions = server_name_extension(lying) + alpn_extension(b"h2") + ech_extension()
        hello = parse_client_hello(build_client_hello(extensions=extensions))
        assert hello is not None
        assert hello.sni is None
        assert hello.alpn == ["h2"]

    def test_empty_server_name_extension_yields_no_sni(self) -> None:
        assert sni_of(build_client_hello(extensions=server_name_extension(b""))) is None

    def test_binary_server_name_yields_no_sni(self) -> None:
        entry = server_name_entry(binary_server_name())
        payload = build_client_hello(extensions=server_name_extension(entry))
        assert sni_of(payload) is None

    def test_ech_still_emits_when_the_server_name_is_binary(self) -> None:
        # Rejecting the junk name must not swallow the ech=True disclosure alongside it.
        entry = server_name_entry(binary_server_name())
        extensions = server_name_extension(entry) + ech_extension()
        hello = parse_client_hello(build_client_hello(extensions=extensions))
        assert hello is not None
        assert hello.sni is None
        assert hello.ech is True


class TestEchDetection:
    def test_ech_bearing_clienthello_flags_cover_name(self) -> None:
        extensions = sni_extension(b"cover.example.net") + ech_extension()
        payload = build_client_hello(extensions=extensions)
        hello = parse_client_hello(payload)
        assert hello is not None
        assert hello.sni == "cover.example.net"
        assert hello.ech is True

    def test_process_marks_ech_on_tls_sni_event(self) -> None:
        proc = local_processor("192.168.1.50")
        extensions = sni_extension(b"cover.example.net") + ech_extension()
        payload = build_client_hello(extensions=extensions)
        events = proc.process(tcp_segment(payload, flags="PA"))
        sni_events = [e for e in events if isinstance(e, TlsSniEvent)]
        assert len(sni_events) == 1
        assert sni_events[0].sni == "cover.example.net"
        assert sni_events[0].ech is True

    def test_process_leaves_ech_false_without_extension(self) -> None:
        proc = local_processor("192.168.1.50")
        payload = build_client_hello(extensions=sni_extension(b"plain.example.net"))
        events = proc.process(tcp_segment(payload, flags="PA"))
        sni_events = [e for e in events if isinstance(e, TlsSniEvent)]
        assert len(sni_events) == 1
        assert sni_events[0].ech is False


def ech_only_hello() -> bytes:
    # A ClientHello that offers ECH with no public server_name (spec-permitted).
    # The real hostname is hidden from the ISP — the single most audit-relevant
    # signal for that connection — so the ech=True fact must still be emitted.
    return build_client_hello(extensions=ech_extension())


class TestEchOnlyEmission:
    def test_tcp_ech_only_hello_still_emits_event(self) -> None:
        proc = local_processor("192.168.1.50")
        events = proc.process(tcp_segment(ech_only_hello(), flags="PA"))
        sni_events = [e for e in events if isinstance(e, TlsSniEvent)]
        assert len(sni_events) == 1
        assert sni_events[0].sni == ""
        assert sni_events[0].ech is True

    def test_quic_ech_only_hello_still_emits_event(self) -> None:
        proc = local_processor("192.168.1.50")
        datagram = encrypt_initial(RFC_DCID, crypto_frame(ech_only_hello()[5:]))
        pkt = (
            Ether()
            / IP(src="192.168.1.50", dst="93.184.216.34")
            / UDP(sport=50000, dport=443)
            / datagram
        )
        pkt.time = PKT_TIME
        sni_events = [e for e in proc.process(pkt) if isinstance(e, TlsSniEvent)]
        assert len(sni_events) == 1
        assert sni_events[0].sni == ""
        assert sni_events[0].ech is True
        assert sni_events[0].transport == "quic"

    def test_ech_only_hello_does_not_pollute_name_ledger(self) -> None:
        proc = local_processor("192.168.1.50")
        proc.process(tcp_segment(ech_only_hello(), flags="PA"))
        assert proc.names.lookup("93.184.216.34") is None


BASE_SEQ = 1000
CH_RECORD_HEADER = b"\x16\x03\x01\x01\x00\x01"  # TLS record + ClientHello handshake type


def tcp_segment(
    data: bytes, sport: int = 51000, dport: int = 443, flags: str = "A", seq: int = BASE_SEQ
) -> Packet:
    pkt = (
        Ether()
        / IP(src="192.168.1.50", dst="93.184.216.34")
        / TCP(sport=sport, dport=dport, flags=flags, seq=seq)
        / data
    )
    pkt.time = PKT_TIME
    return pkt


def pq_client_hello(name: bytes) -> bytes:
    # Post-quantum key shares push the ClientHello past one 1500-byte segment.
    hello = build_client_hello(extensions=padding_extension(2000) + sni_extension(name))
    assert len(hello) > 1500
    return hello


def two_record_client_hello(name: bytes, alpn: bytes = b"") -> bytes:
    # A ClientHello whose handshake message exceeds one 16384-byte TLS record (as
    # post-quantum key shares increasingly force), fragmented across two handshake
    # records, each with its own 5-byte record header.
    exts = padding_extension(17000) + sni_extension(name) + alpn
    handshake = build_client_hello(extensions=exts)[5:]  # strip the single-record header
    assert len(handshake) > 16384
    first, second = handshake[:16384], handshake[16384:]

    def record(body: bytes) -> bytes:
        return b"\x16\x03\x03" + len(body).to_bytes(2, "big") + body

    return record(first) + record(second)


class TestMultiRecordClientHello:
    def test_two_record_clienthello_parses_sni_and_alpn(self) -> None:
        payload = two_record_client_hello(b"multi.example.com", alpn_extension(b"h2"))
        hello = parse_client_hello(payload)
        assert hello is not None
        assert hello.sni == "multi.example.com"
        assert hello.alpn == ["h2"]

    def test_single_record_clienthello_unaffected(self) -> None:
        payload = build_client_hello(extensions=sni_extension(b"one.example.com"))
        hello = parse_client_hello(payload)
        assert hello is not None
        assert hello.sni == "one.example.com"

    def test_lying_sni_length_yields_no_hello(self) -> None:
        # A ClientHello whose server_name length field over-declares is malformed, and a
        # malformed name is no name: the extension must be rejected outright rather than
        # clipped to whatever bytes happen to follow it.
        ext = server_name_extension(server_name_entry(b"safe.example.com", declared_len=80))
        handshake = build_client_hello(extensions=ext)[5:]  # honest handshake length field
        trailing = b"evil.attacker.example/" * 8  # a following record's stripped payload
        assert parse_handshake_client_hello(handshake + trailing) is None

    def test_lying_sni_length_with_ech_still_reports_ech(self) -> None:
        # Rejecting the lying name must not silently swallow a real disclosure with it.
        ext = server_name_extension(server_name_entry(b"safe.example.com", declared_len=80))
        handshake = build_client_hello(extensions=ext + ech_extension())[5:]
        parsed = parse_handshake_client_hello(handshake + b"evil.attacker.example/" * 8)
        assert parsed is not None
        assert parsed.sni is None
        assert parsed.ech is True

    def test_non_handshake_record_after_hello_not_concatenated(self) -> None:
        # A 0x17 application-data record following the ClientHello must not be folded
        # into the handshake message; the SNI still parses from the handshake alone.
        hello = build_client_hello(extensions=sni_extension(b"clean.example.com"))
        app_data = b"\x17\x03\x03\x00\x08" + b"\xff" * 8
        parsed = parse_client_hello(hello + app_data)
        assert parsed is not None
        assert parsed.sni == "clean.example.com"

    def test_incomplete_second_record_waits(self) -> None:
        # The second record's declared length has not fully arrived: no partial parse.
        full = two_record_client_hello(b"partial.example.com")
        assert parse_client_hello(full[:-50]) is Scan.INCOMPLETE

    def test_two_record_hello_across_tcp_segments_yields_sni(self) -> None:
        # TCP segments a stream at MSS boundaries, not record boundaries, so the second
        # segment starts mid-record. Reassembling segments then records yields the SNI.
        proc = local_processor("192.168.1.50")
        payload = two_record_client_hello(b"e2e.example.com", alpn_extension(b"h2"))
        first, second = payload[:8000], payload[8000:]
        proc.process(tcp_segment(first, flags="A", seq=BASE_SEQ))
        done = proc.process(tcp_segment(second, flags="PA", seq=BASE_SEQ + len(first)))
        sni = [e for e in done if isinstance(e, TlsSniEvent)]
        assert len(sni) == 1
        assert sni[0].sni == "e2e.example.com"


class TestSplitClientHelloReassembly:
    def test_pq_clienthello_split_across_two_segments_yields_one_sni(self) -> None:
        proc = local_processor("192.168.1.50")
        hello = pq_client_hello(b"split.example.com")
        first, second = hello[:800], hello[800:]

        first_events = proc.process(tcp_segment(first, flags="A", seq=BASE_SEQ))
        second_events = proc.process(tcp_segment(second, flags="PA", seq=BASE_SEQ + len(first)))

        assert [e for e in first_events if isinstance(e, TlsSniEvent)] == []
        sni_events = [e for e in second_events if isinstance(e, TlsSniEvent)]
        assert len(sni_events) == 1
        assert sni_events[0].sni == "split.example.com"

    def test_segments_reassemble_when_captured_out_of_order(self) -> None:
        proc = local_processor("192.168.1.50")
        hello = pq_client_hello(b"reorder.example.com")
        a, b, c = hello[:700], hello[700:1400], hello[1400:]

        proc.process(tcp_segment(a, flags="A", seq=BASE_SEQ))  # anchor first
        gap = proc.process(tcp_segment(c, flags="A", seq=BASE_SEQ + 1400))  # third before second
        done = proc.process(tcp_segment(b, flags="PA", seq=BASE_SEQ + 700))  # fills the gap

        assert [e for e in gap if isinstance(e, TlsSniEvent)] == []
        sni_events = [e for e in done if isinstance(e, TlsSniEvent)]
        assert len(sni_events) == 1
        assert sni_events[0].sni == "reorder.example.com"

    def test_retransmitted_segment_does_not_corrupt_reassembly(self) -> None:
        proc = local_processor("192.168.1.50")
        hello = pq_client_hello(b"dup.example.com")
        first, second = hello[:800], hello[800:]

        proc.process(tcp_segment(first, flags="A", seq=BASE_SEQ))
        proc.process(tcp_segment(first, flags="A", seq=BASE_SEQ))  # duplicate
        events = proc.process(tcp_segment(second, flags="PA", seq=BASE_SEQ + len(first)))

        sni_events = [e for e in events if isinstance(e, TlsSniEvent)]
        assert len(sni_events) == 1
        assert sni_events[0].sni == "dup.example.com"

    def test_single_segment_clienthello_still_parses(self) -> None:
        proc = local_processor("192.168.1.50")
        hello = build_client_hello(extensions=sni_extension(b"whole.example.com"))
        events = proc.process(tcp_segment(hello, flags="PA"))
        sni_events = [e for e in events if isinstance(e, TlsSniEvent)]
        assert len(sni_events) == 1
        assert sni_events[0].sni == "whole.example.com"

    def test_http_request_split_across_segments_parses_once_whole(self) -> None:
        proc = local_processor("192.168.1.50")
        request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n"
        first, second = request[:20], request[20:]

        first_events = proc.process(tcp_segment(first, dport=80, flags="A", seq=BASE_SEQ))
        second_events = proc.process(
            tcp_segment(second, dport=80, flags="PA", seq=BASE_SEQ + len(first))
        )

        assert [e for e in first_events if isinstance(e, HttpEvent)] == []
        http_events = [e for e in second_events if isinstance(e, HttpEvent)]
        assert len(http_events) == 1
        assert http_events[0].host == "example.com"

    def test_three_byte_first_segment_still_anchors_and_yields_sni(self) -> None:
        # The evasion-resistance guard on the provisional anchor. A ClientHello whose
        # first segment is too short to carry the handshake type must still be tracked,
        # or an attacker segments their way past the monitor.
        proc = local_processor("192.168.1.50")
        hello = build_client_hello(extensions=sni_extension(b"tiny.example.com"))
        proc.process(tcp_segment(hello[:3], flags="A", seq=BASE_SEQ))
        done = proc.process(tcp_segment(hello[3:], flags="PA", seq=BASE_SEQ + 3))
        sni_events = [e for e in done if isinstance(e, TlsSniEvent)]
        assert len(sni_events) == 1
        assert sni_events[0].sni == "tiny.example.com"

    def test_two_byte_http_method_prefix_still_anchors(self) -> None:
        # The same resistance the TLS side always had, now on the HTTP side: a first
        # segment of b"GE" used to be rejected outright and the request lost for good.
        proc = local_processor("192.168.1.50")
        request = b"GET /a HTTP/1.1\r\nHost: split.example.com\r\n\r\n"
        proc.process(tcp_segment(request[:2], dport=80, flags="A", seq=BASE_SEQ))
        done = proc.process(tcp_segment(request[2:], dport=80, flags="PA", seq=BASE_SEQ + 2))
        http_events = [e for e in done if isinstance(e, HttpEvent)]
        assert len(http_events) == 1
        assert http_events[0].host == "split.example.com"

    def test_provisional_anchor_is_dropped_when_it_turns_out_to_be_a_serverhello(self) -> None:
        # The guess is confirmed once the bytes that settle it arrive, never trusted
        # forever: a ServerHello is not the client's opening flight.
        proc = local_processor("192.168.1.50")
        key = ("192.168.1.50", 51000, "93.184.216.34", 443)
        proc.process(tcp_segment(b"\x16\x03\x01", flags="A", seq=BASE_SEQ))
        assert key in proc.reassembler._flows
        events = proc.process(tcp_segment(b"\x00\x2e\x02" + b"\x00" * 64, seq=BASE_SEQ + 3))
        assert [e for e in events if isinstance(e, TlsSniEvent)] == []
        assert key not in proc.reassembler._flows
        assert proc.reassembler._total == 0

    def test_fin_drops_buffer_so_late_segment_is_not_reassembled(self) -> None:
        proc = local_processor("192.168.1.50")
        hello = pq_client_hello(b"dropped.example.com")
        first, second = hello[:800], hello[800:]

        proc.process(tcp_segment(first, flags="A", seq=BASE_SEQ))
        proc.process(tcp_segment(b"", flags="FA", seq=BASE_SEQ + len(first)))
        events = proc.process(tcp_segment(second, flags="A", seq=BASE_SEQ + len(first)))

        assert [e for e in events if isinstance(e, TlsSniEvent)] == []


class TestTcpReassembler:
    def test_untracked_when_first_bytes_are_neither_tls_nor_http(self) -> None:
        r = TcpReassembler()
        key = ("192.168.1.50", 51000, "93.184.216.34", 443)
        assert r.add(key, 0, b"\x17\x03\x03 encrypted app data") == b""
        assert key not in r._flows

    def test_serverhello_direction_is_not_tracked(self) -> None:
        r = TcpReassembler()
        key = ("93.184.216.34", 443, "192.168.1.50", 51000)
        # A TLS record whose handshake type is ServerHello (0x02), not 0x01.
        assert r.add(key, 0, b"\x16\x03\x03\x00\x00\x02" + b"\x00" * 4000) == b""
        assert key not in r._flows

    def test_per_flow_cap_bounds_a_single_buffer(self) -> None:
        r = TcpReassembler(per_flow_cap=10, total_cap=1000)
        key = ("a", 1, "b", 2)
        r.add(key, 0, CH_RECORD_HEADER + b"\x00" * 50)
        assert r._flows[key].size == 10

    def test_total_cap_evicts_oldest_keeps_newest(self) -> None:
        # Over the byte cap evicts the least-recently-updated stream, not every one:
        # the newest (in-progress) stream survives a burst instead of being wiped.
        r = TcpReassembler(per_flow_cap=25, total_cap=40)
        old, new = ("a", 1, "b", 2), ("c", 3, "d", 4)
        r.add(old, 0, CH_RECORD_HEADER + b"\x00" * 19)  # 25 bytes
        r.add(new, 0, CH_RECORD_HEADER + b"\x00" * 19)  # total 50 > 30 -> evict oldest
        assert old not in r._flows
        assert new in r._flows
        assert r._total == r._flows[new].size

    def test_eviction_counts_only_the_streams_evicted(self) -> None:
        r = TcpReassembler(per_flow_cap=25, total_cap=40)
        r.add(("a", 1, "b", 2), 0, CH_RECORD_HEADER + b"\x00" * 19)
        r.add(("c", 3, "d", 4), 0, CH_RECORD_HEADER + b"\x00" * 19)
        assert r.cleared == 1  # only the oldest, not a full wipe

    def test_recently_updated_stream_survives_a_burst(self) -> None:
        # A stream refreshed just before a burst of new ones survives while an older
        # idle stream ages out — the whole point of LRU over clear-all.
        r = TcpReassembler(per_flow_cap=35, total_cap=60)
        hot, idle, burst = ("h", 1, "x", 2), ("a", 1, "x", 2), ("b", 1, "x", 2)
        r.add(hot, 0, CH_RECORD_HEADER + b"\x00" * 19)  # 25
        r.add(idle, 0, CH_RECORD_HEADER + b"\x00" * 19)  # 25, total 50
        r.add(hot, 25, b"\xaa" * 10)  # refresh hot -> most recent; total 60
        r.add(burst, 0, CH_RECORD_HEADER + b"\x00" * 19)  # total 85 > 60 -> evict oldest (idle)
        assert idle not in r._flows
        assert hot in r._flows
        assert burst in r._flows

    def test_drop_removes_buffer_and_reclaims_total(self) -> None:
        r = TcpReassembler()
        key = ("a", 1, "b", 2)
        r.add(key, 0, CH_RECORD_HEADER + b"\x00" * 9)
        r.drop(key)
        assert key not in r._flows
        assert r._total == 0

    def test_the_give_up_bound_is_the_buffer_it_gives_up_on(self) -> None:
        # parse_client_hello calls a hello bigger than MAX_CLIENT_HELLO unassemblable. If
        # per_flow_cap ever grew past it (to fit a larger post-quantum hello, say), a
        # legitimate stream would be declared IMPOSSIBLE before its buffer was even full —
        # the auditor silently missing a real disclosure. One number, so they cannot drift.
        assert TcpReassembler().per_flow_cap == MAX_CLIENT_HELLO

    def test_record_length_over_the_tls_maximum_is_not_anchored(self) -> None:
        # A ciphertext byte pair that happens to read 16 03 still has to declare a record
        # length a TLS record could actually have.
        r = TcpReassembler()
        key = ("a", 1, "b", 2)
        assert r.add(key, 0, b"\x16\x03\x03\xff\xff\x01" + b"\x00" * 64) == b""
        assert key not in r._flows

    def test_short_ambiguous_prefix_anchors_provisionally(self) -> None:
        r = TcpReassembler()
        key = ("a", 1, "b", 2)
        assert r.add(key, 0, b"\x16\x03") == b"\x16\x03"
        assert r._flows[key].confirmed is False

    def test_disconfirmed_provisional_anchor_is_dropped_and_bytes_reclaimed(self) -> None:
        r = TcpReassembler()
        key = ("a", 1, "b", 2)
        r.add(key, 0, b"\x16\x03")
        assert r.add(key, 2, b"\x03\x00\x2e\x02") == b""  # settles as a ServerHello
        assert key not in r._flows
        assert r._total == 0


class TestTcpReassemblerOverlapAndReorder:
    KEY = ("192.168.1.50", 51000, "93.184.216.34", 443)

    def test_second_segment_before_first_still_yields_sni(self) -> None:
        # Capture reordering delivers the ClientHello's tail before its opening
        # segment; the opening segment must retroactively absorb the buffered tail.
        proc = local_processor("192.168.1.50")
        hello = pq_client_hello(b"preorder.example.com")
        first, second = hello[:800], hello[800:]
        early = proc.process(tcp_segment(second, flags="A", seq=BASE_SEQ + 800))
        done = proc.process(tcp_segment(first, flags="PA", seq=BASE_SEQ))
        assert [e for e in early if isinstance(e, TlsSniEvent)] == []
        sni = [e for e in done if isinstance(e, TlsSniEvent)]
        assert len(sni) == 1
        assert sni[0].sni == "preorder.example.com"

    def test_overlapping_repacketized_retransmit_assembles_whole(self) -> None:
        # A retransmit repacketized at a different boundary overlaps the buffered
        # prefix. First-data-wins on the overlap; the extending tail is appended, so
        # the assembled bytes are whole and uncorrupted.
        r = TcpReassembler()
        hello = pq_client_hello(b"overlap.example.com")
        r.add(self.KEY, BASE_SEQ, hello[:800])
        r.add(self.KEY, BASE_SEQ + 600, hello[600:1400])  # overlaps [600:800], extends
        out = r.add(self.KEY, BASE_SEQ + 1400, hello[1400:])
        assert out == hello
        parsed = parse_client_hello(out)
        assert parsed is not None
        assert parsed.sni == "overlap.example.com"

    def test_reassemble_stops_at_a_genuine_gap(self) -> None:
        # Overlap tolerance must not paper over a real hole: a missing middle segment
        # still yields only the contiguous prefix, never the disjoint tail.
        r = TcpReassembler()
        hello = pq_client_hello(b"gap.example.com")
        r.add(self.KEY, BASE_SEQ, hello[:700])
        out = r.add(self.KEY, BASE_SEQ + 1400, hello[1400:])  # skips [700:1400]
        assert out == hello[:700]
        assert parse_client_hello(out) is Scan.INCOMPLETE

    def test_pending_pool_is_byte_bounded_under_a_flood(self) -> None:
        # Every non-opening segment is buffered pending its anchor; a flood of them
        # (the server->client firehose, or a hostile stream) must stay under the cap.
        r = TcpReassembler(pending_cap=4096)
        for i in range(1000):
            key = ("10.0.0.1", 1024 + i, "93.184.216.34", 443)
            r.add(key, 0, b"\x17\x03\x03 not a client hello" + bytes([i % 256]) * 200)
        assert r._pending_total <= 4096

    def test_fin_drops_pending_so_late_anchor_finds_nothing(self) -> None:
        # A RST/FIN before the anchor arrives discards the buffered pre-anchor bytes,
        # matching the anchored-stream drop discipline.
        r = TcpReassembler()
        hello = pq_client_hello(b"resetme.example.com")
        first, second = hello[:800], hello[800:]
        r.add(self.KEY, BASE_SEQ + 800, second)  # buffered pending
        r.drop(self.KEY)  # connection reset
        out = r.add(self.KEY, BASE_SEQ, first)  # anchor arrives after the drop
        assert out == first  # only the anchor's own bytes; the tail was discarded
        assert parse_client_hello(out) is Scan.INCOMPLETE

    def test_anchor_bytes_win_over_pending_garbage_at_same_seq(self) -> None:
        # A segment carrying non-opening bytes buffered at the sequence the real
        # ClientHello will use must not pre-empt the verified opening segment. The
        # anchor's own bytes are authoritative; pending only fills the gaps it leaves.
        r = TcpReassembler()
        hello = pq_client_hello(b"authentic.example.com")
        first, second = hello[:800], hello[800:]
        r.add(self.KEY, BASE_SEQ, b"\x17\x03\x03" + b"\xcc" * 797)  # garbage at anchor seq
        r.add(self.KEY, BASE_SEQ + 800, second)  # real tail, buffered pending
        out = r.add(self.KEY, BASE_SEQ, first)  # real opening anchors last
        assert out == hello
        parsed = parse_client_hello(out)
        assert parsed is not None
        assert parsed.sni == "authentic.example.com"

    def test_serverhello_still_never_enters_flows(self) -> None:
        # The pending pool must not promote a server->client ServerHello into a tracked
        # (anchored) stream — it is only ever held unanchored, never parsed as a client.
        r = TcpReassembler()
        server_key = ("93.184.216.34", 443, "192.168.1.50", 51000)
        assert r.add(server_key, 0, b"\x16\x03\x03\x00\x00\x02" + b"\x00" * 4000) == b""
        assert server_key not in r._flows


DOT_RESOLVER = "149.112.112.11"
DOT_CLIENT = "192.168.11.32"
DOT_KEY = (DOT_CLIENT, 51000, DOT_RESOLVER, 853)


def dot_segment(data: bytes, seq: int = BASE_SEQ, flags: str = "A") -> Packet:
    pkt = (
        Ether()
        / IP(src=DOT_CLIENT, dst=DOT_RESOLVER)
        / TCP(sport=51000, dport=853, flags=flags, seq=seq)
        / data
    )
    pkt.time = PKT_TIME
    return pkt


def false_anchor_ciphertext(count: int = 40) -> list[bytes]:
    # Encrypted DNS-over-TLS application data whose first captured segment happens to
    # begin like a handshake record carrying a ClientHello — the mid-stream coincidence
    # that anchored the reassembler overnight. What follows it is a record of a
    # different content type, which proves no cleartext handshake can still arrive.
    rng = random.Random(0)
    record = b"\x16\x03\x01" + struct.pack(">H", 320) + b"\x01" + rng.randbytes(319)
    tail = bytearray(rng.randbytes(1081))
    tail[0] = 0x17  # application data: the handshake is over
    return [record + bytes(tail)] + [rng.randbytes(1400) for _ in range(count - 1)]


def feed_dot(proc: PacketProcessor, chunks: list[bytes]) -> list[Event]:
    events: list[Event] = []
    seq = BASE_SEQ
    for chunk in chunks:
        events += proc.process(dot_segment(chunk, seq=seq))
        seq += len(chunk)
    return events


class TestCiphertextFalseAnchor:
    def test_binary_server_name_is_not_reported_as_an_sni(self) -> None:
        # The overnight bug end to end: a "ClientHello" whose server_name holds ciphertext
        # must disclose nothing. A name netmon cannot prove is a hostname is not a name.
        proc = local_processor(DOT_CLIENT)
        entry = server_name_entry(binary_server_name())
        hello = build_client_hello(extensions=server_name_extension(entry))
        events = proc.process(dot_segment(hello, flags="PA"))
        assert [e for e in events if isinstance(e, TlsSniEvent)] == []

    def test_binary_server_name_does_not_poison_the_name_ledger(self) -> None:
        # The blast radius beyond the one event: a junk SNI also names the resolver's IP
        # in the ledger and buckets it in the top-SNI counter.
        proc = local_processor(DOT_CLIENT)
        entry = server_name_entry(binary_server_name())
        proc.process(dot_segment(build_client_hello(extensions=server_name_extension(entry))))
        assert proc.names.lookup(DOT_RESOLVER) is None
        assert proc.sni_names.most_common(1) == []

    def test_ciphertext_flow_is_abandoned_not_buffered(self) -> None:
        # A stream that can never be a ClientHello must be given up on, not re-parsed
        # over a growing buffer until FIN. A squatting false anchor also consumes the
        # reassembler's LRU budget, which can evict genuinely pending ClientHellos.
        proc = local_processor(DOT_CLIENT)
        feed_dot(proc, false_anchor_ciphertext())
        assert DOT_KEY not in proc.reassembler._flows
        assert proc.reassembler._total == 0

    def test_ciphertext_never_emits_an_sni_event(self) -> None:
        proc = local_processor(DOT_CLIENT)
        events = feed_dot(proc, false_anchor_ciphertext())
        assert [e for e in events if isinstance(e, TlsSniEvent)] == []


SERVER_IP = "93.184.216.34"
SERVER_KEY = (SERVER_IP, 443, "192.168.1.50", 51000)


def server_segment(data: bytes, flags: str = "A", seq: int = BASE_SEQ) -> Packet:
    pkt = (
        Ether()
        / IP(src=SERVER_IP, dst="192.168.1.50")
        / TCP(sport=443, dport=51000, flags=flags, seq=seq)
        / data
    )
    pkt.time = PKT_TIME
    return pkt


def tls_record(body: bytes, rtype: int = 0x16) -> bytes:
    return bytes([rtype, 0x03, 0x03]) + len(body).to_bytes(2, "big") + body


def server_hello_message() -> bytes:
    # TLS 1.2 ServerHello: version, random, empty session id, one suite, null
    # compression, empty extensions.
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x2f" + b"\x00" + b"\x00\x00"
    return b"\x02" + len(body).to_bytes(3, "big") + body


def certificate_message(*ders: bytes) -> bytes:
    # RFC 5246 §7.4.2: 3-byte chain length, then each certificate as 3-byte length + DER.
    chain = b"".join(len(d).to_bytes(3, "big") + d for d in ders)
    body = len(chain).to_bytes(3, "big") + chain
    return b"\x0b" + len(body).to_bytes(3, "big") + body


def self_signed_der(*sans: str) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "netmon-test")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2036, 1, 1, tzinfo=UTC))
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def server_certificate_flight(*sans: str) -> bytes:
    return tls_record(server_hello_message()) + tls_record(
        certificate_message(self_signed_der(*sans))
    )


class TestServerStreamStart:
    def test_serverhello_record_opens_the_server_flight(self) -> None:
        assert _server_stream_start(b"\x16\x03\x03\x00\x2e\x02") is StreamStart.OPENS

    def test_clienthello_record_is_rejected(self) -> None:
        assert _server_stream_start(CH_RECORD_HEADER) is StreamStart.REJECTED

    def test_ambiguous_short_prefix_is_undecided(self) -> None:
        # Too few bytes to settle it: anchor provisionally rather than lose a
        # ServerHello an attacker split across segments.
        assert _server_stream_start(b"\x16\x03") is StreamStart.UNDECIDED

    def test_application_data_is_rejected(self) -> None:
        assert _server_stream_start(b"\x17\x03\x03\x00\x10") is StreamStart.REJECTED


class TestExtractCertificateSans:
    def test_complete_flight_returns_the_leaf_dns_names(self) -> None:
        flight = server_certificate_flight("a.example.com", "b.example.com")
        assert extract_certificate_sans(flight) == ["a.example.com", "b.example.com"]

    def test_incomplete_flight_returns_none_to_keep_waiting(self) -> None:
        flight = server_certificate_flight("wait.example.com")
        assert extract_certificate_sans(flight[:60]) is None

    def test_cipher_change_before_a_certificate_is_terminal(self) -> None:
        # TLS 1.3 (and resumed TLS 1.2) never sends a cleartext Certificate: once a
        # non-handshake record follows the hello, stop waiting.
        flight = tls_record(server_hello_message()) + tls_record(b"\x01", rtype=0x14)
        assert extract_certificate_sans(flight) == []

    def test_malformed_der_is_terminal_and_yields_nothing(self) -> None:
        junk = certificate_message(b"\x30\x82\xff\xff" + b"\xcc" * 40)
        flight = tls_record(server_hello_message()) + tls_record(junk)
        assert extract_certificate_sans(flight) == []

    def test_certificate_without_san_extension_yields_nothing(self) -> None:
        assert extract_certificate_sans(server_certificate_flight()) == []


class TestTls12CertificateSan:
    def test_server_certificate_san_seeds_the_name_ledger(self) -> None:
        proc = local_processor("192.168.1.50")
        proc.process(server_segment(server_certificate_flight("cert.example.com"), flags="PA"))
        assert proc.names.lookup(SERVER_IP) == "cert.example.com"

    def test_recovered_name_names_a_later_flow_to_that_ip(self) -> None:
        proc = local_processor("192.168.1.50")
        proc.process(server_segment(server_certificate_flight("cert.example.com"), flags="PA"))
        events = proc.process(make_syn("192.168.1.50", SERVER_IP, 52000, 443))
        flows = [e for e in events if isinstance(e, FlowEvent)]
        assert len(flows) == 1
        assert flows[0].hostname == "cert.example.com"

    def test_certificate_split_across_segments_parses_after_the_last(self) -> None:
        proc = local_processor("192.168.1.50")
        flight = server_certificate_flight("split.example.com")
        first, second = flight[:120], flight[120:]
        proc.process(server_segment(first, seq=BASE_SEQ))
        assert proc.names.lookup(SERVER_IP) is None
        proc.process(server_segment(second, flags="PA", seq=BASE_SEQ + len(first)))
        assert proc.names.lookup(SERVER_IP) == "split.example.com"

    def test_reordered_server_segments_still_yield_the_san(self) -> None:
        proc = local_processor("192.168.1.50")
        flight = server_certificate_flight("reorder.example.com")
        # Split inside the ServerHello's zeroed random so the tail's first bytes are
        # deterministically unclaimable by any anchor gate (client, server, or DNS).
        first, second = flight[:20], flight[20:]
        proc.process(server_segment(second, seq=BASE_SEQ + len(first)))
        proc.process(server_segment(first, flags="PA", seq=BASE_SEQ))
        assert proc.names.lookup(SERVER_IP) == "reorder.example.com"

    def test_cert_san_never_clobbers_a_dns_or_sni_name(self) -> None:
        proc = local_processor("192.168.1.50")
        proc.names.observe(SERVER_IP, "real.example.com")
        proc.process(server_segment(server_certificate_flight("cert.example.com"), flags="PA"))
        assert proc.names.lookup(SERVER_IP) == "real.example.com"

    def test_wildcard_san_defers_to_a_concrete_name(self) -> None:
        proc = local_processor("192.168.1.50")
        flight = server_certificate_flight("*.cdn.example.com", "concrete.example.com")
        proc.process(server_segment(flight, flags="PA"))
        assert proc.names.lookup(SERVER_IP) == "concrete.example.com"

    def test_all_wildcard_sans_still_seed_the_first(self) -> None:
        proc = local_processor("192.168.1.50")
        proc.process(server_segment(server_certificate_flight("*.only.example.com"), flags="PA"))
        assert proc.names.lookup(SERVER_IP) == "*.only.example.com"

    def test_truncated_certificate_yields_nothing_and_does_not_crash(self) -> None:
        proc = local_processor("192.168.1.50")
        flight = server_certificate_flight("cut.example.com")
        proc.process(server_segment(flight[:120], flags="PA"))
        proc.process(server_segment(b"", flags="FA", seq=BASE_SEQ + 120))
        assert proc.names.lookup(SERVER_IP) is None
        assert proc.coverage.fate["parse_error"] == 0

    def test_malformed_der_stops_tracking_and_yields_nothing(self) -> None:
        proc = local_processor("192.168.1.50")
        junk = certificate_message(b"\x30\x82\xff\xff" + b"\xcc" * 40)
        flight = tls_record(server_hello_message()) + tls_record(junk)
        proc.process(server_segment(flight, flags="PA"))
        assert proc.names.lookup(SERVER_IP) is None
        assert not proc.certs.tracks(SERVER_KEY)
        assert proc.coverage.fate["parse_error"] == 0

    def test_tls13_stream_stops_buffering_after_cipher_change(self) -> None:
        proc = local_processor("192.168.1.50")
        flight = tls_record(server_hello_message()) + tls_record(b"\x01", rtype=0x14)
        proc.process(server_segment(flight, flags="PA"))
        assert proc.names.lookup(SERVER_IP) is None
        assert not proc.certs.tracks(SERVER_KEY)

    def test_fin_drops_the_server_stream(self) -> None:
        proc = local_processor("192.168.1.50")
        flight = server_certificate_flight("late.example.com")
        proc.process(server_segment(flight[:120], seq=BASE_SEQ))
        proc.process(server_segment(b"", flags="FA", seq=BASE_SEQ + 120))
        proc.process(server_segment(flight[120:], flags="PA", seq=BASE_SEQ + 120))
        assert proc.names.lookup(SERVER_IP) is None

    def test_client_direction_still_parses_sni_untouched(self) -> None:
        # The server-direction reassembler must not disturb the client path: the same
        # flow's ClientHello still yields its SNI event.
        proc = local_processor("192.168.1.50")
        events = proc.process(
            tcp_segment(build_client_hello(extensions=sni_extension(b"client.example.com")))
        )
        sni = [e for e in events if isinstance(e, TlsSniEvent)]
        assert len(sni) == 1
        assert sni[0].sni == "client.example.com"

    def test_cert_stream_evictions_surface_in_coverage(self) -> None:
        proc = local_processor("192.168.1.50")
        assert proc.summary()["coverage"]["evicted"]["cert_streams"] == 0

    def test_packet_completing_a_certificate_gets_a_cert_san_fate(self) -> None:
        # The segment whose certificate discloses a name must not be bookkept as
        # no_disclosure — the fate ledger stays honest about what the packet yielded.
        proc = local_processor("192.168.1.50")
        flight = server_certificate_flight("fate.example.com")
        first, second = flight[:120], flight[120:]
        proc.process(server_segment(first, seq=BASE_SEQ))
        proc.process(server_segment(second, flags="PA", seq=BASE_SEQ + len(first)))
        assert proc.coverage.fate["cert_san"] == 1
        assert proc.names.lookup(SERVER_IP) == "fate.example.com"

    def test_san_less_certificate_still_counts_as_no_disclosure(self) -> None:
        proc = local_processor("192.168.1.50")
        flight = server_certificate_flight()
        first, second = flight[:120], flight[120:]
        proc.process(server_segment(first, seq=BASE_SEQ))
        proc.process(server_segment(second, flags="PA", seq=BASE_SEQ + len(first)))
        assert proc.coverage.fate["cert_san"] == 0

    def test_client_stream_in_progress_stays_out_of_the_cert_pending_pool(self) -> None:
        # A key anchored as the client's ClientHello can never be the server's
        # certificate flight; buffering it again would let bulk client traffic evict
        # genuinely pending server segments.
        proc = local_processor("192.168.1.50")
        hello = pq_client_hello(b"guard.example.com")
        proc.process(tcp_segment(hello[:800], flags="A", seq=BASE_SEQ))
        assert not proc.certs._pending
        assert not proc.certs._flows


def _flow_events(proc: PacketProcessor, n: int, base_port: int = 40000) -> list[Event]:
    events: list[Event] = []
    for i in range(n):
        events += proc.process(make_syn("192.168.1.50", "93.184.216.34", base_port + i, 443))
    return events


class TestOutputRotation:
    def test_size_cap_rolls_output_to_numbered_files(self, tmp_path: Path) -> None:
        writer = JsonlWriter(tmp_path / "run", rotate_bytes=500, rotate_keep=10)
        for ev in _flow_events(local_processor("192.168.1.50"), 20):
            writer.write(ev)
        writer.close()
        names = sorted(p.name for p in (tmp_path / "run").glob("flows*.jsonl"))
        assert "flows.00001.jsonl" in names  # rolled archive
        assert "flows.jsonl" in names  # the active file keeps its canonical name

    def test_ring_never_exceeds_the_keep_bound(self, tmp_path: Path) -> None:
        writer = JsonlWriter(tmp_path / "run", rotate_bytes=300, rotate_keep=2)
        for ev in _flow_events(local_processor("192.168.1.50"), 60):
            writer.write(ev)
        writer.close()
        archives = list((tmp_path / "run").glob("flows.[0-9]*.jsonl"))
        assert 0 < len(archives) <= 2
        assert not (tmp_path / "run" / "flows.00001.jsonl").exists()  # oldest deleted

    def test_rotated_files_keep_owner_only_mode(self, tmp_path: Path) -> None:
        writer = JsonlWriter(tmp_path / "run", rotate_bytes=300, rotate_keep=5)
        for ev in _flow_events(local_processor("192.168.1.50"), 20):
            writer.write(ev)
        writer.close()
        for path in (tmp_path / "run").glob("flows*.jsonl"):
            assert (path.stat().st_mode & 0o777) == 0o600

    def test_rotation_failure_degrades_without_faking_drops(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A failed roll is housekeeping, not data loss: the event that triggered it
        # was already written and must not be counted as dropped. Every event is
        # either on disk or in write_failures — the ledger stays exact.
        writer = JsonlWriter(tmp_path / "run", rotate_bytes=300, rotate_keep=5)
        events = _flow_events(local_processor("192.168.1.50"), 20)

        def refuse(self: Path, target: Path) -> Path:
            raise OSError(errno.EROFS, "read-only file system")

        monkeypatch.setattr(Path, "rename", refuse)
        for ev in events:
            writer.write(ev)  # must not raise
        writer.close()
        assert writer.write_failures > 0
        written = sum(1 for _ in (tmp_path / "run" / "flows.jsonl").open())
        assert written + writer.write_failures == len(events)

    def test_pcap_rotation_reopen_still_refuses_a_symlink_swap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The post-roll reopen carries the same CWE-59 discipline as every other
        # create: a pre-staged file/symlink at the canonical name must crash-stop,
        # never silently degrade into "disk full".
        import netmon

        run = tmp_path / "run"
        run.mkdir()
        sink = PcapSink(run / "capture.pcap", rotate_bytes=100, rotate_keep=2)

        def planted(path: Path) -> Any:
            raise OSError(errno.EEXIST, "pre-staged file")

        monkeypatch.setattr(netmon, "open_private_new_bytes", planted)
        with pytest.raises(OSError):
            for i in range(10):
                sink.write(make_syn("192.168.1.50", "93.184.216.34", 40000 + i, 443))

    def test_prune_orders_archives_numerically_past_the_pad_width(self, tmp_path: Path) -> None:
        # Lexical ordering would sort 100000 before 99999 and prune the newest
        # archives; the ring must order by sequence number.
        writer = JsonlWriter(tmp_path / "run", rotate_bytes=300, rotate_keep=2)
        writer._rolled["flows.jsonl"] = 99998
        for ev in _flow_events(local_processor("192.168.1.50"), 60):
            writer.write(ev)
        writer.close()
        names = sorted(p.name for p in (tmp_path / "run").glob("flows.[0-9]*.jsonl"))
        assert len(names) <= 2
        assert all(int(n.split(".")[1]) >= 100000 for n in names)  # newest survive

    def test_rotate_flags_are_clamped_to_sane_values(self, tmp_path: Path) -> None:
        from netmon import build_session

        args = _legacy_parser().parse_args(
            ["-o", str(tmp_path), "--rotate-mb", "-5", "--rotate-keep", "0"]
        )
        session = build_session(args)
        assert isinstance(session.writer, JsonlWriter)
        assert session.writer.rotate_bytes == 0  # negative = off, never roll-every-write
        assert session.writer.rotate_keep >= 1  # never delete-on-create
        session.writer.close()

    def test_rotation_off_by_default_keeps_single_files(self, tmp_path: Path) -> None:
        writer = JsonlWriter(tmp_path / "run")
        for ev in _flow_events(local_processor("192.168.1.50"), 40):
            writer.write(ev)
        writer.close()
        assert [p.name for p in (tmp_path / "run").glob("flows*.jsonl")] == ["flows.jsonl"]

    def test_query_reads_rotated_archives_as_one_timeline(self, tmp_path: Path) -> None:
        writer = JsonlWriter(tmp_path / "run", rotate_bytes=500, rotate_keep=10)
        events = _flow_events(local_processor("192.168.1.50"), 20)
        for ev in events:
            writer.write(ev)
        writer.close()
        from netmon import _load_run_events

        read = list(_load_run_events(tmp_path / "run", frozenset(KIND_VALUES)))
        assert len(read) == len(events)  # nothing lost across the roll

    def test_pcap_sink_rolls_and_bounds_the_ring(self, tmp_path: Path) -> None:
        run = tmp_path / "run"
        run.mkdir()
        sink = PcapSink(run / "capture.pcap", rotate_bytes=2_000, rotate_keep=2)
        for i in range(60):
            pkt = make_syn("192.168.1.50", "93.184.216.34", 40000 + i, 443)
            sink.write(pkt)
        sink.close()
        archives = sorted(run.glob("capture.[0-9]*.pcap"))
        assert 0 < len(archives) <= 2
        assert (run / "capture.pcap").exists()
        for archive in archives:
            assert len(rdpcap(str(archive))) > 0  # every rolled file is a valid pcap

    def test_rotate_flags_reach_the_writer_and_sink(self, tmp_path: Path) -> None:
        from netmon import build_session

        args = _legacy_parser().parse_args(
            ["-o", str(tmp_path), "--pcap", "--rotate-mb", "5", "--rotate-keep", "3"]
        )
        session = build_session(args)
        assert isinstance(session.writer, JsonlWriter)
        assert session.writer.rotate_bytes == 5_000_000
        assert session.writer.rotate_keep == 3
        assert session.pcap_sink is not None
        assert session.pcap_sink.rotate_bytes == 5_000_000
        session.writer.close()
        session.pcap_sink.close()


def _completed(argv: list[str], rc: int, out: str = "", err: str = "") -> Any:
    return subprocess.CompletedProcess(argv, rc, out, err)


class TestLiveCaptureQueue:
    async def test_enqueue_overflow_counts_userspace_drops_and_stop_drains(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The sniffer thread hands packets to the loop via call_soon_threadsafe;
        # a full queue must count the drop (the stats/summary line every operator
        # reads) and never block, and stop must still drain what was queued.
        import netmon

        sent = [make_syn("192.168.1.50", "93.184.216.34", 40000 + i, 443) for i in range(5)]
        straggler = make_syn("192.168.1.50", "93.184.216.34", 49999, 443)

        class FakeSniffer:
            running = True

            def __init__(self, opened_socket: dict[Any, str], prn: Any, store: bool) -> None:
                self.prn = prn

            def start(self) -> None:
                for pkt in sent:
                    self.prn(pkt)

            def stop(self, join: bool = True) -> None:
                # The real sniffer thread can hand over a last packet while the
                # loop thread blocks in join(): its enqueue callback only lands
                # after control returns to the event loop — the exact race the
                # post-stop drain exists for.
                self.running = False
                self.prn(straggler)

        class FakeSock:
            def close(self) -> None: ...

        monkeypatch.setattr(netmon, "AsyncSniffer", FakeSniffer)
        monkeypatch.setattr(
            netmon.conf, "L2listen", lambda iface, filter, promisc: FakeSock(), raising=False
        )
        cap = LiveCapture(["fake0"], None, queue_size=2)
        received = []
        async with asyncio.timeout(5):  # a delivery regression must fail, not hang CI
            async for pkt in cap.packets():
                received.append(pkt)
                if len(received) == 2:
                    cap.stop()
        assert received == [*sent[:2], straggler]  # queued arrive in order; stop drains
        assert cap.stats().userspace_dropped == 3  # the overflow is counted, not hidden


class TestCmdUpdate:
    def _which(self, *, systemctl: bool = True) -> Any:
        return lambda name: None if (name == "systemctl" and not systemctl) else f"/usr/bin/{name}"

    def _pip_install(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        import netmon

        # A venv with a pip in it is, authoritatively, one the pip/requirements.txt path
        # built: `uv sync` never seeds pip into the venv it creates.
        (tmp_path / ".venv" / "bin").mkdir(parents=True)
        (tmp_path / ".venv" / "bin" / "pip").touch()
        (tmp_path / "requirements.txt").touch()
        monkeypatch.setattr(netmon, "_install_dir", lambda: tmp_path)
        return tmp_path

    def test_refuses_when_git_is_missing(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: None)
        assert cmd_update([]) == 1
        assert "needs git" in capsys.readouterr().err

    def test_refuses_when_no_builder_can_be_found(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import netmon

        # No uv on PATH and no pip in the venv: there is no way to rebuild this install, and
        # saying so beats pulling first and discovering it afterwards.
        monkeypatch.setattr(netmon, "_install_dir", lambda: tmp_path)
        monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/git" if name == "git" else None)
        assert cmd_update([]) == 1
        assert "cannot sync this install" in capsys.readouterr().err

    def test_a_pip_built_install_updates_with_pip_not_uv(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Re-syncing a pip-built venv with uv would rebuild it around a different interpreter
        # and silently drop any --setcap grant on the current one -- passwordless capture would
        # just stop working, with nothing said.
        dir_ = self._pip_install(tmp_path, monkeypatch)
        monkeypatch.setattr(shutil, "which", self._which())
        ran: list[list[str]] = []

        def fake_run(argv: list[str], **kw: Any) -> Any:
            ran.append(argv)
            if "--short" in argv:
                return _completed(argv, 0, out="aaa1111\n")
            if "--porcelain" in argv:
                return _completed(argv, 0, out="")
            if "--name-only" in argv:
                return _completed(argv, 0, out="netmon.py\n")
            return _completed(argv, 0, out="true")

        monkeypatch.setattr(subprocess, "run", fake_run)
        assert cmd_update([]) == 0
        pip_py = str(dir_ / ".venv" / "bin" / "python3")
        deps = [a for a in ran if a[:3] == [pip_py, "-m", "pip"]]
        assert deps, "a pip-built install must be updated with its own pip"
        assert "--require-hashes" in deps[0]  # an update must not pull an unpinned dependency
        assert str(dir_ / "requirements.txt") in deps[0]
        assert not [a for a in ran if a[0] == "/usr/bin/uv"]  # uv is never used here

    def test_a_uv_built_install_still_updates_with_uv_sync(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(shutil, "which", self._which())
        ran: list[list[str]] = []

        def fake_run(argv: list[str], **kw: Any) -> Any:
            ran.append(argv)
            if "--short" in argv:
                return _completed(argv, 0, out="aaa1111\n")
            if "--porcelain" in argv:
                return _completed(argv, 0, out="")
            return _completed(argv, 0, out="true")

        monkeypatch.setattr(subprocess, "run", fake_run)
        assert cmd_update([]) == 0
        assert [a for a in ran if a[:2] == ["/usr/bin/uv", "sync"]]

    def test_pip_reinstalls_the_project_only_when_pyproject_changed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # An unconditional editable reinstall reaches PyPI for the build backend on every
        # no-op update -- a real regression against `uv sync`, which does nothing when
        # nothing changed. Only pyproject can change the installed metadata; the code is
        # editable and takes effect from the pull alone.
        dir_ = self._pip_install(tmp_path, monkeypatch)
        monkeypatch.setattr(shutil, "which", self._which())
        changed: list[str] = ["netmon.py\n"]
        ran: list[list[str]] = []

        def fake_run(argv: list[str], **kw: Any) -> Any:
            ran.append(argv)
            if "--short" in argv:
                return _completed(argv, 0, out=("aaa1111\n" if len(ran) < 4 else "bbb2222\n"))
            if "--porcelain" in argv:
                return _completed(argv, 0, out="")
            if "--name-only" in argv:
                return _completed(argv, 0, out=changed[0])
            return _completed(argv, 0, out="true")

        monkeypatch.setattr(subprocess, "run", fake_run)
        assert cmd_update([]) == 0
        assert not [a for a in ran if "-e" in a], "no pyproject change => no editable reinstall"

        ran.clear()
        changed[0] = "pyproject.toml\nnetmon.py\n"
        assert cmd_update([]) == 0
        editable = [a for a in ran if "-e" in a]
        assert editable and str(dir_) in editable[0]

    def test_an_unreadable_diff_reinstalls_rather_than_skipping(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Fail safe: if we cannot tell whether pyproject moved, rebuild. A skipped reinstall
        # is a silently stale entry point; a redundant one merely costs time.
        self._pip_install(tmp_path, monkeypatch)
        monkeypatch.setattr(shutil, "which", self._which())
        ran: list[list[str]] = []

        def fake_run(argv: list[str], **kw: Any) -> Any:
            ran.append(argv)
            if "--name-only" in argv:
                return _completed(argv, 128, err="fatal: bad revision")
            if "--short" in argv:
                return _completed(argv, 0, out=("aaa1111\n" if len(ran) < 4 else "bbb2222\n"))
            if "--porcelain" in argv:
                return _completed(argv, 0, out="")
            return _completed(argv, 0, out="true")

        monkeypatch.setattr(subprocess, "run", fake_run)
        assert cmd_update([]) == 0
        assert [a for a in ran if "-e" in a]

    def test_resolves_the_sync_plan_before_pulling(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import netmon

        # An install that cannot be synced must not be left pulled-but-unbuilt.
        monkeypatch.setattr(netmon, "_install_dir", lambda: tmp_path)
        monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/git" if name == "git" else None)
        ran: list[list[str]] = []

        def fake_run(argv: list[str], **kw: Any) -> Any:
            ran.append(argv)
            return _completed(argv, 0, out="true")

        monkeypatch.setattr(subprocess, "run", fake_run)
        assert cmd_update([]) == 1
        assert not [a for a in ran if "pull" in a]
        assert "cannot sync this install" in capsys.readouterr().err

    def test_refuses_outside_a_git_checkout(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(shutil, "which", self._which())

        def fake_run(argv: list[str], **kw: Any) -> Any:
            assert "--is-inside-work-tree" in argv
            return _completed(argv, 128, err="fatal: not a git repository")

        monkeypatch.setattr(subprocess, "run", fake_run)
        assert cmd_update([]) == 1
        assert "not a git checkout" in capsys.readouterr().err

    def test_refuses_a_dirty_working_tree(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(shutil, "which", self._which())

        def fake_run(argv: list[str], **kw: Any) -> Any:
            if "--porcelain" in argv:
                return _completed(argv, 0, out=" M netmon.py\n")
            return _completed(argv, 0, out="true")

        monkeypatch.setattr(subprocess, "run", fake_run)
        assert cmd_update([]) == 1
        assert "working tree has local changes" in capsys.readouterr().err

    def test_reports_a_failed_ff_only_pull(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(shutil, "which", self._which())

        def fake_run(argv: list[str], **kw: Any) -> Any:
            if "pull" in argv:
                return _completed(argv, 1, err="fatal: Not possible to fast-forward")
            if "--porcelain" in argv:
                return _completed(argv, 0, out="")
            return _completed(argv, 0, out="true")

        monkeypatch.setattr(subprocess, "run", fake_run)
        assert cmd_update([]) == 1
        assert "fast-forward" in capsys.readouterr().err

    def test_reports_a_failed_uv_sync(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(shutil, "which", self._which())

        def fake_run(argv: list[str], **kw: Any) -> Any:
            if argv[0] == "/usr/bin/uv":
                return _completed(argv, 1)
            if "--porcelain" in argv:
                return _completed(argv, 0, out="")
            return _completed(argv, 0, out="true")

        monkeypatch.setattr(subprocess, "run", fake_run)
        assert cmd_update([]) == 1
        assert "uv dependency sync failed" in capsys.readouterr().err

    def test_restarts_an_active_service_and_reports_revisions(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(shutil, "which", self._which())
        revisions = iter(["aaa1111", "bbb2222"])
        restarted: list[list[str]] = []

        def fake_run(argv: list[str], **kw: Any) -> Any:
            if "restart" in argv:
                restarted.append(argv)
                return _completed(argv, 0)
            if "is-active" in argv:
                return _completed(argv, 0)
            if "--short" in argv:
                return _completed(argv, 0, out=next(revisions) + "\n")
            if "--porcelain" in argv:
                return _completed(argv, 0, out="")
            return _completed(argv, 0, out="true")

        monkeypatch.setattr(subprocess, "run", fake_run)
        assert cmd_update([]) == 0
        out = capsys.readouterr().out
        assert restarted == [["/usr/bin/systemctl", "restart", "netmon.service"]]
        assert "restarted netmon.service" in out
        assert "netmon updated aaa1111 -> bbb2222" in out

    def test_already_up_to_date_without_systemd(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(shutil, "which", self._which(systemctl=False))

        def fake_run(argv: list[str], **kw: Any) -> Any:
            assert "systemctl" not in argv[0]  # no restart path without systemd
            if "--short" in argv:
                return _completed(argv, 0, out="aaa1111\n")
            if "--porcelain" in argv:
                return _completed(argv, 0, out="")
            return _completed(argv, 0, out="true")

        monkeypatch.setattr(subprocess, "run", fake_run)
        assert cmd_update([]) == 0
        assert "already up to date (aaa1111)" in capsys.readouterr().out


class TestCmdService:
    def test_unknown_action_prints_usage_and_exits_2(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert cmd_service(["frobnicate"]) == 2
        assert "usage: netmon service" in capsys.readouterr().err

    def test_no_action_prints_usage_and_exits_2(self) -> None:
        assert cmd_service([]) == 2

    def test_missing_systemd_exits_1(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: None)
        assert cmd_service(["status"]) == 1
        assert "systemd not available" in capsys.readouterr().err

    def _recording_run(self, calls: list[list[str]], rc: int) -> Any:
        def fake_run(argv: list[str], **kw: Any) -> Any:
            calls.append(argv)
            return _completed(argv, rc)

        return fake_run

    def test_logs_follows_the_unit_journal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[list[str]] = []
        monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr(subprocess, "run", self._recording_run(calls, 0))
        assert cmd_service(["logs"]) == 0
        assert calls == [["/usr/bin/journalctl", "-u", "netmon.service", "-f"]]

    def test_action_passes_through_and_propagates_the_exit_code(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[list[str]] = []
        monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr(subprocess, "run", self._recording_run(calls, 3))
        assert cmd_service(["restart"]) == 3
        assert calls == [["/usr/bin/systemctl", "restart", "netmon.service"]]


class TestCliGuards:
    def test_tui_without_a_tty_exits_2(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # `netmon run` implies the TUI; with a non-tty stdin the guard must refuse
        # before any capture/privilege work. Pinned explicitly so the test never
        # depends on how pytest was invoked (-s would hand it the real tty).
        monkeypatch.setattr(sys, "stdin", io.StringIO())
        with pytest.raises(SystemExit) as exc:
            main(["run"])
        assert exc.value.code == 2
        assert "interactive terminal" in capsys.readouterr().err

    def test_privilege_check_exits_1_when_raw_sockets_are_denied(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import netmon

        def deny(*a: Any, **k: Any) -> Any:
            raise PermissionError

        monkeypatch.setattr(netmon.socket, "socket", deny)
        with pytest.raises(SystemExit) as exc:
            check_capture_privileges()
        assert exc.value.code == 1

    def test_privilege_check_passes_when_raw_sockets_open(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import netmon

        class Ok:
            def __init__(self, *a: Any, **k: Any) -> None: ...
            def close(self) -> None: ...

        monkeypatch.setattr(netmon.socket, "socket", Ok)
        check_capture_privileges()  # must not raise


class TestBuildSessionLive:
    def test_live_capture_opens_all_working_ifaces(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        import netmon

        monkeypatch.setattr(
            netmon,
            "get_working_ifaces",
            lambda: [argparse.Namespace(name="eth0"), argparse.Namespace(name="wlan0")],
        )
        args = _legacy_parser().parse_args(["-o", str(tmp_path)])
        session = build_session(args)
        assert isinstance(session.capture, LiveCapture)
        assert session.capture.ifaces == ["eth0", "wlan0"]
        session.writer.close()

    def test_iface_flag_narrows_the_capture(self, tmp_path: Path) -> None:
        args = _legacy_parser().parse_args(["-o", str(tmp_path), "-i", "wlan0"])
        session = build_session(args)
        assert isinstance(session.capture, LiveCapture)
        assert session.capture.ifaces == ["wlan0"]
        session.writer.close()


class TestStatsAndAnnounce:
    async def test_stats_loop_polls_capture_stats_on_its_cadence(self) -> None:
        class FakeCapture:
            def __init__(self) -> None:
                self.polls = 0

            def stats(self) -> CaptureStats:
                self.polls += 1
                return CaptureStats(0, 0, None, None)

            def stop(self) -> None: ...
            def packets(self) -> Any: ...

        fake = FakeCapture()
        session = Session(Path("unused"), local_processor(), NullWriter(), fake)
        task = asyncio.create_task(stats_loop(session, interval=0.01))
        try:
            for _ in range(100):
                await asyncio.sleep(0.01)
                if fake.polls >= 2:
                    break
        finally:
            task.cancel()
        assert fake.polls >= 2

    def test_announce_replay_logs_the_evidence_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Capture the structured events directly; reconfiguring structlog inside a
        # test would bind it to pytest's transient captured stdout for good.
        import netmon

        records: list[tuple[str, dict[str, Any]]] = []
        monkeypatch.setattr(
            netmon, "log", argparse.Namespace(info=lambda ev, **kw: records.append((ev, kw)))
        )
        args = _legacy_parser().parse_args(["-r", "x.pcap", "-o", str(tmp_path)])
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        sink = PcapSink(run_dir / "capture.pcap")
        session = Session(
            run_dir, local_processor(), NullWriter(), ReplayCapture(Path("x.pcap")), sink
        )
        announce_start(args, session)
        sink.close()
        assert records[0][0] == "replay_started"
        assert str(records[0][1]["evidence"]).endswith("capture.pcap")

    def test_announce_live_logs_ifaces_and_local_ips(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import netmon

        records: list[tuple[str, dict[str, Any]]] = []
        monkeypatch.setattr(
            netmon, "log", argparse.Namespace(info=lambda ev, **kw: records.append((ev, kw)))
        )
        args = _legacy_parser().parse_args(["-o", str(tmp_path)])
        session = Session(
            tmp_path / "run",
            local_processor("192.168.1.50"),
            NullWriter(),
            LiveCapture(["eth0"], None),
        )
        announce_start(args, session)
        assert records[0][0] == "capture_started"
        assert records[0][1]["ifaces"] == ["eth0"]
        assert records[0][1]["local_ips"] == ["192.168.1.50"]


class TestTunnelAndNonEthernet:
    def test_raw_ip_frame_from_a_tun_link_yields_a_flow(self) -> None:
        # A tun/wireguard/ppp capture has no Ethernet header — the frame IS the IP
        # packet. It must decode like any other, not fall into a non_ip fate.
        proc = local_processor("192.168.1.50")
        pkt = IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=51000, dport=443, flags="S")
        pkt.time = PKT_TIME
        flow = single_flow(proc.process(pkt))
        assert flow.direction == "outbound"
        assert flow.remote_ip == "93.184.216.34"

    def test_raw_ipv6_frame_yields_a_flow(self) -> None:
        proc = local_processor("2606:4700::10")
        pkt = IPv6(src="2606:4700::10", dst="2606:4700::1") / TCP(sport=51000, dport=443, flags="S")
        pkt.time = PKT_TIME
        flow = single_flow(proc.process(pkt))
        assert flow.remote_ip == "2606:4700::1"

    def test_cooked_linux_frame_decodes_the_ip_inside(self) -> None:
        # A pcap captured with -i any wraps frames in Linux cooked (SLL) headers.
        proc = local_processor("192.168.1.50")
        pkt = (
            CookedLinux(proto=0x0800)
            / IP(src="192.168.1.50", dst="93.184.216.34")
            / TCP(sport=51000, dport=443, flags="S")
        )
        pkt.time = PKT_TIME
        flow = single_flow(proc.process(pkt))
        assert flow.remote_ip == "93.184.216.34"

    def test_6in4_flow_reflects_the_inner_endpoints(self) -> None:
        # getlayer(IP) returns the tunnel's outer header while getlayer(TCP) returns
        # the inner ports; the flow must name the real peer, not the tunnel server.
        proc = local_processor("192.168.1.50", "2001:470:1f0b::2")
        pkt = (
            Ether()
            / IP(src="192.168.1.50", dst="203.0.113.1")
            / IPv6(src="2001:470:1f0b::2", dst="2606:4700::1")
            / TCP(sport=51000, dport=443, flags="S")
        )
        pkt.time = PKT_TIME
        flow = single_flow(proc.process(pkt))
        assert flow.remote_ip == "2606:4700::1"
        assert flow.local_ip == "2001:470:1f0b::2"
        assert flow.direction == "outbound"

    def test_ipip_flow_reflects_the_inner_endpoints(self) -> None:
        proc = local_processor("192.168.1.50", "10.200.0.2")
        pkt = (
            Ether()
            / IP(src="192.168.1.50", dst="203.0.113.1")
            / IP(src="10.200.0.2", dst="93.184.216.34")
            / TCP(sport=51000, dport=443, flags="S")
        )
        pkt.time = PKT_TIME
        flow = single_flow(proc.process(pkt))
        assert flow.remote_ip == "93.184.216.34"
        assert flow.local_ip == "10.200.0.2"

    def test_fragmented_middle_tunnel_stops_the_descent(self) -> None:
        # A first-fragment of a nested tunnel datagram dissects fully but cannot
        # vouch for its inner packet; both its fragments must attribute to the
        # fragmented layer's endpoints, never to a possibly-truncated deeper one.
        proc = local_processor("192.168.1.50")
        first = (
            Ether()
            / IP(src="192.168.1.50", dst="203.0.113.1", proto=4)
            / IP(src="10.200.0.2", dst="93.184.216.34", proto=4, flags="MF")
            / IP(src="172.16.0.9", dst="8.8.8.8")
            / TCP(sport=51000, dport=443, flags="S")
        )
        first.time = PKT_TIME
        events = proc.process(first)
        flows = [e for e in events if isinstance(e, FlowEvent)]
        assert all(f.remote_ip != "8.8.8.8" for f in flows)  # never the unvouched inner
        later = (
            Ether()
            / IP(src="192.168.1.50", dst="203.0.113.1", proto=4)
            / IP(src="10.200.0.2", dst="93.184.216.34", proto=4, frag=100)
            / (b"\x00" * 32)
        )
        later.time = PKT_TIME
        proc.process(later)
        assert proc.summary()["coverage"]["fate"]["ip_fragment"] >= 1

    def test_fragmented_outer_tunnel_is_accounted_as_a_fragment(self) -> None:
        # A fragmented outer header cannot vouch for a complete inner one: never
        # descend into what may be a truncated inner packet.
        proc = local_processor("192.168.1.50")
        pkt = (
            Ether()
            / IP(src="192.168.1.50", dst="203.0.113.1", proto=41, flags="MF")
            / (b"\x60" + b"\x00" * 39)
        )
        pkt.time = PKT_TIME
        proc.process(pkt)
        assert proc.summary()["coverage"]["fate"]["ip_fragment"] == 1


class TestRefreshLocalAddresses:
    def test_flow_from_a_new_own_address_reclassifies_outbound(self) -> None:
        # An RFC 4941 rotation / DHCP renewal adds an own global address mid-run;
        # before a refresh its egress misclassifies as transit, after it is outbound.
        # Genuinely global addresses (not TEST-NET, which classifies as on-link).
        proc = local_processor("93.184.216.40")
        before = single_flow(proc.process(make_syn("93.184.216.50", "104.16.1.1", 40000, 443)))
        assert before.direction == "transit"
        proc.refresh_local_ips(frozenset({"93.184.216.40", "93.184.216.50"}))
        after = single_flow(proc.process(make_syn("93.184.216.50", "104.16.1.1", 40001, 443)))
        assert after.direction == "outbound"

    def test_local_addresses_reenumerates_interfaces_via_reload(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # conf.ifaces caches enumeration at import; without a reload a mid-run
        # refresh would keep returning the boot-time snapshot forever.
        class FakeIfaces(dict):  # type: ignore[type-arg]
            reloads = 0

            def reload(self) -> None:
                self.reloads += 1
                self["eth0"] = argparse.Namespace(ips={4: ["198.51.100.7"], 6: []})

        fake = FakeIfaces()
        monkeypatch.setattr(conf, "ifaces", fake)
        assert "198.51.100.7" in local_addresses()
        assert fake.reloads == 1

    def test_empty_refresh_keeps_the_known_addresses(self) -> None:
        # A transient enumeration failure must never blank the set and flip every
        # own flow to transit.
        proc = local_processor("203.0.113.10")
        proc.refresh_local_ips(frozenset())
        assert proc.local_ips == frozenset({"203.0.113.10"})

    def test_refresh_does_not_drop_in_flight_state(self) -> None:
        proc = local_processor("203.0.113.10")
        proc.names.observe("93.184.216.34", "keep.example.com")
        proc.process(make_syn("203.0.113.10", "93.184.216.34", 40000, 443))
        proc.refresh_local_ips(frozenset({"203.0.113.10"}))
        assert proc.names.lookup("93.184.216.34") == "keep.example.com"
        assert proc.process(make_syn("203.0.113.10", "93.184.216.34", 40000, 443)) == []

    async def test_refresh_loop_feeds_current_addresses_to_the_processor(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import netmon

        proc = local_processor("203.0.113.10")
        session = Session(Path("unused"), proc, NullWriter(), ReplayCapture(Path("x")))
        monkeypatch.setattr(netmon, "local_addresses", lambda: frozenset({"198.51.100.7"}))
        task = asyncio.create_task(refresh_local_ips_loop(session, interval=0.01))
        try:
            for _ in range(100):
                await asyncio.sleep(0.01)
                if "198.51.100.7" in proc.local_ips:
                    break
        finally:
            task.cancel()
        assert "198.51.100.7" in proc.local_ips


RFC_DCID = bytes.fromhex("8394c8f03e515708")

# RFC 9001 Appendix A.2 — the sample protected client Initial packet, verbatim.
# Its ClientHello carries SNI "example.com". Real on-wire bytes, so this pins
# the whole decrypt path (header reconstruction, AAD, AEAD, CRYPTO parse)
# against the standard rather than only against our own encoder.
RFC9001_A2_CLIENT_INITIAL = bytes.fromhex(
    """
    c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11
    d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399
    1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c
    8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212
    30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5
    457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208
    4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec
    4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3
    485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db
    059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c
    7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8
    9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556
    be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74
    68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a
    c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00
    f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632
    291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964
    25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd
    14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff
    ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198
    e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd
    c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73
    203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f
    cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e
    fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade
    a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047
    90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2
    162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4
    40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0
    6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e
    8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0
    be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400
    54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab
    760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9
    f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4
    056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064
    7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241
    e221af44860018ab0856972e194cd934
    """
)


def encode_varint(v: int) -> bytes:
    if v < 0x40:
        return bytes([v])
    if v < 0x4000:
        return (v | 0x4000).to_bytes(2, "big")
    if v < 0x40000000:
        return (v | 0x80000000).to_bytes(4, "big")
    return (v | 0xC000000000000000).to_bytes(8, "big")


def crypto_frame(data: bytes, offset: int = 0) -> bytes:
    return b"\x06" + encode_varint(offset) + encode_varint(len(data)) + data


def handshake_message(name: bytes, extra_ext: bytes = b"") -> bytes:
    # A ClientHello as a bare TLS handshake message (no record layer), as it
    # appears inside a QUIC CRYPTO frame. build_client_hello wraps it in a
    # 5-byte TLS record header, which we strip.
    return build_client_hello(extensions=sni_extension(name) + extra_ext)[5:]


def encrypt_initial(dcid: bytes, plaintext: bytes, version: int = QUIC_V1, pn: int = 0) -> bytes:
    # Construct an encrypted QUIC Initial the way a real client does, so the
    # decryptor is exercised end to end.
    key, iv, hp = derive_initial_keys(dcid, version)
    pn_len = 4
    pn_bytes = pn.to_bytes(pn_len, "big")
    ptype = 0 if version == QUIC_V1 else 1
    first = 0xC0 | (ptype << 4) | (pn_len - 1)
    length = pn_len + len(plaintext) + 16
    header = (
        bytes([first])
        + version.to_bytes(4, "big")
        + bytes([len(dcid)])
        + dcid
        + b"\x00"  # source connection id length 0
        + encode_varint(0)  # token length 0
        + encode_varint(length)
    )
    pn_offset = len(header)
    aad = header + pn_bytes
    ciphertext = AESGCM(key).encrypt(packet_nonce(iv, pn), plaintext, aad)
    sample = (aad + ciphertext)[pn_offset + 4 : pn_offset + 4 + 16]
    mask = header_protection_mask(hp, sample)
    protected_first = first ^ (mask[0] & 0x0F)
    protected_pn = bytes(pn_bytes[i] ^ mask[1 + i] for i in range(pn_len))
    return bytes([protected_first]) + header[1:] + protected_pn + ciphertext


class TestQuicKeyDerivation:
    def test_rfc9001_appendix_a1_client_initial_keys(self) -> None:
        key, iv, hp = derive_initial_keys(RFC_DCID, QUIC_V1)
        assert key.hex() == "1f369613dd76d5467730efcbe3b1a22d"
        assert iv.hex() == "fa044b2f42a3fd3b46fb255c"
        assert hp.hex() == "9f50449e04a0e810283a1e9933adedd2"


class TestQuicSniExtraction:
    def test_rfc9001_a2_sample_client_initial_yields_example_com(self) -> None:
        hello = QuicReassembler().add(RFC9001_A2_CLIENT_INITIAL)
        assert hello is not None
        assert hello.sni == "example.com"

    def test_decrypts_initial_and_extracts_sni(self) -> None:
        reasm = QuicReassembler()
        datagram = encrypt_initial(RFC_DCID, crypto_frame(handshake_message(b"quic.example.com")))
        hello = reasm.add(datagram)
        assert hello is not None
        assert hello.sni == "quic.example.com"
        assert hello.ech is False

    def test_crypto_stream_split_across_two_initials(self) -> None:
        reasm = QuicReassembler()
        msg = handshake_message(b"big.example.com", extra_ext=padding_extension(2000))
        mid = len(msg) // 2
        first = encrypt_initial(RFC_DCID, crypto_frame(msg[:mid], offset=0), pn=0)
        second = encrypt_initial(RFC_DCID, crypto_frame(msg[mid:], offset=mid), pn=1)
        assert reasm.add(first) is None
        hello = reasm.add(second)
        assert hello is not None
        assert hello.sni == "big.example.com"

    def test_flood_of_distinct_dcids_evicts_oldest_not_all(self) -> None:
        # Initial keys are publicly derivable, so a flood of distinct DCIDs is
        # attacker-triggerable. LRU ages out the oldest connections, keeping the newest
        # and counting each eviction, instead of periodically wiping every in-flight one.
        r = QuicReassembler(max_conns=3)
        partial = crypto_frame(handshake_message(b"x.example.com", padding_extension(2000))[:100])
        dcids = [bytes([i]) + b"\x00" * 7 for i in range(5)]
        for dcid in dcids:
            assert r.add(encrypt_initial(dcid, partial)) is None  # never completes
        assert len(r._crypto) <= 3
        assert dcids[-1] in r._crypto  # newest survives
        assert dcids[0] not in r._crypto  # oldest evicted
        assert r.cleared == 2  # 5 fed, 3 kept -> 2 evicted, not a full wipe

    def test_flood_spares_the_recently_active_multi_initial(self) -> None:
        # A post-quantum ClientHello spans two Initials. A concurrent flood must not
        # discard it mid-reassembly: LRU keeps the recently-active connection alive
        # between its parts (clear-all wiped it on any cap breach), so the second
        # Initial still completes it.
        r = QuicReassembler(max_conns=2)
        msg = handshake_message(b"legit.example.com", padding_extension(2000))
        mid = len(msg) // 2
        legit = bytes([0xAA]) + b"\x00" * 7
        j1, j2 = bytes([0xB1]) + b"\x00" * 7, bytes([0xB2]) + b"\x00" * 7
        r.add(encrypt_initial(j1, crypto_frame(b"\x00" * 50)))  # older junk
        assert r.add(encrypt_initial(legit, crypto_frame(msg[:mid], offset=0), pn=0)) is None
        r.add(encrypt_initial(j2, crypto_frame(b"\x00" * 50)))  # breach: evicts oldest (j1)
        assert legit in r._crypto  # the recently-active connection was spared
        hello = r.add(encrypt_initial(legit, crypto_frame(msg[mid:], offset=mid), pn=1))
        assert hello is not None
        assert hello.sni == "legit.example.com"

    def test_reassemble_terminates_on_empty_chunk(self) -> None:
        # An empty chunk at a reachable offset must be treated as the end of the
        # contiguous prefix, never spun over forever (a zero-length QUIC CRYPTO frame
        # is legal on the wire and attacker-craftable).
        assert _reassemble({0: b""}) == b""
        assert _reassemble({0: b"abc", 3: b""}) == b"abc"
        assert _reassemble({0: b"ab", 2: b"cd"}) == b"abcd"  # normal case unchanged

    def test_zero_length_crypto_frame_neither_hangs_nor_squats_offset(self) -> None:
        # A QUIC Initial with a zero-length CRYPTO frame must not spin the reassembler
        # and must not occupy offset 0 and block the real ClientHello that follows.
        r = QuicReassembler()
        assert r.add(encrypt_initial(RFC_DCID, crypto_frame(b"", offset=0), pn=0)) is None
        hello = r.add(
            encrypt_initial(RFC_DCID, crypto_frame(handshake_message(b"real.example.com")), pn=1)
        )
        assert hello is not None
        assert hello.sni == "real.example.com"

    def test_coalesced_initial_isolated_by_length_field(self) -> None:
        reasm = QuicReassembler()
        msg = handshake_message(b"coalesced.example.com")
        initial = encrypt_initial(RFC_DCID, crypto_frame(msg))
        # A following Handshake packet (long-header type 2) sharing the datagram:
        # header form + fixed + type 2, v1, empty conn ids, length 3, 3 payload bytes.
        trailing = bytes([0xE0]) + QUIC_V1.to_bytes(4, "big") + b"\x00\x00"
        trailing += encode_varint(3) + b"\xaa\xbb\xcc"
        hello = reasm.add(initial + trailing)
        assert hello is not None
        assert hello.sni == "coalesced.example.com"

    def test_quic_v2_salt(self) -> None:
        reasm = QuicReassembler()
        datagram = encrypt_initial(
            RFC_DCID, crypto_frame(handshake_message(b"v2.example.com")), version=QUIC_V2
        )
        hello = reasm.add(datagram)
        assert hello is not None
        assert hello.sni == "v2.example.com"

    def test_ech_cover_name_flagged_for_quic(self) -> None:
        reasm = QuicReassembler()
        msg = handshake_message(b"cover.example.net", extra_ext=ech_extension())
        hello = reasm.add(encrypt_initial(RFC_DCID, crypto_frame(msg)))
        assert hello is not None
        assert hello.sni == "cover.example.net"
        assert hello.ech is True

    def test_wrong_keys_do_not_yield_hello(self) -> None:
        reasm = QuicReassembler()
        good = encrypt_initial(RFC_DCID, crypto_frame(handshake_message(b"x.example.net")))
        datagram = bytearray(good)
        datagram[-1] ^= 0xFF  # corrupt the AEAD tag
        assert reasm.add(bytes(datagram)) is None

    def test_decrypt_failure_is_counted(self) -> None:
        reasm = QuicReassembler()
        good = encrypt_initial(RFC_DCID, crypto_frame(handshake_message(b"x.example.net")))
        datagram = bytearray(good)
        datagram[-1] ^= 0xFF  # corrupt the AEAD tag
        assert reasm.add(bytes(datagram)) is None
        assert reasm.decrypt_failures == 1


class TestQuicViaProcess:
    def _quic_pkt(self, datagram: bytes, sport: int = 50000, dport: int = 443) -> Packet:
        pkt = (
            Ether()
            / IP(src="192.168.1.50", dst="93.184.216.34")
            / UDP(sport=sport, dport=dport)
            / datagram
        )
        pkt.time = PKT_TIME
        return pkt

    def test_process_emits_quic_tagged_sni_and_flow(self) -> None:
        proc = local_processor("192.168.1.50")
        datagram = encrypt_initial(RFC_DCID, crypto_frame(handshake_message(b"quic.example.com")))
        events = proc.process(self._quic_pkt(datagram))
        sni_events = [e for e in events if isinstance(e, TlsSniEvent)]
        assert len(sni_events) == 1
        assert sni_events[0].sni == "quic.example.com"
        assert sni_events[0].transport == "quic"
        assert sni_events[0].dport == 443
        assert any(isinstance(e, FlowEvent) for e in events)

    def test_quic_initial_on_nonstandard_port_yields_sni(self) -> None:
        # Framing-based recognition: a QUIC Initial is decoded on any port, not
        # only 443 — the port is a hint, not a gate.
        proc = local_processor("192.168.1.50")
        datagram = encrypt_initial(RFC_DCID, crypto_frame(handshake_message(b"quic.example.com")))
        events = proc.process(self._quic_pkt(datagram, dport=51000))
        sni_events = [e for e in events if isinstance(e, TlsSniEvent)]
        assert len(sni_events) == 1
        assert sni_events[0].sni == "quic.example.com"
        assert sni_events[0].transport == "quic"


class TestParseHttpRequest:
    def test_full_request_with_host_and_user_agent(self) -> None:
        payload = (
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: pytest-agent/1.0\r\n\r\n"
        )
        assert parse_http_request(payload) == (
            "GET",
            "/index.html",
            "example.com",
            "pytest-agent/1.0",
        )

    def test_request_with_no_host_header(self) -> None:
        payload = b"GET /path HTTP/1.1\r\nUser-Agent: curl/8.0\r\n\r\n"
        assert parse_http_request(payload) == ("GET", "/path", None, "curl/8.0")

    def test_non_http_payload_returns_none(self) -> None:
        assert parse_http_request(b"\x16\x03\x01\x00\x05hello") is None

    def test_garbage_starting_with_get_but_no_http_version_returns_none(self) -> None:
        assert parse_http_request(b"GET /path SOMETHINGELSE\r\n\r\n") is None


class TestQuestionList:
    def test_drops_resource_records_from_linked_question_chain(self) -> None:
        # Older-scapy shape: qd is a DNSQR whose payload runs into the message's records.
        linked = DNSQR(qname="a.com") / DNSRR(rrname="a.com", type="A", rdata="1.2.3.4")
        assert [type(q).__name__ for q in question_list(linked)] == ["DNSQR"]

    def test_drops_non_questions_from_list_form(self) -> None:
        # Newer-scapy list form: a stray non-DNSQR must still not reach a .qname reader.
        mixed = [DNSQR(qname="a.com"), DNSRR(rrname="a.com", type="A", rdata="1.2.3.4")]
        assert [type(q).__name__ for q in question_list(mixed)] == ["DNSQR"]

    def test_none_is_empty(self) -> None:
        assert question_list(None) == []


class TestMalformedPacketResilience:
    # A passive monitor ingests untrusted traffic; scapy accepts many malformed packets
    # and only raises when a field is read. process() must survive any such packet,
    # account it, and keep going — one bad packet cannot kill the capture loop.
    @staticmethod
    def _pkt(dns_bytes: bytes):
        p = Ether(
            bytes(
                Ether()
                / IP(src="10.0.0.5", dst="10.0.0.1")
                / UDP(sport=40000, dport=53)
                / dns_bytes
            )
        )
        p.time = PKT_TIME
        return p

    def test_malformed_dns_packet_accounted_not_crashed(self) -> None:
        # A real fuzzed port-53 packet that scapy accepts but whose record-field read
        # (here .type) raises; _process would die, process() must catch and account it.
        raw = bytes.fromhex(
            "000081000001000100000000016103636f6d00c6010001016103636f6d37"
            "000100010000001a000401010101"
        )
        proc = PacketProcessor(local_ips=frozenset())
        assert proc.process(self._pkt(raw)) == []
        assert proc.coverage.fate["parse_error"] == 1
        assert proc.summary()["coverage"]["parse_failed"]["packet"] == 1

    def test_fuzzed_malformed_packets_never_crash_the_worker(self) -> None:
        seeds = [
            bytes(DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))),
            bytes(
                DNS(
                    qr=1,
                    qd=DNSQR(qname="a.com"),
                    an=DNSRR(rrname="a.com", type="A", rdata="1.1.1.1"),
                    ancount=1,
                )
            ),
            bytes(DNS(rd=1, qd=DNSQR(qname="x.com"), ar=DNSRROPT(rrname=""))),
        ]
        rng = random.Random(20260708)
        proc = PacketProcessor(local_ips=frozenset())
        for _ in range(3000):
            b = bytearray(rng.choice(seeds))
            if rng.random() < 0.7:
                struct.pack_into(">H", b, rng.choice([4, 6, 8, 10]), rng.randint(0, 5))
            for _ in range(rng.randint(0, 6)):
                b[rng.randrange(len(b))] = rng.randrange(256)
            proc.process(self._pkt(bytes(b)))  # must not raise
        assert proc.coverage.fate["parse_error"] > 0  # the fuzz actually hit the guard

    def test_well_formed_dns_unaffected_by_guard(self) -> None:
        proc = PacketProcessor(local_ips=frozenset())
        events = proc.process(self._pkt(bytes(DNS(rd=1, qd=DNSQR(qname="good.example.com")))))
        assert any(isinstance(e, DnsQueryEvent) and e.qname == "good.example.com" for e in events)
        assert proc.coverage.fate["parse_error"] == 0


class TestNonDnsTrafficOnDnsPorts:
    # scapy binds a DNS layer to UDP 53/5353 by port alone, so non-DNS noise that
    # squats there (BitTorrent DHT, QUIC, scans) gets force-decoded into a bogus DNS
    # layer with a garbage qname/qtype. Detection must gate on shape, not the port
    # binding, so this never surfaces as a dns_query. Re-dissect via Ether(bytes(...))
    # so the port bindings actually fire, as they do on a live capture.
    @staticmethod
    def _udp(port: int, payload: bytes) -> Packet:
        p = Ether(
            bytes(
                Ether()
                / IP(src="115.55.224.86", dst="192.168.11.32")
                / UDP(sport=port, dport=port)
                / payload
            )
        )
        p.time = PKT_TIME
        return p

    # A BitTorrent DHT find_node datagram (bencode) like the ones in the report.
    _DHT = (
        b"d1:ad2:id20:"
        + bytes(range(20))
        + b"6:target20:"
        + bytes(range(20, 40))
        + b"e1:q9:find_node1:t4:abcd1:y1:qe"
    )

    @pytest.mark.parametrize("port", [53, 5353])
    def test_dht_noise_is_not_reported_as_dns(self, port: int) -> None:
        proc = PacketProcessor(local_ips=frozenset())
        events = proc.process(self._udp(port, self._DHT))
        assert not [e for e in events if isinstance(e, DnsQueryEvent)]
        assert proc.coverage.fate["parse_error"] == 0  # rejected by shape, not a crash

    def test_real_mdns_on_5353_still_parses(self) -> None:
        proc = PacketProcessor(local_ips=frozenset())
        events = proc.process(
            self._udp(5353, bytes(DNS(rd=0, qd=DNSQR(qname="_airplay._tcp.local", qtype="PTR"))))
        )
        assert any(
            isinstance(e, DnsQueryEvent) and e.qname == "_airplay._tcp.local" for e in events
        )


class TestDnsEvents:
    def test_dns_query_event_fields(self, processor: PacketProcessor) -> None:
        pkt = (
            Ether()
            / IP(src="192.168.1.50", dst="8.8.8.8")
            / UDP(sport=54321, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
        )
        pkt.time = PKT_TIME
        events = processor.process(pkt)
        query_events = [e for e in events if isinstance(e, DnsQueryEvent)]
        assert len(query_events) == 1
        event = query_events[0]
        assert event.ts == EXPECTED_ISO
        assert event.src == "192.168.1.50"
        assert event.dst == "8.8.8.8"
        assert event.transport == "udp"
        assert event.qname == "example.com"
        assert event.qtype == "A"

    def test_dns_query_with_linked_resource_records_does_not_crash(
        self, processor: PacketProcessor
    ) -> None:
        # Regression: older scapy links a DNS message's sections into one payload chain
        # (qd -> an/ns/ar), so dns.qd is a DNSQR whose payload runs into resource records.
        # rr_list walked that chain across the question/RR boundary and _dns_events then
        # read .qname off a DNSRR, killing the capture worker with AttributeError. The
        # question walk must stop at the questions.
        class LinkedDNS:  # the shape older scapy hands us; DNS() on 2.7 flattens qd to a list
            qr = 0
            qd = DNSQR(qname="example.com", qtype="A") / DNSRR(
                rrname="example.com", type="A", ttl=300, rdata="93.184.216.34"
            )
            an = ns = ar = None

        net = IP(src="192.168.1.50", dst="8.8.8.8")
        events = processor._dns_events(EXPECTED_ISO, net, LinkedDNS(), "udp")
        query_events = [e for e in events if isinstance(e, DnsQueryEvent)]
        assert len(query_events) == 1
        assert query_events[0].qname == "example.com"
        assert query_events[0].qtype == "A"

    def test_dns_answer_a_record_populates_ip_to_name(self, processor: PacketProcessor) -> None:
        pkt = (
            Ether()
            / IP(src="8.8.8.8", dst="192.168.1.50")
            / UDP(sport=53, dport=54321)
            / DNS(
                qr=1,
                qd=DNSQR(qname="example.com"),
                an=DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.34"),
            )
        )
        pkt.time = PKT_TIME
        events = processor.process(pkt)
        answer_events = [e for e in events if isinstance(e, DnsAnswerEvent)]
        assert len(answer_events) == 1
        event = answer_events[0]
        assert event.ts == EXPECTED_ISO
        assert event.resolver == "8.8.8.8"
        assert event.qname == "example.com"
        assert event.rtype == "A"
        assert event.value == "93.184.216.34"
        assert event.ttl == 300
        assert processor.names.lookup("93.184.216.34") == "example.com"

    def test_dns_answer_enriches_subsequent_flow_with_hostname(self) -> None:
        processor = local_processor("192.168.1.50")
        answer = (
            Ether()
            / IP(src="8.8.8.8", dst="192.168.1.50")
            / UDP(sport=53, dport=54321)
            / DNS(
                qr=1,
                qd=DNSQR(qname="example.com"),
                an=DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.34"),
            )
        )
        answer.time = PKT_TIME
        processor.process(answer)

        syn = make_syn("192.168.1.50", "93.184.216.34", 44000, 443)
        events = processor.process(syn)
        assert len(events) == 1
        flow = events[0]
        assert isinstance(flow, FlowEvent)
        assert flow.remote_ip == "93.184.216.34"
        assert flow.hostname == "example.com"

    def test_dns_answer_cname_strips_trailing_dot(self, processor: PacketProcessor) -> None:
        pkt = (
            Ether()
            / IP(src="8.8.8.8", dst="192.168.1.50")
            / UDP(sport=53, dport=54321)
            / DNS(
                qr=1,
                qd=DNSQR(qname="www.example.com"),
                an=DNSRR(rrname="www.example.com", type="CNAME", ttl=60, rdata="example.com"),
            )
        )
        pkt.time = PKT_TIME
        events = processor.process(pkt)
        answer_events = [e for e in events if isinstance(e, DnsAnswerEvent)]
        assert len(answer_events) == 1
        event = answer_events[0]
        assert event.rtype == "CNAME"
        assert event.value == "example.com"
        assert not event.value.endswith(".")


class TestTlsSniAndHttpViaProcess:
    def test_process_emits_tls_sni_event(self, processor: PacketProcessor) -> None:
        extensions = padding_extension(6) + sni_extension(b"example.com")
        payload = build_client_hello(extensions=extensions)
        pkt = (
            Ether()
            / IP(src="192.168.1.50", dst="93.184.216.34")
            / TCP(sport=51000, dport=443, flags="PA")
            / payload
        )
        pkt.time = PKT_TIME
        events = processor.process(pkt)
        sni_events = [e for e in events if isinstance(e, TlsSniEvent)]
        assert len(sni_events) == 1
        assert sni_events[0].sni == "example.com"
        assert sni_events[0].dport == 443
        assert sni_events[0].ts == EXPECTED_ISO

    def test_process_emits_http_event(self, processor: PacketProcessor) -> None:
        payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        pkt = (
            Ether()
            / IP(src="192.168.1.50", dst="93.184.216.34")
            / TCP(sport=51000, dport=80, flags="PA")
            / payload
        )
        pkt.time = PKT_TIME
        events = processor.process(pkt)
        http_events = [e for e in events if isinstance(e, HttpEvent)]
        assert len(http_events) == 1
        assert http_events[0].host == "example.com"
        assert http_events[0].method == "GET"
        assert http_events[0].path == "/index.html"


class TestFlowDirection:
    def test_outbound_flow_from_local_ip(self) -> None:
        processor = local_processor("192.168.1.50")
        pkt = make_syn("192.168.1.50", "93.184.216.34", 51000, 443)
        flow = single_flow(processor.process(pkt))
        assert flow.direction == "outbound"
        assert flow.local_ip == "192.168.1.50"
        assert flow.local_port == 51000
        assert flow.remote_ip == "93.184.216.34"
        assert flow.remote_port == 443

    def test_inbound_flow_to_local_ip(self) -> None:
        processor = local_processor("192.168.1.50")
        pkt = make_syn("93.184.216.34", "192.168.1.50", 443, 54321)
        flow = single_flow(processor.process(pkt))
        assert flow.direction == "inbound"
        assert flow.local_ip == "192.168.1.50"
        assert flow.local_port == 54321
        assert flow.remote_ip == "93.184.216.34"
        assert flow.remote_port == 443


class TestFlowDedup:
    def test_same_five_tuple_twice_creates_one_flow_event(self) -> None:
        processor = local_processor("192.168.1.50")
        first = make_syn("192.168.1.50", "93.184.216.34", 51000, 443)
        second = make_syn("192.168.1.50", "93.184.216.34", 51000, 443)
        first_events = processor.process(first)
        second_events = processor.process(second)
        assert len(first_events) == 1
        assert len(second_events) == 0

    def test_repeated_flow_does_not_reemit_after_cap_crossed(self) -> None:
        processor = PacketProcessor(local_ips=frozenset({"192.168.1.50"}), flow_cap=5)
        hot = make_syn("192.168.1.50", "93.184.216.34", 51000, 443)
        assert len(processor.process(hot)) == 1
        for port in range(1000, 1020):  # drive well past the cap
            processor.process(make_syn("192.168.1.50", "93.184.216.34", port, 443))
            assert processor.process(make_syn("192.168.1.50", "93.184.216.34", 51000, 443)) == []

    def test_flow_table_size_stays_at_cap(self) -> None:
        processor = PacketProcessor(local_ips=frozenset({"192.168.1.50"}), flow_cap=5)
        for port in range(1000, 1100):
            processor.process(make_syn("192.168.1.50", "93.184.216.34", port, 443))
        assert len(processor.seen_flows) == 5

    def test_transit_connection_deduped_across_directions(self) -> None:
        # No local end to normalize against: the forward and reverse legs of one
        # transit connection must still dedup to a single flow.
        # Two internet hosts (neither local by address class): a mirrored upstream
        # connection whose forward and reverse legs must dedup to one 'transit' flow.
        proc = PacketProcessor(local_ips=frozenset())
        fwd = Ether() / IP(src="8.8.8.8", dst="1.1.1.1") / TCP(sport=1111, dport=443, flags="S")
        rev = Ether() / IP(src="1.1.1.1", dst="8.8.8.8") / TCP(sport=443, dport=1111, flags="SA")
        fwd.time = PKT_TIME
        rev.time = PKT_TIME
        flows = [e for e in (*proc.process(fwd), *proc.process(rev)) if isinstance(e, FlowEvent)]
        assert len(flows) == 1
        assert flows[0].direction == "transit"


class TestLruSet:
    def test_add_returns_true_only_first_time(self) -> None:
        s: LruSet[str] = LruSet(cap=4)
        assert s.add("a") is True
        assert s.add("a") is False

    def test_evicts_least_recent_beyond_cap(self) -> None:
        s: LruSet[str] = LruSet(cap=3)
        for k in ("a", "b", "c", "d"):
            s.add(k)
        assert s.add("a") is True  # oldest was evicted
        assert len(s) == 3

    def test_hit_refreshes_recency(self) -> None:
        s: LruSet[str] = LruSet(cap=3)
        for k in ("a", "b", "c"):
            s.add(k)
        s.add("a")  # refresh: b is now least recent
        s.add("d")  # evicts b
        assert s.add("a") is False
        assert s.add("b") is True

    def test_eviction_is_counted(self) -> None:
        s: LruSet[str] = LruSet(cap=2)
        for k in ("a", "b", "c", "d"):
            s.add(k)
        assert s.evicted == 2


class TestNameLedger:
    def test_observe_then_lookup_returns_name(self) -> None:
        ledger = NameLedger(cap=8)
        ledger.observe("93.184.216.34", "example.com")
        assert ledger.lookup("93.184.216.34") == "example.com"

    def test_lookup_miss_returns_none(self) -> None:
        assert NameLedger(cap=8).lookup("1.2.3.4") is None

    def test_last_observation_wins(self) -> None:
        # A shared/CDN IP that later serves a different site must re-attribute to the
        # most recent name (temporal locality), not stay pinned to the first.
        ledger = NameLedger(cap=8)
        ledger.observe("1.2.3.4", "first.example.com")
        ledger.observe("1.2.3.4", "second.example.com")
        assert ledger.lookup("1.2.3.4") == "second.example.com"

    def test_reobserving_ip_does_not_grow_or_evict(self) -> None:
        ledger = NameLedger(cap=8)
        ledger.observe("1.2.3.4", "a.example.com")
        ledger.observe("1.2.3.4", "b.example.com")
        assert len(ledger) == 1
        assert ledger.evicted == 0

    def test_reobserve_at_capacity_does_not_evict(self) -> None:
        ledger = NameLedger(cap=2)
        ledger.observe("1.1.1.1", "a")
        ledger.observe("2.2.2.2", "b")
        ledger.observe("1.1.1.1", "a2")  # re-observe while full: no drift, no eviction
        assert ledger.evicted == 0
        assert len(ledger) == 2
        assert ledger.lookup("1.1.1.1") == "a2"
        assert ledger.lookup("2.2.2.2") == "b"

    def test_placeholder_never_clobbers_a_real_name(self) -> None:
        ledger = NameLedger(cap=8)
        ledger.observe("2001:db8::53", "dns.example.com")  # real name learned first
        ledger.observe_if_absent("2001:db8::53", RA_RDNSS_NAME)
        assert ledger.lookup("2001:db8::53") == "dns.example.com"

    def test_placeholder_fills_gap_then_yields_to_real_name(self) -> None:
        ledger = NameLedger(cap=8)
        ledger.observe_if_absent("2001:db8::53", RA_RDNSS_NAME)
        assert ledger.lookup("2001:db8::53") == RA_RDNSS_NAME  # gap filled
        ledger.observe("2001:db8::53", "dns.example.com")  # real name later wins
        assert ledger.lookup("2001:db8::53") == "dns.example.com"

    def test_flow_hostname_reflects_latest_name_for_reused_ip(self) -> None:
        # End to end: a CDN edge resolved first for imgs, then for login; a later flow
        # to that edge must name the site the client most recently asked for.
        proc = local_processor("192.168.1.50")
        proc.process(
            dns_response(
                DNSQR(qname="imgs.example.com"),
                DNSRR(rrname="imgs.example.com", type="A", ttl=60, rdata="93.184.216.34"),
            )
        )
        proc.process(
            dns_response(
                DNSQR(qname="login.bank.com"),
                DNSRR(rrname="login.bank.com", type="A", ttl=60, rdata="93.184.216.34"),
            )
        )
        flow = single_flow(proc.process(make_syn("192.168.1.50", "93.184.216.34", 51000, 443)))
        assert flow.hostname == "login.bank.com"

    def test_cap_enforced_under_distinct_flood(self) -> None:
        ledger = NameLedger(cap=10)
        for i in range(100_000):
            ledger.observe(f"10.0.{i >> 8 & 255}.{i & 255}", f"h{i}.example.com")
        assert len(ledger) == 10

    def test_lookup_refreshes_recency_against_eviction(self) -> None:
        ledger = NameLedger(cap=3)
        ledger.observe("1.1.1.1", "one.example.com")
        ledger.observe("2.2.2.2", "two.example.com")
        ledger.observe("3.3.3.3", "three.example.com")
        ledger.lookup("1.1.1.1")
        ledger.observe("4.4.4.4", "four.example.com")  # evicts 2.2.2.2, not 1.1.1.1
        assert ledger.lookup("1.1.1.1") == "one.example.com"
        assert ledger.lookup("2.2.2.2") is None

    def test_eviction_is_counted(self) -> None:
        ledger = NameLedger(cap=2)
        for i in range(5):
            ledger.observe(f"10.0.0.{i}", f"h{i}.example.com")
        assert ledger.evicted == 3


class TestBoundedCounter:
    def test_counts_and_most_common(self) -> None:
        c = BoundedCounter(cap=100)
        for _ in range(3):
            c.add("a")
        c.add("b")
        assert c.most_common(2) == [("a", 3), ("b", 1)]

    def test_len_bounded_under_distinct_flood(self) -> None:
        c = BoundedCounter(cap=50)
        for i in range(10_000):
            c.add(f"key{i}")
        assert len(c) <= 50

    def test_hot_keys_survive_flood_with_exact_counts(self) -> None:
        c = BoundedCounter(cap=50)
        for _ in range(500):
            c.add("hot.example.com")
        for i in range(10_000):
            c.add(f"noise{i}")
        assert dict(c.most_common(1)) == {"hot.example.com": 500}

    def test_distinct_estimate_counts_all_keys_seen(self) -> None:
        c = BoundedCounter(cap=50)
        for i in range(1000):
            c.add(f"key{i}")
        assert c.distinct_estimate == 1000

    def test_flush_drops_are_counted(self) -> None:
        c = BoundedCounter(cap=10, keep=5)
        for i in range(11):
            c.add(f"k{i}")
        assert c.flushed == 6


class TestBoundedProcessorMemory:
    def test_summary_top30_correct_under_bounded_counters(self) -> None:
        proc = PacketProcessor(local_ips=frozenset(), counter_cap=64)
        hot = (
            Ether()
            / IP(src="192.168.1.50", dst="8.8.8.8")
            / UDP(sport=54321, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="hot.example.com", qtype="A"))
        )
        hot.time = PKT_TIME
        for _ in range(40):
            proc.process(hot)
        for i in range(200):
            pkt = (
                Ether()
                / IP(src="192.168.1.50", dst="8.8.8.8")
                / UDP(sport=54321, dport=53)
                / DNS(rd=1, qd=DNSQR(qname=f"noise{i}.example.com", qtype="A"))
            )
            pkt.time = PKT_TIME
            proc.process(pkt)
        summary = proc.summary()
        assert summary["top_dns_names"]["hot.example.com"] == 40
        assert summary["unique_dns_names"] == 201

    def test_name_ledger_wired_into_processor(self) -> None:
        proc = PacketProcessor(local_ips=frozenset(), name_cap=4)
        for i in range(20):
            pkt = (
                Ether()
                / IP(src="8.8.8.8", dst="192.168.1.50")
                / UDP(sport=53, dport=54321)
                / DNS(
                    qr=1,
                    qd=DNSQR(qname=f"h{i}.example.com"),
                    an=DNSRR(rrname=f"h{i}.example.com", type="A", ttl=60, rdata=f"10.0.0.{i}"),
                )
            )
            pkt.time = PKT_TIME
            proc.process(pkt)
        assert len(proc.names) == 4


class TestLoopbackDedup:
    def test_identical_lo_frame_within_window_is_dropped(self) -> None:
        processor = local_processor("127.0.0.1")
        first = make_syn("127.0.0.1", "127.0.0.53", 51000, 53)
        second = make_syn("127.0.0.1", "127.0.0.53", 51000, 53)
        first.sniffed_on = "lo"
        second.sniffed_on = "lo"
        second.time = PKT_TIME + 0.001
        assert len(processor.process(first)) == 1
        assert processor.process(second) == []

    def test_identical_frame_on_other_iface_is_not_deduped(
        self, processor: PacketProcessor
    ) -> None:
        hello = build_client_hello(extensions=sni_extension(b"example.com"))

        def make_hello() -> Packet:
            pkt = (
                Ether()
                / IP(src="192.168.1.50", dst="8.8.8.8")
                / TCP(sport=51000, dport=443, flags="PA")
                / hello
            )
            pkt.time = PKT_TIME
            pkt.sniffed_on = "enp1s0"
            return pkt

        # First sighting of the 5-tuple also emits a pre-existing flow; the point
        # is that the tls_sni is re-emitted (not deduped) on a non-loopback iface.
        first = [e.kind for e in processor.process(make_hello())]
        second = [e.kind for e in processor.process(make_hello())]
        assert first.count("tls_sni") == 1
        assert second.count("tls_sni") == 1


class TestFlowScope:
    def test_scope_lan_for_private_target(self) -> None:
        processor = local_processor("192.168.1.50")
        pkt = make_syn("192.168.1.50", "192.168.1.5", 51000, 443)
        assert single_flow(processor.process(pkt)).scope == "lan"

    def test_scope_internet_for_public_target(self) -> None:
        processor = local_processor("192.168.1.50")
        pkt = make_syn("192.168.1.50", "8.8.8.8", 51000, 443)
        assert single_flow(processor.process(pkt)).scope == "internet"

    def test_scope_multicast_for_ipv4_multicast_target(self, processor: PacketProcessor) -> None:
        assert remote_scope("239.255.255.250") == "multicast"

    def test_scope_multicast_for_ipv6_multicast_target(self, processor: PacketProcessor) -> None:
        assert remote_scope("ff12::8384") == "multicast"

    def test_scope_distinguishes_cgnat_loopback_linklocal(self) -> None:
        assert remote_scope("100.64.1.1") == "cgnat"  # carrier NAT, was mislabelled 'lan'
        assert remote_scope("127.0.0.1") == "loopback"
        assert remote_scope("169.254.4.4") == "linklocal"
        assert remote_scope("fe80::1") == "linklocal"
        assert remote_scope("10.0.0.1") == "lan"  # RFC1918 stays 'lan'


class TestAddressClassFlow:
    # Direction anchors on address class (private/link-local/loopback = local) OR this
    # host's own IPs, so a mirror/SPAN deployment classifies LAN<->internet correctly
    # and LAN-internal traffic is 'local', not double-emitted or mislabelled 'transit'.
    def test_both_local_loopback_dedups_to_one_local_flow(self) -> None:
        proc = local_processor("127.0.0.1")
        req = (
            Ether() / IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=54321, dport=5000, flags="S")
        )
        rep = (
            Ether()
            / IP(src="127.0.0.1", dst="127.0.0.1")
            / TCP(sport=5000, dport=54321, flags="SA")
        )
        req.time = PKT_TIME
        rep.time = PKT_TIME
        fr = [e for e in proc.process(req) if isinstance(e, FlowEvent)]
        fp = [e for e in proc.process(rep) if isinstance(e, FlowEvent)]
        assert len(fr) == 1  # was two 'outbound' events for one connection
        assert fr[0].direction == "local"
        assert fr[0].scope == "loopback"
        assert fp == []  # the reply leg dedups to the same flow

    def test_lan_to_lan_is_local(self) -> None:
        proc = local_processor("192.168.1.50")
        flow = single_flow(proc.process(make_syn("192.168.1.10", "192.168.1.20", 40000, 445)))
        assert flow.direction == "local"
        assert flow.scope == "lan"

    def test_received_multicast_is_local_not_transit(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = Ether() / IP(src="192.168.1.9", dst="224.0.0.251") / UDP(sport=5353, dport=5353)
        pkt.time = PKT_TIME
        flow = single_flow([e for e in proc.process(pkt) if isinstance(e, FlowEvent)])
        assert flow.direction == "local"
        assert flow.scope == "multicast"

    def test_private_peer_egress_to_internet_is_outbound(self) -> None:
        # A LAN host that is not us, egressing to the internet (mirror view): outbound.
        proc = local_processor("192.168.1.50")
        flow = single_flow(proc.process(make_syn("192.168.1.77", "8.8.8.8", 40000, 443)))
        assert flow.direction == "outbound"
        assert flow.remote_ip == "8.8.8.8"
        assert flow.scope == "internet"

    def test_self_connect_on_global_ip_not_counted_as_internet_host(self) -> None:
        # A host with a globally-routable own IP connecting to itself is 'local'; it
        # must not credit the host's own address as a top internet host.
        proc = local_processor("1.2.3.4")
        proc.process(make_syn("1.2.3.4", "1.2.3.4", 51000, 443))
        summary = proc.summary()
        assert summary["top_internet_hosts"] == {}
        assert summary["unique_internet_hosts"] == 0

    def test_own_global_ip_egress_still_outbound(self) -> None:
        # A globally-addressed host (public IP / un-NAT'd IPv6) whose own address is
        # global (both ends global) would be 'transit' by address class alone; the
        # local_ips anchor must still make its own egress 'outbound'.
        proc = local_processor("1.2.3.4")
        flow = single_flow(proc.process(make_syn("1.2.3.4", "8.8.8.8", 51000, 443)))
        assert flow.direction == "outbound"


class TestServiceGuess:
    def test_tcp_443_is_https(self) -> None:
        processor = local_processor("192.168.1.50")
        pkt = make_syn("192.168.1.50", "93.184.216.34", 51000, 443)
        assert single_flow(processor.process(pkt)).service == "https"

    def test_udp_443_is_quic(self) -> None:
        processor = local_processor("192.168.1.50")
        pkt = Ether() / IP(src="192.168.1.50", dst="93.184.216.34") / UDP(sport=51000, dport=443)
        pkt.time = PKT_TIME
        assert single_flow(processor.process(pkt)).service == "quic"

    def test_unknown_port_falls_back_to_proto_slash_port(self) -> None:
        processor = local_processor("192.168.1.50")
        pkt = make_syn("192.168.1.50", "93.184.216.34", 51000, 54321)
        assert single_flow(processor.process(pkt)).service == "tcp/54321"


class TestTcpFlagCombinations:
    def test_pure_syn_is_observed_birth(self) -> None:
        processor = local_processor("192.168.1.50")
        pkt = make_syn("192.168.1.50", "93.184.216.34", 51000, 443, flags="S")
        flow = single_flow(processor.process(pkt))
        assert flow.birth == "observed"

    def test_syn_ack_without_prior_syn_is_pre_existing(self) -> None:
        # Joined mid-handshake: the client SYN was never on the wire we saw.
        processor = local_processor("192.168.1.50")
        pkt = make_syn("192.168.1.50", "93.184.216.34", 51000, 443, flags="SA")
        flow = single_flow(processor.process(pkt))
        assert flow.birth == "pre-existing"

    def test_mid_stream_ack_inventories_pre_existing_connection(self) -> None:
        # The durable channels an operator most wants: a connection already open
        # when capture began, seen only as data/ACK, must still be inventoried.
        processor = local_processor("192.168.1.50")
        pkt = make_syn("192.168.1.50", "93.184.216.34", 51000, 443, flags="A")
        flow = single_flow(processor.process(pkt))
        assert flow.birth == "pre-existing"
        assert flow.remote_ip == "93.184.216.34"
        assert flow.service == "https"


class TestIpv6:
    def test_ipv6_syn_produces_flow_event(self) -> None:
        processor = local_processor("2001:db8::1")
        pkt = IPv6(src="2001:db8::1", dst="2606:4700:4700::1111") / TCP(
            sport=51000, dport=443, flags="S"
        )
        pkt.time = PKT_TIME
        flow = single_flow(processor.process(pkt))
        assert flow.local_ip == "2001:db8::1"
        assert flow.remote_ip == "2606:4700:4700::1111"
        assert flow.direction == "outbound"
        assert flow.ts == EXPECTED_ISO


class TestLogFilePermissions:
    def test_writer_creates_owner_only_run_dir(self, tmp_path: Path) -> None:
        out = tmp_path / "run-x"
        JsonlWriter(out)
        assert out.stat().st_mode & 0o777 == 0o700

    def test_written_log_file_is_owner_only(self, tmp_path: Path) -> None:
        out = tmp_path / "run-x"
        writer = JsonlWriter(out)
        writer.write(
            DnsQueryEvent(ts=EXPECTED_ISO, src="a", dst="b", transport="udp", qname="x", qtype="A")
        )
        writer.close()
        mode = (out / "dns.jsonl").stat().st_mode
        assert mode & 0o077 == 0, oct(mode)

    def test_summary_written_owner_only(self, tmp_path: Path) -> None:
        out = tmp_path / "run-x"
        writer = JsonlWriter(out)
        writer.write_summary({"packets": 0})
        writer.close()
        assert (out / "summary.json").stat().st_mode & 0o077 == 0

    def test_refuses_preexisting_run_dir(self, tmp_path: Path) -> None:
        out = tmp_path / "run-x"
        out.mkdir()
        with pytest.raises(FileExistsError):
            JsonlWriter(out)

    def test_refuses_symlinked_run_dir_without_touching_target(self, tmp_path: Path) -> None:
        victim = tmp_path / "victim"
        victim.mkdir(mode=0o755)
        link = tmp_path / "run-x"
        link.symlink_to(victim, target_is_directory=True)
        with pytest.raises(FileExistsError):
            JsonlWriter(link)
        assert victim.stat().st_mode & 0o077 != 0

    def test_summary_refuses_symlinked_target(self, tmp_path: Path) -> None:
        out = tmp_path / "run-x"
        writer = JsonlWriter(out)
        victim = tmp_path / "victim.txt"
        victim.write_text("keep")
        (out / "summary.json").symlink_to(victim)
        with pytest.raises(FileExistsError):
            writer.write_summary({"packets": 1})
        assert victim.read_text() == "keep"

    def test_event_write_still_refuses_symlinked_target(self, tmp_path: Path) -> None:
        # The disk-full degrade path must not swallow the CWE-59 symlink refusal.
        out = tmp_path / "run-x"
        writer = JsonlWriter(out)
        victim = tmp_path / "victim.txt"
        victim.write_text("keep")
        (out / "dns.jsonl").symlink_to(victim)
        ev = DnsQueryEvent(ts="t", src="a", dst="b", transport="udp", qname="x", qtype="A")
        with pytest.raises(FileExistsError):
            writer.write(ev)
        assert victim.read_text() == "keep"
        assert writer.write_failures == 0  # a security refusal is not a disk-full drop


class TestHttpQueryRedaction:
    def _http_pkt(self, target: bytes) -> Packet:
        payload = b"GET " + target + b" HTTP/1.1\r\nHost: example.com\r\n\r\n"
        pkt = (
            Ether()
            / IP(src="192.168.1.50", dst="93.184.216.34")
            / TCP(sport=51000, dport=80, flags="PA")
            / payload
        )
        pkt.time = PKT_TIME
        return pkt

    def test_query_string_redacted_by_default(self, processor: PacketProcessor) -> None:
        events = processor.process(self._http_pkt(b"/reset?token=abc123"))
        http = next(e for e in events if isinstance(e, HttpEvent))
        assert http.path == "/reset?<redacted>"

    def test_query_retained_when_disabled(self) -> None:
        proc = PacketProcessor(local_ips=frozenset(), redact_query=False)
        events = proc.process(self._http_pkt(b"/reset?token=abc123"))
        http = next(e for e in events if isinstance(e, HttpEvent))
        assert http.path == "/reset?token=abc123"

    def test_path_without_query_unchanged(self, processor: PacketProcessor) -> None:
        events = processor.process(self._http_pkt(b"/index.html"))
        http = next(e for e in events if isinstance(e, HttpEvent))
        assert http.path == "/index.html"


class TestTimestampFormatting:
    def test_flow_event_ts_is_iso8601_utc_with_milliseconds(self) -> None:
        processor = local_processor("192.168.1.50")
        pkt = make_syn("192.168.1.50", "93.184.216.34", 51000, 443)
        events = processor.process(pkt)
        assert events[0].ts == EXPECTED_ISO


SOL_PACKET, PACKET_STATISTICS = 263, 6


class FakePacketSocket:
    # Stands in for a scapy SuperSocket: `.ins` is the AF_PACKET socket that
    # answers getsockopt(SOL_PACKET, PACKET_STATISTICS) with reset-on-read
    # semantics, i.e. each poll returns only the drops since the last poll.
    def __init__(
        self,
        drop_deltas: list[int] | None = None,
        fail: bool = False,
        packet_deltas: list[int] | None = None,
    ) -> None:
        self.ins = self
        self._deltas = list(drop_deltas or [])
        self._packet_deltas = list(packet_deltas) if packet_deltas is not None else None
        self._fail = fail

    def getsockopt(self, level: int, optname: int, buflen: int) -> bytes:
        assert (level, optname, buflen) == (SOL_PACKET, PACKET_STATISTICS, 8)
        if self._fail:
            raise OSError("not supported")
        dropped = self._deltas.pop(0) if self._deltas else 0
        # The kernel folds tp_drops into tp_packets; mirror that unless the test
        # pins tp_packets explicitly.
        total = self._packet_deltas.pop(0) if self._packet_deltas else dropped
        return struct.pack("2I", total, dropped)


class TestLiveCaptureKernelDrops:
    def test_stats_before_start_reports_kernel_drops_unavailable(self) -> None:
        capture = LiveCapture(ifaces=["eth0"], bpf=None)
        assert capture.stats().kernel_dropped is None

    def test_kernel_drops_accumulate_reset_on_read_deltas(self) -> None:
        capture = LiveCapture(ifaces=["eth0"], bpf=None)
        capture._sockets = [FakePacketSocket(drop_deltas=[3, 4])]
        assert capture.stats().kernel_dropped == 3
        assert capture.stats().kernel_dropped == 7

    def test_kernel_drops_sum_across_interfaces(self) -> None:
        capture = LiveCapture(ifaces=["eth0", "wlan0"], bpf=None)
        capture._sockets = [FakePacketSocket([2]), FakePacketSocket([5])]
        assert capture.stats().kernel_dropped == 7

    def test_kernel_drops_unavailable_when_getsockopt_fails(self) -> None:
        capture = LiveCapture(ifaces=["eth0"], bpf=None)
        capture._sockets = [FakePacketSocket(fail=True)]
        assert capture.stats().kernel_dropped is None

    def test_synthetic_overload_reports_nonzero_kernel_drops(self) -> None:
        capture = LiveCapture(ifaces=["eth0"], bpf=None)
        capture._sockets = [FakePacketSocket(drop_deltas=[10_000])]
        assert capture.stats().kernel_dropped == 10_000

    def test_stats_survive_socket_without_ins(self) -> None:
        capture = LiveCapture(ifaces=["eth0"], bpf=None)
        capture._sockets = [object()]  # libpcap-backed SuperSockets expose no .ins
        assert capture.stats().kernel_dropped is None

    def test_kernel_delivered_excludes_drops_folded_into_tp_packets(self) -> None:
        # getsockopt returns tp_packets already inclusive of drops, so the count
        # actually handed to userspace is tp_packets - tp_drops.
        capture = LiveCapture(ifaces=["eth0"], bpf=None)
        capture._sockets = [FakePacketSocket(drop_deltas=[2], packet_deltas=[10])]
        st = capture.stats()
        assert st.kernel_dropped == 2
        assert st.kernel_delivered == 8


class FakeListenSocket:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class TestLiveCaptureSocketCleanup:
    async def test_failed_iface_open_closes_already_opened_sockets(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        opened: list[FakeListenSocket] = []

        def fake_l2listen(iface: str, filter: str | None, promisc: bool) -> FakeListenSocket:
            if iface == "bad0":
                raise OSError("no such device")
            sock = FakeListenSocket()
            opened.append(sock)
            return sock

        monkeypatch.setattr(conf, "L2listen", fake_l2listen)
        capture = LiveCapture(ifaces=["eth0", "bad0"], bpf=None)
        with pytest.raises(OSError):
            await anext(capture.packets())
        assert len(opened) == 1
        assert all(sock.closed for sock in opened)


def write_replay_pcap(path: Path) -> None:
    query = (
        Ether()
        / IP(src="192.168.1.50", dst="8.8.8.8")
        / UDP(sport=54321, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    )
    syn = (
        Ether()
        / IP(src="192.168.1.50", dst="93.184.216.34")
        / TCP(sport=51000, dport=443, flags="S")
    )
    hello = (
        Ether()
        / IP(src="192.168.1.50", dst="93.184.216.34")
        / TCP(sport=51000, dport=443, flags="PA")
        / build_client_hello(extensions=sni_extension(b"example.com"))
    )
    for pkt in (query, syn, hello):
        pkt.time = PKT_TIME
    wrpcap(str(path), [query, syn, hello])


class TestReplayCapture:
    async def test_replays_packets_with_preserved_timestamps(self, tmp_path: Path) -> None:
        pcap = tmp_path / "replay.pcap"
        write_replay_pcap(pcap)
        capture = ReplayCapture(pcap)
        packets = [pkt async for pkt in capture.packets()]
        assert len(packets) == 3
        assert float(packets[0].time) == pytest.approx(PKT_TIME)

    async def test_replay_drives_processor_deterministically(self, tmp_path: Path) -> None:
        pcap = tmp_path / "replay.pcap"
        write_replay_pcap(pcap)
        proc = PacketProcessor(local_ips=frozenset({"192.168.1.50"}))
        capture = ReplayCapture(pcap)
        kinds = [e.kind async for pkt in capture.packets() for e in proc.process(pkt)]
        # the DNS query itself is a UDP flow, then the SYN, then the ClientHello
        assert kinds == ["dns_query", "flow", "flow", "tls_sni"]

    def test_replay_stats_report_kernel_drops_unavailable(self, tmp_path: Path) -> None:
        pcap = tmp_path / "replay.pcap"
        write_replay_pcap(pcap)
        stats = ReplayCapture(pcap).stats()
        assert stats.kernel_dropped is None
        assert stats.userspace_dropped == 0


class TestAlpnFromClientHello:
    def test_alpn_parsed_from_clienthello(self) -> None:
        ext = alpn_extension(b"h2", b"http/1.1") + sni_extension(b"example.com")
        hello = parse_client_hello(build_client_hello(extensions=ext))
        assert hello is not None
        assert hello.alpn == ["h2", "http/1.1"]

    def test_no_alpn_yields_empty_list(self) -> None:
        hello = parse_client_hello(build_client_hello(extensions=sni_extension(b"example.com")))
        assert hello is not None
        assert hello.alpn == []

    def test_process_attaches_alpn_to_tls_event(self) -> None:
        proc = local_processor("192.168.1.50")
        ext = alpn_extension(b"h2") + sni_extension(b"example.com")
        events = proc.process(tcp_segment(build_client_hello(extensions=ext), flags="PA"))
        sni = next(e for e in events if isinstance(e, TlsSniEvent))
        assert sni.alpn == ["h2"]

    def test_alpn_survives_ech_outer_hello(self) -> None:
        ext = alpn_extension(b"h3") + sni_extension(b"cover.example.net") + ech_extension()
        hello = parse_client_hello(build_client_hello(extensions=ext))
        assert hello is not None
        assert hello.ech is True
        assert hello.alpn == ["h3"]

    def test_quic_clienthello_alpn_extracted(self) -> None:
        reasm = QuicReassembler()
        msg = handshake_message(b"quic.example.com", extra_ext=alpn_extension(b"h3"))
        hello = reasm.add(encrypt_initial(RFC_DCID, crypto_frame(msg)))
        assert hello is not None
        assert hello.alpn == ["h3"]

    def test_malformed_alpn_length_does_not_overrun(self) -> None:
        # ALPN entry claims a 200-byte protocol but only 2 bytes follow: the
        # parser must stop at the extension boundary, not walk into later bytes.
        inner = struct.pack(">H", 3) + b"\xc8" + b"h3"
        bad_alpn = struct.pack(">H", 0x10) + struct.pack(">H", len(inner)) + inner
        payload = build_client_hello(extensions=bad_alpn + sni_extension(b"x.example"))
        hello = parse_client_hello(payload)
        assert hello is not None
        assert hello.sni == "x.example"
        assert hello.alpn == []


def dns_svcb_packet(
    qname: str,
    rtype: str = "HTTPS",
    priority: int = 1,
    target: str = ".",
    alpn: list[bytes] | None = None,
    port: int | None = None,
    ipv4hint: list[str] | None = None,
    ipv6hint: list[str] | None = None,
    ech: bytes | None = None,
) -> Packet:
    params = []
    if alpn is not None:
        params.append(SvcParam(key="alpn", value=alpn))
    if port is not None:
        params.append(SvcParam(key="port", value=port))
    if ipv4hint is not None:
        params.append(SvcParam(key="ipv4hint", value=ipv4hint))
    if ipv6hint is not None:
        params.append(SvcParam(key="ipv6hint", value=ipv6hint))
    if ech is not None:
        params.append(SvcParam(key="ech", value=ech))
    cls = DNSRRSVCB if rtype == "SVCB" else DNSRRHTTPS
    rr = cls(
        rrname=qname,
        type=rtype,
        ttl=300,
        svc_priority=priority,
        target_name=target,
        svc_params=params,
    )
    pkt = (
        Ether()
        / IP(src="8.8.8.8", dst="192.168.1.50")
        / UDP(sport=53, dport=54321)
        / DNS(qr=1, qd=DNSQR(qname=qname, qtype=rtype), an=rr)
    )
    # Reparse from bytes so the SvcParams traverse the real on-wire dissection.
    reparsed = Ether(bytes(pkt))
    reparsed.time = PKT_TIME
    return reparsed


class TestDnsHttpsRecords:
    def test_https_answer_emits_event_with_hints_and_ech(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = dns_svcb_packet(
            "example.com",
            alpn=[b"h3", b"h2"],
            port=443,
            ipv4hint=["192.0.2.1"],
            ipv6hint=["2001:db8::1"],
            ech=b"\x00\x01\x02",
        )
        events = proc.process(pkt)
        https = [e for e in events if isinstance(e, DnsHttpsEvent)]
        assert len(https) == 1
        e = https[0]
        assert e.qname == "example.com"
        assert e.rtype == "HTTPS"
        assert e.alpn == ["h3", "h2"]
        assert e.port == 443
        assert e.ipv4hint == ["192.0.2.1"]
        assert e.ipv6hint == ["2001:db8::1"]
        assert e.ech is True

    def test_https_hints_populate_name_ledger(self) -> None:
        proc = local_processor("192.168.1.50")
        proc.process(
            dns_svcb_packet("example.com", ipv4hint=["192.0.2.7"], ipv6hint=["2001:db8::7"])
        )
        assert proc.names.lookup("192.0.2.7") == "example.com"
        assert proc.names.lookup("2001:db8::7") == "example.com"

    def test_https_without_ech_leaves_flag_false(self) -> None:
        proc = local_processor("192.168.1.50")
        events = proc.process(dns_svcb_packet("example.com", alpn=[b"h2"]))
        e = next(x for x in events if isinstance(x, DnsHttpsEvent))
        assert e.ech is False
        assert e.alpn == ["h2"]

    def test_svcb_record_type64_also_parsed(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = dns_svcb_packet("_dns.example.com", rtype="SVCB", ipv4hint=["192.0.2.9"])
        e = next(x for x in proc.process(pkt) if isinstance(x, DnsHttpsEvent))
        assert e.rtype == "SVCB"
        assert e.ipv4hint == ["192.0.2.9"]

    def test_https_event_writes_to_dns_jsonl(self, tmp_path: Path) -> None:
        writer = JsonlWriter(tmp_path / "run-x")
        writer.write(
            DnsHttpsEvent(
                ts=EXPECTED_ISO,
                resolver="8.8.8.8",
                qname="example.com",
                rtype="HTTPS",
                priority=1,
                target="",
                ttl=300,
            )
        )
        writer.close()
        assert (tmp_path / "run-x" / "dns.jsonl").exists()


class TestServiceAnnotations:
    def _http_get(self, host: bytes) -> Packet:
        payload = b"GET / HTTP/1.1\r\nHost: " + host + b"\r\n\r\n"
        return tcp_segment(payload, dport=80, flags="PA")

    def test_captive_portal_host_tagged(self) -> None:
        proc = local_processor("192.168.1.50")
        http = next(
            e
            for e in proc.process(self._http_get(b"captive.apple.com"))
            if isinstance(e, HttpEvent)
        )
        assert http.tag == "captive-portal"

    def test_ordinary_host_not_tagged(self) -> None:
        proc = local_processor("192.168.1.50")
        http = next(
            e for e in proc.process(self._http_get(b"example.com")) if isinstance(e, HttpEvent)
        )
        assert http.tag is None

    def test_captive_portal_host_with_port_tagged(self) -> None:
        proc = local_processor("192.168.1.50")
        http = next(
            e
            for e in proc.process(self._http_get(b"captive.apple.com:80"))
            if isinstance(e, HttpEvent)
        )
        assert http.tag == "captive-portal"

    def test_ntp_flow_annotated(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = Ether() / IP(src="192.168.1.50", dst="17.253.14.125") / UDP(sport=51000, dport=123)
        pkt.time = PKT_TIME
        flow = single_flow(proc.process(pkt))
        assert flow.service == "ntp"
        assert flow.note is not None

    def test_starttls_smtp_flow_annotated(self) -> None:
        proc = local_processor("192.168.1.50")
        flow = single_flow(proc.process(make_syn("192.168.1.50", "17.253.14.125", 51000, 587)))
        assert flow.service == "smtp-submission"
        assert flow.note is not None

    def test_ordinary_https_flow_has_no_note(self) -> None:
        proc = local_processor("192.168.1.50")
        flow = single_flow(proc.process(make_syn("192.168.1.50", "93.184.216.34", 51000, 443)))
        assert flow.note is None


class TestRunAgainstReplay:
    async def test_run_writes_events_and_capture_stats_to_summary(self, tmp_path: Path) -> None:
        pcap = tmp_path / "replay.pcap"
        write_replay_pcap(pcap)
        args = argparse.Namespace(
            read=str(pcap),
            iface=None,
            bpf=None,
            output=str(tmp_path / "logs"),
            quiet=True,
            keep_query=False,
        )
        await run(args)
        run_dir = next((tmp_path / "logs").iterdir())
        summary = json.loads((run_dir / "summary.json").read_text())
        assert summary["capture"]["kernel_dropped"] == "unavailable"
        assert summary["capture"]["userspace_dropped"] == 0
        assert summary["events"]["dns_query"] == 1
        assert summary["events"]["tls_sni"] == 1
        assert (run_dir / "dns.jsonl").exists()

    async def test_missing_pcap_exits_cleanly_without_run_dir(self, tmp_path: Path) -> None:
        # A wrong -r path must fail with a clean exit, not crash the reader mid-run
        # with a traceback and leave an empty run directory behind.
        args = argparse.Namespace(
            read=str(tmp_path / "nope.pcap"),
            iface=None,
            bpf=None,
            output=str(tmp_path / "logs"),
            quiet=True,
            keep_query=False,
        )
        with pytest.raises(SystemExit) as exc:
            await run(args)
        assert exc.value.code == 1
        assert not (tmp_path / "logs").exists()  # no run dir created for a bad path


class _FullDiskFile:
    # A disk with no space left: every write raises the kernel's real ENOSPC
    # OSError. A genuine file-object contract (incl. context manager, as
    # open_private_new returns), no mocking framework.
    def __init__(self) -> None:
        self.closed = False

    def write(self, _s: str) -> int:
        raise OSError(28, "No space left on device")

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> "_FullDiskFile":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class _FullDiskClosingFile(_FullDiskFile):
    # Same, but a delayed-writeback error also surfaces at close() (some filesystems
    # only report a full disk when the final buffered flush lands).
    def close(self) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")


class TestDiskFullResilience:
    # The always-on recorder fills a disk with browsing history; a full disk must
    # degrade the record honestly, never crash the run into a systemd restart loop.
    def test_write_failure_degrades_without_raising(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import netmon

        monkeypatch.setattr(netmon, "open_private_new", lambda _p: _FullDiskFile())
        writer = JsonlWriter(tmp_path / "run")
        ev = DnsQueryEvent(ts="t", src="a", dst="b", transport="udp", qname="x.example", qtype="A")
        writer.write(ev)  # must not raise despite ENOSPC
        writer.write(ev)
        assert writer.write_failures == 2

    def test_summary_write_failure_does_not_raise(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import netmon

        monkeypatch.setattr(netmon, "open_private_new", lambda _p: _FullDiskFile())
        writer = JsonlWriter(tmp_path / "run")
        writer.write_summary({"ok": True})  # must not raise
        writer.close()  # must not raise

    def test_finalize_reports_dropped_events(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import netmon

        monkeypatch.setattr(netmon, "open_private_new", lambda _p: _FullDiskFile())
        proc = local_processor("192.168.1.50")
        writer = JsonlWriter(tmp_path / "run")
        for ev in proc.process(make_syn("192.168.1.50", "93.184.216.34", 51000, 443)):
            writer.write(ev)
        session = Session(tmp_path / "run", proc, writer, ReplayCapture(tmp_path / "x.pcap"))
        summary = finalize(session)  # must not raise
        assert summary["persistence"]["events_dropped"] >= 1

    async def test_run_survives_a_full_disk(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import netmon

        pcap = tmp_path / "replay.pcap"
        write_replay_pcap(pcap)
        monkeypatch.setattr(netmon, "open_private_new", lambda _p: _FullDiskFile())
        args = argparse.Namespace(
            read=str(pcap),
            iface=None,
            bpf=None,
            output=str(tmp_path / "logs"),
            quiet=True,
            keep_query=False,
        )
        await run(args)  # previously crashed on ENOSPC; must now complete cleanly

    def test_degrade_survives_log_redirected_to_full_disk(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # `netmon run --log` redirects the diagnostic log onto the same (full) disk,
        # so the degrade path's own log.error must not itself re-crash the run.
        import netmon

        monkeypatch.setattr(netmon, "open_private_new", lambda _p: _FullDiskFile())
        # a minimal fault-injecting stand-in for the redirected diagnostic log
        configure_logging(stream=_FullDiskFile())  # type: ignore[arg-type]
        try:
            writer = JsonlWriter(tmp_path / "run")
            ev = DnsQueryEvent(ts="t", src="a", dst="b", transport="udp", qname="x", qtype="A")
            writer.write(ev)  # must not raise though logging the failure also fails
            assert writer.write_failures == 1
        finally:
            configure_logging()

    def test_run_dir_creation_on_full_disk_degrades_not_crashes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A disk already full at startup: mkdir raises ENOSPC. The writer degrades to
        # a no-op instead of crash-looping before the run can report anything.
        def boom(self: Path, *_a: object, **_k: object) -> None:
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(Path, "mkdir", boom)
        writer = JsonlWriter(tmp_path / "run")  # must not raise
        ev = DnsQueryEvent(ts="t", src="a", dst="b", transport="udp", qname="x", qtype="A")
        writer.write(ev)
        assert writer.write_failures == 1

    def test_close_does_not_raise_on_full_disk(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import netmon

        monkeypatch.setattr(netmon, "open_private_new", lambda _p: _FullDiskClosingFile())
        writer = JsonlWriter(tmp_path / "run")
        ev = DnsQueryEvent(ts="t", src="a", dst="b", transport="udp", qname="x", qtype="A")
        writer.write(ev)  # stores the handle, then the write fails -> degraded
        writer.close()  # a buffered final flush also hits ENOSPC; must not raise


class TestPcapEvidenceSink:
    # `--pcap` preserves the raw wire bytes JSONL cannot (cert timing, JA3/JA4) so a
    # finding can be re-opened in tshark/Wireshark. Same owner-only, symlink-refusing,
    # degrade-not-crash discipline as JsonlWriter.
    def test_written_pcap_is_owner_only(self, tmp_path: Path) -> None:
        sink = PcapSink(tmp_path / "capture.pcap")
        sink.write(make_syn("192.168.1.50", "93.184.216.34", 51000, 443))
        sink.close()
        mode = (tmp_path / "capture.pcap").stat().st_mode
        assert mode & 0o077 == 0, oct(mode)
        assert sink.write_failures == 0

    def test_write_failure_degrades_without_raising(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import netmon

        monkeypatch.setattr(netmon, "open_private_new_bytes", lambda _p: _FullDiskFile())
        sink = PcapSink(tmp_path / "capture.pcap")
        pkt = make_syn("192.168.1.50", "93.184.216.34", 51000, 443)
        sink.write(pkt)  # must not raise despite ENOSPC
        sink.write(pkt)
        sink.close()  # must not raise
        assert sink.write_failures == 2

    def test_close_does_not_raise_on_full_disk(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import netmon

        monkeypatch.setattr(netmon, "open_private_new_bytes", lambda _p: _FullDiskClosingFile())
        sink = PcapSink(tmp_path / "capture.pcap")
        sink.write(make_syn("192.168.1.50", "93.184.216.34", 51000, 443))
        sink.close()  # a buffered final flush also hits ENOSPC; must not raise

    def test_unserializable_packet_is_skipped_not_crashed(self, tmp_path: Path) -> None:
        # A packet scapy cannot map to a link type (a Raw frame from a tun/tunnel
        # capture or an exotic -r pcap) raises KeyError deep in PcapWriter, not OSError.
        # It must be dropped and counted, never crash the run — and must not blind the
        # sink to the well-formed packets around it. Mirrors process()'s parse guard.
        from scapy.packet import Raw

        sink = PcapSink(tmp_path / "capture.pcap")
        good = make_syn("192.168.1.50", "93.184.216.34", 51000, 443)
        sink.write(good)
        sink.write(Raw(b"\x00\x01\x02\x03"))  # must not raise
        sink.write(good)
        sink.close()
        assert sink.write_failures == 1  # only the Raw packet dropped
        assert len(rdpcap(str(tmp_path / "capture.pcap"))) == 2  # both good packets kept

    def test_create_failure_degrades_not_crashes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A disk already full when the sink opens: degrade to a no-op that counts
        # drops, matching the JSONL writer, rather than crash the run at startup.
        import netmon

        def boom(_p: Path) -> object:
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(netmon, "open_private_new_bytes", boom)
        sink = PcapSink(tmp_path / "capture.pcap")  # must not raise
        sink.write(make_syn("192.168.1.50", "93.184.216.34", 51000, 443))
        assert sink.write_failures == 1

    def test_refuses_symlinked_target_without_touching_it(self, tmp_path: Path) -> None:
        # CWE-59: never follow a pre-staged symlink at the pcap path (root arbitrary
        # write). The security refusal must propagate, not be swallowed as a drop.
        victim = tmp_path / "victim.bin"
        victim.write_bytes(b"keep")
        link = tmp_path / "capture.pcap"
        link.symlink_to(victim)
        with pytest.raises(FileExistsError):
            PcapSink(link)
        assert victim.read_bytes() == b"keep"

    def test_pcap_flag_defaults_off_in_both_parsers(self) -> None:
        assert _legacy_parser().parse_args([]).pcap is False
        assert _run_parser().parse_args([]).pcap is False
        assert _legacy_parser().parse_args(["--pcap"]).pcap is True
        assert _run_parser().parse_args(["--pcap"]).pcap is True

    async def test_no_pcap_flag_writes_no_capture_file(self, tmp_path: Path) -> None:
        pcap = tmp_path / "in.pcap"
        write_replay_pcap(pcap)
        args = argparse.Namespace(
            read=str(pcap),
            iface=None,
            bpf=None,
            output=str(tmp_path / "logs"),
            quiet=True,
            keep_query=False,
        )
        await run(args)  # no `pcap` attr => default off
        run_dir = next((tmp_path / "logs").glob("run-*"))
        assert not (run_dir / "capture.pcap").exists()

    async def test_pcap_flag_writes_capture_file(self, tmp_path: Path) -> None:
        pcap = tmp_path / "in.pcap"
        write_replay_pcap(pcap)
        args = argparse.Namespace(
            read=str(pcap),
            iface=None,
            bpf=None,
            output=str(tmp_path / "logs"),
            quiet=True,
            keep_query=False,
            pcap=True,
        )
        await run(args)
        out = next((tmp_path / "logs").glob("run-*/capture.pcap"))
        assert out.stat().st_mode & 0o077 == 0

    async def test_replay_pcap_round_trips_without_corrupting_packets(self, tmp_path: Path) -> None:
        # `netmon -r <in.pcap> --pcap` reads then re-writes; every packet must survive
        # byte-for-byte so a preserved capture is faithful evidence.
        src = tmp_path / "in.pcap"
        write_replay_pcap(src)
        args = argparse.Namespace(
            read=str(src),
            iface=None,
            bpf=None,
            output=str(tmp_path / "logs"),
            quiet=True,
            keep_query=False,
            pcap=True,
        )
        await run(args)
        out = next((tmp_path / "logs").glob("run-*/capture.pcap"))
        original = rdpcap(str(src))
        roundtripped = rdpcap(str(out))
        assert len(roundtripped) == len(original)
        assert [bytes(p) for p in roundtripped] == [bytes(p) for p in original]

    async def test_summary_reports_pcap_drops(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A pcap that could not be fully written is surfaced in the summary the same
        # way a truncated JSONL record is — an honest gap, not a silent one.
        import netmon

        pcap = tmp_path / "in.pcap"
        write_replay_pcap(pcap)
        monkeypatch.setattr(netmon, "open_private_new_bytes", lambda _p: _FullDiskFile())
        proc = local_processor("192.168.1.50")
        session = Session(
            tmp_path / "run",
            proc,
            NullWriter(),
            ReplayCapture(pcap),
            PcapSink(tmp_path / "run" / "capture.pcap"),
        )
        async for pkt in session.capture.packets():
            if session.pcap_sink is not None:
                session.pcap_sink.write(pkt)
        summary = finalize(session)
        assert summary["persistence"]["pcap_dropped"] >= 1


class TestCoverageLedger:
    def test_summary_includes_coverage_block(self) -> None:
        proc = local_processor("192.168.1.50")
        proc.process(make_syn("192.168.1.50", "93.184.216.34", 51000, 443))
        cov = proc.summary()["coverage"]
        assert cov["packets"] == 1
        assert cov["fate"]["event"] == 1
        assert "evicted" in cov
        assert "parse_failed" in cov

    def test_every_packet_lands_in_exactly_one_fate(self) -> None:
        proc = local_processor("192.168.1.50")
        proc.process(make_syn("192.168.1.50", "93.184.216.34", 51000, 443))  # flow
        proc.process(make_syn("192.168.1.50", "93.184.216.34", 51000, 443))  # dedup
        other = Ether(type=0x9999) / b"\x00\x01\x02\x03"  # unknown ethertype
        other.time = PKT_TIME
        proc.process(other)  # non_ip
        cov = proc.summary()["coverage"]
        assert cov["packets"] == 3
        assert sum(cov["fate"].values()) == 3

    def test_non_ip_frame_fate_names_its_deepest_decoded_layer(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = Ether(type=0x9999) / b"\x00\x01\x02\x03"  # not IP, not ARP
        pkt.time = PKT_TIME
        assert proc.process(pkt) == []
        assert proc.summary()["coverage"]["fate"]["non_ip:Ether"] == 1

    def test_icmp_marked_unhandled_by_protocol(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / ICMP()
        pkt.time = PKT_TIME
        assert proc.process(pkt) == []
        assert proc.summary()["coverage"]["fate"]["unhandled:icmp"] == 1

    def test_quic_decrypt_failure_surfaces_in_coverage(self) -> None:
        proc = local_processor("192.168.1.50")
        good = encrypt_initial(RFC_DCID, crypto_frame(handshake_message(b"x.example.net")))
        datagram = bytearray(good)
        datagram[-1] ^= 0xFF  # corrupt the AEAD tag
        pkt = (
            Ether()
            / IP(src="192.168.1.50", dst="93.184.216.34")
            / UDP(sport=50000, dport=443)
            / bytes(datagram)
        )
        pkt.time = PKT_TIME
        proc.process(pkt)
        assert proc.summary()["coverage"]["parse_failed"]["quic_initial"] == 1

    def test_name_ledger_eviction_surfaces_in_coverage(self) -> None:
        proc = PacketProcessor(local_ips=frozenset({"192.168.1.50"}), name_cap=4)
        for i in range(20):
            ans = (
                Ether()
                / IP(src="8.8.8.8", dst="192.168.1.50")
                / UDP(sport=53, dport=54321)
                / DNS(
                    qr=1,
                    qd=DNSQR(qname=f"h{i}.example.com"),
                    an=DNSRR(rrname=f"h{i}.example.com", type="A", ttl=60, rdata=f"10.0.0.{i}"),
                )
            )
            ans.time = PKT_TIME
            proc.process(ans)
        assert proc.summary()["coverage"]["evicted"]["names"] > 0


class TestSilentDropHonesty:
    # The ledger's whole promise is "a clean log is not a silent gap". A fragment we
    # cannot reassemble must not vanish into "no_disclosure"/"unhandled": its L4
    # content is skipped, but a first fragment still carries the flow disclosure, and
    # a fragment that yields no event lands under the honest ip_fragment fate.
    def test_first_fragment_still_records_the_flow(self) -> None:
        proc = local_processor("192.168.1.50")
        # First fragment of a large DNS response: MF set, payload truncated. The L4
        # header is intact, so the flow (who talked to whom) must still surface.
        pkt = Ether(
            bytes(
                Ether()
                / IP(src="8.8.8.8", dst="192.168.1.50", flags="MF")
                / UDP(sport=53, dport=54321)
                / bytes(DNS(qr=1, qd=DNSQR(qname="big.example.com")))[:8]
            )
        )
        pkt.time = PKT_TIME
        events = proc.process(pkt)
        assert [type(e) for e in events] == [FlowEvent]  # flow kept, payload not parsed
        fate = proc.summary()["coverage"]["fate"]
        assert fate.get("event") == 1
        assert "no_disclosure" not in fate

    def test_trailing_fragment_marked_ip_fragment(self) -> None:
        proc = local_processor("192.168.1.50")
        # A non-first fragment has no L4 header at all (frag offset > 0), so there is
        # nothing to disclose but the fragment itself.
        pkt = Ether(
            bytes(Ether() / IP(src="8.8.8.8", dst="192.168.1.50", frag=100) / (b"\x00" * 40))
        )
        pkt.time = PKT_TIME
        assert proc.process(pkt) == []
        fate = proc.summary()["coverage"]["fate"]
        assert fate["ip_fragment"] == 1
        assert not any(k.startswith("unhandled") for k in fate)

    def test_ipv6_first_fragment_still_records_the_flow(self) -> None:
        proc = local_processor("2001:db8::50")
        pkt = Ether(
            bytes(
                Ether()
                / IPv6(src="2001:db8::1", dst="2001:db8::50")
                / IPv6ExtHdrFragment(offset=0, m=1, nh=17)
                / UDP(sport=53, dport=54321)
                / bytes(DNS(qr=1, qd=DNSQR(qname="big.example.com")))[:8]
            )
        )
        pkt.time = PKT_TIME
        events = proc.process(pkt)
        assert [type(e) for e in events] == [FlowEvent]
        assert proc.summary()["coverage"]["fate"].get("event") == 1

    def test_ipv6_trailing_fragment_marked_ip_fragment(self) -> None:
        proc = local_processor("2001:db8::50")
        pkt = Ether(
            bytes(
                Ether()
                / IPv6(src="2001:db8::1", dst="2001:db8::50")
                / IPv6ExtHdrFragment(offset=64, m=0, nh=17)
                / (b"\x11" * 24)
            )
        )
        pkt.time = PKT_TIME
        assert proc.process(pkt) == []
        assert proc.summary()["coverage"]["fate"]["ip_fragment"] == 1

    def test_deduped_first_fragment_marked_ip_fragment(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = Ether(
            bytes(
                Ether()
                / IP(src="8.8.8.8", dst="192.168.1.50", flags="MF")
                / UDP(sport=53, dport=54321)
                / (b"\x00" * 8)
            )
        )
        pkt.time = PKT_TIME
        proc.process(pkt)  # first sight: emits the flow
        proc.process(pkt)  # flow already seen: no event, honest ip_fragment fate
        fate = proc.summary()["coverage"]["fate"]
        assert fate["event"] == 1
        assert fate["ip_fragment"] == 1

    def test_icmpv6_error_quoting_a_fragment_is_not_mistaken_for_one(self) -> None:
        # A whole ICMPv6 error quotes the original (fragmented) datagram, header and
        # all: the fragment header sits inside the error, not in our outer chain.
        proc = local_processor("2001:db8::50")
        pkt = Ether(
            bytes(
                Ether()
                / IPv6(src="2001:db8::9", dst="2001:db8::50")
                / ICMPv6DestUnreach()
                / IPv6(src="a::1", dst="b::2")
                / IPv6ExtHdrFragment(offset=5, m=0, nh=17)
                / UDP()
                / b"hello"
            )
        )
        pkt.time = PKT_TIME
        proc.process(pkt)
        fate = proc.summary()["coverage"]["fate"]
        assert "ip_fragment" not in fate
        assert fate["unhandled:icmpv6"] == 1

    def test_fragment_lands_in_exactly_one_fate(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = Ether(
            bytes(Ether() / IP(src="8.8.8.8", dst="192.168.1.50", frag=100) / (b"\x00" * 8))
        )
        pkt.time = PKT_TIME
        proc.process(pkt)
        cov = proc.summary()["coverage"]
        assert cov["packets"] == 1
        assert sum(cov["fate"].values()) == 1

    def test_plausible_dns_that_fails_to_parse_counts_as_dns_parse_failed(self) -> None:
        proc = local_processor("192.168.1.50")
        # A real query whose header lies (ancount=1 with no answer bytes): passes
        # the shape gate but scapy cannot turn it into a valid message.
        raw = bytearray(bytes(DNS(qr=0, qd=DNSQR(qname="tracker.example.com"))))
        struct.pack_into(">H", raw, 6, 1)  # ancount 0 -> 1
        pkt = (
            Ether()
            / IP(src="192.168.1.50", dst="8.8.8.8")
            / UDP(sport=51000, dport=53)
            / bytes(raw)
        )
        pkt.time = PKT_TIME
        proc.process(pkt)
        cov = proc.summary()["coverage"]
        assert cov["parse_failed"]["dns"] == 1
        assert cov["fate"]["event"] == 1  # the flow itself still surfaces

    def test_non_dns_noise_not_counted_as_dns_parse_failed(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = (
            Ether()
            / IP(src="192.168.1.50", dst="8.8.8.8")
            / UDP(sport=51000, dport=53)
            / bytes(range(40))
        )
        pkt.time = PKT_TIME
        proc.process(pkt)
        assert proc.summary()["coverage"]["parse_failed"]["dns"] == 0

    def test_quic_initial_not_miscounted_as_dns_parse_failed(self) -> None:
        proc = local_processor("192.168.1.50")
        datagram = encrypt_initial(RFC_DCID, crypto_frame(handshake_message(b"x.example.net")))
        pkt = (
            Ether()
            / IP(src="192.168.1.50", dst="93.184.216.34")
            / UDP(sport=50000, dport=443)
            / datagram
        )
        pkt.time = PKT_TIME
        proc.process(pkt)
        assert proc.summary()["coverage"]["parse_failed"]["dns"] == 0


def dns_response(
    qd: object,
    an: object | None = None,
    rcode: int = 0,
    src: str = "8.8.8.8",
    dst: str = "192.168.1.50",
) -> Packet:
    dns = DNS(qr=1, rcode=rcode, qd=qd) if an is None else DNS(qr=1, rcode=rcode, qd=qd, an=an)
    pkt = Ether() / IP(src=src, dst=dst) / UDP(sport=53, dport=54321) / dns
    reparsed = Ether(bytes(pkt))  # traverse the real on-wire dissection
    reparsed.time = PKT_TIME
    return reparsed


NXDOMAIN, SERVFAIL, REFUSED = 3, 2, 5


class TestDnsResponseOutcomes:
    def test_nxdomain_empty_answer_emits_response_event(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = dns_response(DNSQR(qname="nope.example.com", qtype="A"), rcode=NXDOMAIN)
        resp = [e for e in proc.process(pkt) if isinstance(e, DnsResponseEvent)]
        assert len(resp) == 1
        assert resp[0].qname == "nope.example.com"
        assert resp[0].qtype == "A"
        assert resp[0].rcode == "NXDOMAIN"
        assert resp[0].resolver == "8.8.8.8"

    def test_refused_outcome_recorded(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = dns_response(DNSQR(qname="blocked.example.com"), rcode=REFUSED)
        resp = [e for e in proc.process(pkt) if isinstance(e, DnsResponseEvent)]
        assert len(resp) == 1
        assert resp[0].rcode == "REFUSED"

    def test_noerror_answer_carries_rcode(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = dns_response(
            DNSQR(qname="example.com"),
            an=DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.34"),
        )
        answer = next(e for e in proc.process(pkt) if isinstance(e, DnsAnswerEvent))
        assert answer.rcode == "NOERROR"
        assert answer.value == "93.184.216.34"

    def test_cname_chain_answer_attributes_queried_name_not_cname_target(self) -> None:
        # A CNAME→A chain (every CDN-fronted site): the final A record's rrname
        # is the CNAME target, but the ledger must be seeded with the name the
        # client actually queried, so later flows show the visited host.
        proc = local_processor("192.168.1.50")
        pkt = dns_response(
            DNSQR(qname="www.example.com"),
            an=[
                DNSRR(rrname="www.example.com", type="CNAME", ttl=300, rdata="cdn.example.net"),
                DNSRR(rrname="cdn.example.net", type="A", ttl=300, rdata="1.2.3.4"),
            ],
        )
        answers = [e for e in proc.process(pkt) if isinstance(e, DnsAnswerEvent)]
        a_record = next(e for e in answers if e.rtype == "A")
        assert a_record.qname == "www.example.com"
        assert proc.names.lookup("1.2.3.4") == "www.example.com"

    def test_multi_question_response_records_every_question(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = dns_response(
            [DNSQR(qname="a.example.com", qtype="A"), DNSQR(qname="b.example.com", qtype="AAAA")],
            rcode=NXDOMAIN,
        )
        resp = [e for e in proc.process(pkt) if isinstance(e, DnsResponseEvent)]
        assert {e.qname for e in resp} == {"a.example.com", "b.example.com"}

    def test_empty_answer_counts_as_event_not_no_disclosure(self) -> None:
        proc = local_processor("192.168.1.50")
        proc.process(dns_response(DNSQR(qname="nope.example.com"), rcode=NXDOMAIN))
        fate = proc.summary()["coverage"]["fate"]
        assert fate.get("event") == 1
        assert "no_disclosure" not in fate

    def test_response_event_written_to_dns_jsonl(self, tmp_path: Path) -> None:
        writer = JsonlWriter(tmp_path / "run-x")
        writer.write(
            DnsResponseEvent(
                ts=EXPECTED_ISO,
                resolver="8.8.8.8",
                qname="nope.example.com",
                qtype="A",
                rcode="NXDOMAIN",
            )
        )
        writer.close()
        assert (tmp_path / "run-x" / "dns.jsonl").exists()

    def test_truncated_response_yields_nothing_and_does_not_crash(self) -> None:
        # Header claims a question but the packet is truncated to the 12-byte
        # header — no question bytes to attribute. Must produce no event, no crash.
        proc = local_processor("192.168.1.50")
        truncated = bytes(DNS(qr=1, rcode=SERVFAIL, qdcount=1))[:12]
        pkt = (
            Ether() / IP(src="8.8.8.8", dst="192.168.1.50") / UDP(sport=53, dport=54321) / truncated
        )
        pkt = Ether(bytes(pkt))
        pkt.time = PKT_TIME
        events = proc.process(pkt)
        assert [e for e in events if isinstance(e, DnsResponseEvent | DnsAnswerEvent)] == []


class TestFramingBasedQuic:
    def _quic_pkt(self, datagram: bytes, dport: int) -> Packet:
        pkt = (
            Ether()
            / IP(src="192.168.1.50", dst="93.184.216.34")
            / UDP(sport=50000, dport=dport)
            / datagram
        )
        pkt.time = PKT_TIME
        return pkt

    def test_doq_udp853_yields_quic_tagged_sni(self) -> None:
        proc = local_processor("192.168.1.50")
        datagram = encrypt_initial(RFC_DCID, crypto_frame(handshake_message(b"dns.example.com")))
        sni = [e for e in proc.process(self._quic_pkt(datagram, 853)) if isinstance(e, TlsSniEvent)]
        assert len(sni) == 1
        assert sni[0].sni == "dns.example.com"
        assert sni[0].transport == "quic"

    def test_http3_alt_port_8443_yields_sni(self) -> None:
        proc = local_processor("192.168.1.50")
        datagram = encrypt_initial(RFC_DCID, crypto_frame(handshake_message(b"h3.example.com")))
        sni = [
            e for e in proc.process(self._quic_pkt(datagram, 8443)) if isinstance(e, TlsSniEvent)
        ]
        assert len(sni) == 1
        assert sni[0].sni == "h3.example.com"

    def test_non_quic_udp_yields_only_flow(self) -> None:
        proc = local_processor("192.168.1.50")
        events = proc.process(self._quic_pkt(b"\x01not a quic long header at all", 1234))
        assert [e for e in events if isinstance(e, TlsSniEvent)] == []
        assert any(isinstance(e, FlowEvent) for e in events)

    def test_port_443_still_extracts_sni(self) -> None:
        proc = local_processor("192.168.1.50")
        datagram = encrypt_initial(RFC_DCID, crypto_frame(handshake_message(b"quic.example.com")))
        sni = [e for e in proc.process(self._quic_pkt(datagram, 443)) if isinstance(e, TlsSniEvent)]
        assert len(sni) == 1
        assert sni[0].sni == "quic.example.com"


def llmnr_query(
    name: str = "wpad", qtype: str = "A", src: str = "192.168.1.50", dst: str = "224.0.0.252"
) -> Packet:
    pkt = (
        Ether()
        / IP(src=src, dst=dst)
        / UDP(sport=50000, dport=5355)
        / LLMNRQuery(qd=DNSQR(qname=name, qtype=qtype))
    )
    reparsed = Ether(bytes(pkt))
    reparsed.time = PKT_TIME
    return reparsed


def nbns_query(
    name: str = "WORKGROUP", src: str = "192.168.1.50", dst: str = "192.168.1.255"
) -> Packet:
    pkt = (
        Ether()
        / IP(src=src, dst=dst)
        / UDP(sport=137, dport=137)
        / NBNSHeader()
        / NBNSQueryRequest(QUESTION_NAME=name)
    )
    reparsed = Ether(bytes(pkt))
    reparsed.time = PKT_TIME
    return reparsed


class TestLlmnrNbns:
    def test_llmnr_query_emits_event_with_name(self) -> None:
        proc = local_processor("192.168.1.50")
        events = proc.process(llmnr_query("wpad"))
        llmnr = [e for e in events if isinstance(e, LlmnrEvent)]
        assert len(llmnr) == 1
        assert llmnr[0].qname == "wpad"
        assert llmnr[0].src == "192.168.1.50"

    def test_nbns_query_emits_event_with_name(self) -> None:
        proc = local_processor("192.168.1.50")
        nbns = [e for e in proc.process(nbns_query("WORKGROUP")) if isinstance(e, NbnsEvent)]
        assert len(nbns) == 1
        assert nbns[0].qname == "WORKGROUP"

    def test_kinds_routed_to_own_files(self) -> None:
        from netmon import KIND_TO_FILE

        assert KIND_TO_FILE["llmnr"] == "llmnr.jsonl"
        assert KIND_TO_FILE["nbns"] == "nbns.jsonl"

    def test_llmnr_counts_as_event_in_coverage(self) -> None:
        proc = local_processor("192.168.1.50")
        proc.process(llmnr_query())
        assert proc.summary()["coverage"]["fate"].get("event") == 1

    def test_repeated_llmnr_query_deduped(self) -> None:
        proc = local_processor("192.168.1.50")
        assert [e for e in proc.process(llmnr_query("host1")) if isinstance(e, LlmnrEvent)]
        assert [e for e in proc.process(llmnr_query("host1")) if isinstance(e, LlmnrEvent)] == []

    def test_malformed_llmnr_yields_nothing_and_does_not_crash(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = Ether() / IP(src="192.168.1.50", dst="224.0.0.252") / UDP(dport=5355) / LLMNRQuery()
        pkt = Ether(bytes(pkt))
        pkt.time = PKT_TIME
        assert [e for e in proc.process(pkt) if isinstance(e, LlmnrEvent)] == []

    def test_llmnr_query_with_linked_resource_records_does_not_crash(self) -> None:
        # LLMNR reuses DNS's qd machinery, so the same older-scapy linked-chain over-walk
        # applies: walking llmnr.qd into a resource record and reading .qname must not crash.
        proc = local_processor("192.168.1.50")

        class LinkedLlmnr:
            qr = 0
            qd = DNSQR(qname="wpad", qtype="A") / DNSRR(rrname="wpad", type="A", rdata="1.2.3.4")

        net = IP(src="192.168.1.50", dst="224.0.0.252")
        events = proc._llmnr_events(EXPECTED_ISO, net, LinkedLlmnr())
        llmnr = [e for e in events if isinstance(e, LlmnrEvent)]
        assert len(llmnr) == 1
        assert llmnr[0].qname == "wpad"


def ra_packet(
    router: str = "fe80::1",
    prefix: str = "2001:db8::",
    prefixlen: int = 64,
    rdnss: list[str] | None = None,
) -> Packet:
    ra = (
        IPv6(src=router, dst="ff02::1")
        / ICMPv6ND_RA()
        / ICMPv6NDOptPrefixInfo(prefix=prefix, prefixlen=prefixlen)
    )
    if rdnss is not None:
        ra = ra / ICMPv6NDOptRDNSS(dns=rdnss)
    reparsed = IPv6(bytes(ra))
    reparsed.time = PKT_TIME
    return reparsed


class TestIcmp6RouterAdvertisement:
    def test_ra_emits_event_with_router_prefix_and_rdnss(self) -> None:
        proc = local_processor("2001:db8::99")
        pkt = ra_packet(rdnss=["2001:db8::53", "2001:db8::54"])
        ra = [e for e in proc.process(pkt) if isinstance(e, Icmp6RaEvent)]
        assert len(ra) == 1
        assert ra[0].router == "fe80::1"
        assert "2001:db8::/64" in ra[0].prefixes
        assert ra[0].rdnss == ["2001:db8::53", "2001:db8::54"]

    def test_rdnss_seeds_name_ledger(self) -> None:
        proc = local_processor("2001:db8::99")
        proc.process(ra_packet(rdnss=["2001:db8::53"]))
        assert proc.names.lookup("2001:db8::53") == RA_RDNSS_NAME

    def test_icmp6_ra_routed_to_own_file(self) -> None:
        from netmon import KIND_TO_FILE

        assert KIND_TO_FILE["icmp6_ra"] == "icmp6.jsonl"

    def test_ra_leaves_unhandled_icmpv6_for_event(self) -> None:
        proc = local_processor("2001:db8::99")
        proc.process(ra_packet(rdnss=["2001:db8::53"]))
        fate = proc.summary()["coverage"]["fate"]
        assert fate.get("event") == 1
        assert "unhandled:icmpv6" not in fate

    def test_non_ra_icmpv6_yields_no_ra_event_and_does_not_crash(self) -> None:
        proc = local_processor("2001:db8::99")
        pkt = IPv6(src="fe80::1", dst="2001:db8::99") / ICMPv6EchoRequest()
        pkt = IPv6(bytes(pkt))
        pkt.time = PKT_TIME
        assert [e for e in proc.process(pkt) if isinstance(e, Icmp6RaEvent)] == []
        assert proc.summary()["coverage"]["fate"].get("unhandled:icmpv6") == 1


def arp_pkt(
    op: int = 1,
    psrc: str = "192.168.1.50",
    hwsrc: str = "aa:bb:cc:dd:ee:01",
    pdst: str = "192.168.1.1",
    hwdst: str = "00:00:00:00:00:00",
) -> Packet:
    pkt = Ether() / ARP(op=op, psrc=psrc, hwsrc=hwsrc, pdst=pdst, hwdst=hwdst)
    pkt.time = PKT_TIME
    return pkt


class TestArpDiscovery:
    def test_who_has_emits_arp_event(self) -> None:
        proc = local_processor("192.168.1.50")
        arp = [e for e in proc.process(arp_pkt(op=1)) if isinstance(e, ArpEvent)]
        assert len(arp) == 1
        assert arp[0].op == "who-has"
        assert arp[0].sender_ip == "192.168.1.50"
        assert arp[0].sender_mac == "aa:bb:cc:dd:ee:01"
        assert arp[0].target_ip == "192.168.1.1"
        assert arp[0].target_mac is None

    def test_is_at_emits_resolved_binding(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = arp_pkt(
            op=2,
            psrc="192.168.1.1",
            hwsrc="11:22:33:44:55:66",
            pdst="192.168.1.50",
            hwdst="aa:bb:cc:dd:ee:01",
        )
        arp = next(e for e in proc.process(pkt) if isinstance(e, ArpEvent))
        assert arp.op == "is-at"
        assert arp.sender_ip == "192.168.1.1"
        assert arp.sender_mac == "11:22:33:44:55:66"
        assert arp.target_mac == "aa:bb:cc:dd:ee:01"

    def test_repeated_identical_arp_deduped(self) -> None:
        proc = local_processor("192.168.1.50")
        assert [e for e in proc.process(arp_pkt()) if isinstance(e, ArpEvent)]
        assert [e for e in proc.process(arp_pkt()) if isinstance(e, ArpEvent)] == []

    def test_arp_dedup_evictions_counted_in_coverage(self) -> None:
        proc = PacketProcessor(local_ips=frozenset(), discovery_cap=2)
        for i in range(5):
            proc.process(arp_pkt(psrc=f"10.0.0.{i}", hwsrc=f"aa:bb:cc:dd:ee:{i:02x}"))
        assert proc.summary()["coverage"]["evicted"]["arp"] > 0

    def test_arp_leaves_non_ip_for_event(self) -> None:
        proc = local_processor("192.168.1.50")
        proc.process(arp_pkt())
        fate = proc.summary()["coverage"]["fate"]
        assert fate.get("event") == 1
        assert "non_ip" not in fate

    def test_arp_routed_to_own_file(self) -> None:
        from netmon import KIND_TO_FILE

        assert KIND_TO_FILE["arp"] == "arp.jsonl"


def dns_query_pkt(qname: str = "example.com", qtype: str = "A", dport: int = 53) -> Packet:
    pkt = (
        Ether()
        / IP(src="192.168.1.50", dst="8.8.8.8")
        / UDP(sport=50000, dport=dport)
        / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    )
    reparsed = Ether(bytes(pkt))  # dport binding decides whether scapy dissects DNS
    reparsed.time = PKT_TIME
    return reparsed


class TestDnsAuthorityAdditional:
    def test_ecs_option_in_query_surfaces_client_subnet(self) -> None:
        proc = local_processor("192.168.1.50")
        opt = DNSRROPT(rrname=".", rdata=[EDNS0ClientSubnet(address="192.0.2.0", source_plen=24)])
        pkt = (
            Ether()
            / IP(src="192.168.1.50", dst="8.8.8.8")
            / UDP(sport=50000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.com"), ar=opt)
        )
        pkt = Ether(bytes(pkt))
        pkt.time = PKT_TIME
        ecs = [e for e in proc.process(pkt) if isinstance(e, DnsEcsEvent)]
        assert len(ecs) == 1
        assert ecs[0].client_subnet == "192.0.2.0/24"
        assert ecs[0].qname == "example.com"

    def test_https_record_in_additional_section_emits_dns_https(self) -> None:
        proc = local_processor("192.168.1.50")
        rr = DNSRRHTTPS(
            rrname="example.com",
            type="HTTPS",
            ttl=300,
            svc_priority=1,
            target_name=".",
            svc_params=[SvcParam(key="alpn", value=[b"h3"])],
        )
        pkt = (
            Ether()
            / IP(src="8.8.8.8", dst="192.168.1.50")
            / UDP(sport=53, dport=54321)
            / DNS(qr=1, qd=DNSQR(qname="example.com", qtype="A"), ar=rr)
        )
        pkt = Ether(bytes(pkt))
        pkt.time = PKT_TIME
        https = [e for e in proc.process(pkt) if isinstance(e, DnsHttpsEvent)]
        assert len(https) == 1
        assert https[0].alpn == ["h3"]

    def test_glue_a_record_in_additional_seeds_name_ledger(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = (
            Ether()
            / IP(src="8.8.8.8", dst="192.168.1.50")
            / UDP(sport=53, dport=54321)
            / DNS(
                qr=1,
                rcode=0,
                qd=DNSQR(qname="example.com"),
                ns=DNSRR(rrname="example.com", type="NS", ttl=3600, rdata="ns1.example.net"),
                ar=DNSRR(rrname="ns1.example.net", type="A", ttl=3600, rdata="192.0.2.53"),
            )
        )
        pkt = Ether(bytes(pkt))
        pkt.time = PKT_TIME
        proc.process(pkt)
        assert proc.names.lookup("192.0.2.53") == "ns1.example.net"

    def test_soa_in_authority_section_surfaced(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = (
            Ether()
            / IP(src="8.8.8.8", dst="192.168.1.50")
            / UDP(sport=53, dport=54321)
            / DNS(
                qr=1,
                rcode=3,
                qd=DNSQR(qname="sub.example.com"),
                ns=DNSRRSOA(
                    rrname="example.com",
                    type="SOA",
                    ttl=3600,
                    mname="ns1.example.com",
                    rname="hostmaster.example.com",
                ),
            )
        )
        pkt = Ether(bytes(pkt))
        pkt.time = PKT_TIME
        answers = [e for e in proc.process(pkt) if isinstance(e, DnsAnswerEvent)]
        soa = [e for e in answers if e.rtype == "SOA"]
        assert len(soa) == 1
        assert soa[0].section == "authority"
        assert "ns1.example.com" in soa[0].value

    def test_answer_only_response_unaffected(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = (
            Ether()
            / IP(src="8.8.8.8", dst="192.168.1.50")
            / UDP(sport=53, dport=54321)
            / DNS(
                qr=1,
                qd=DNSQR(qname="example.com"),
                an=DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.34"),
            )
        )
        pkt = Ether(bytes(pkt))
        pkt.time = PKT_TIME
        answers = [e for e in proc.process(pkt) if isinstance(e, DnsAnswerEvent)]
        assert len(answers) == 1
        assert answers[0].section == "answer"
        assert answers[0].value == "93.184.216.34"


def dns_tcp_segments(msg: Packet, split_at: int, base_seq: int = 5000) -> list[Packet]:
    # A DNS-over-TCP message carries a 2-byte length prefix ahead of the body;
    # scapy emits it when DNS rides TCP. Split the wire bytes across two segments.
    full = (
        Ether()
        / IP(src="8.8.8.8", dst="192.168.1.50")
        / TCP(sport=53, dport=40000, flags="A", seq=base_seq)
        / msg
    )
    wire = bytes(Ether(bytes(full))[TCP].payload)
    out: list[Packet] = []
    for i, (start, chunk) in enumerate([(0, wire[:split_at]), (split_at, wire[split_at:])]):
        seg = (
            Ether()
            / IP(src="8.8.8.8", dst="192.168.1.50")
            / TCP(sport=53, dport=40000, flags="PA" if i == 1 else "A", seq=base_seq + start)
            / chunk
        )
        seg.time = PKT_TIME
        out.append(seg)
    return out


class TestDnsTcpReassembler:
    def _prefixed(self, qname: str, payload_len: int = 60) -> bytes:
        body = bytes(
            DNS(
                qr=1,
                qd=DNSQR(qname=qname),
                an=DNSRR(rrname=qname, type="TXT", ttl=60, rdata="x" * payload_len),
            )
        )
        return len(body).to_bytes(2, "big") + body

    def test_message_split_across_two_segments_assembles_once(self) -> None:
        r = DnsTcpReassembler()
        key = ("8.8.8.8", 53, "192.168.1.50", 40000)
        framed = self._prefixed("big.example.com")
        first, second = framed[:30], framed[30:]
        assert r.add(key, 0, first) == []
        bodies = r.add(key, 30, second)
        assert len(bodies) == 1
        assert bodies[0] == framed[2:]

    def test_single_segment_message_assembles(self) -> None:
        r = DnsTcpReassembler()
        key = ("8.8.8.8", 53, "192.168.1.50", 40000)
        framed = self._prefixed("whole.example.com")
        bodies = r.add(key, 0, framed)
        assert len(bodies) == 1
        assert bodies[0] == framed[2:]

    def test_long_lived_stream_does_not_go_blind_past_cap(self) -> None:
        # A persistent DoT connection multiplexes a device's whole lookup stream; the
        # sliding window must keep emitting once cumulative bytes pass per_flow_cap,
        # not fall permanently silent.
        r = DnsTcpReassembler(per_flow_cap=1024)
        key = ("8.8.8.8", 53, "192.168.1.50", 40000)
        msg = self._prefixed("q.example.com")
        emitted = 0
        seq = 0
        for _ in range(50):  # ~5 KB total, well past the 1 KB cap
            emitted += len(r.add(key, seq, msg))
            seq += len(msg)
        assert emitted == 50  # every message surfaced; the stream never went blind

    def test_sliding_window_frees_emitted_bytes(self) -> None:
        # With a cap large enough that blindness is not the gate, a long fully-emitted
        # stream must still shrink back to ~nothing — the compaction, not the cap, is
        # what frees the buffer.
        r = DnsTcpReassembler(per_flow_cap=100_000)
        key = ("8.8.8.8", 53, "192.168.1.50", 40000)
        msg = self._prefixed("q.example.com")
        seq = 0
        for _ in range(200):  # ~20 KB, all emitted, none of it should be retained
            r.add(key, seq, msg)
            seq += len(msg)
        assert r._total < 2 * len(msg)  # only the (empty) tail is held, not cumulative

    def test_partial_trailing_message_retained_after_earlier_emit(self) -> None:
        # Compacting away a completed message must not disturb the in-flight partial
        # message that follows it.
        r = DnsTcpReassembler(per_flow_cap=4096)
        key = ("8.8.8.8", 53, "192.168.1.50", 40000)
        m1 = self._prefixed("first.example.com")
        m2 = self._prefixed("second.example.com")
        seq = 0
        assert len(r.add(key, seq, m1)) == 1  # first message emits and is compacted
        seq += len(m1)
        assert r.add(key, seq, m2[:20]) == []  # partial second message: retained
        bodies = r.add(key, seq + 20, m2[20:])  # completes across the compaction
        assert len(bodies) == 1
        assert bodies[0] == m2[2:]

    def test_overlapping_out_of_order_segment_does_not_corrupt_window(self) -> None:
        # A stale/overlapping segment straddling a completing message's end must not
        # collide into the compacted buffer and block the next message — the classic
        # TCP-segment-reordering evasion, on-topic for a leak monitor.
        r = DnsTcpReassembler(per_flow_cap=8192)
        key = ("8.8.8.8", 53, "192.168.1.50", 40000)
        m1 = self._prefixed("first.example.com")
        m2 = self._prefixed("second.example.com")
        split = len(m1) - 8
        assert r.add(key, 0, m1[:split]) == []  # first part of m1
        r.add(key, len(m1) - 3, b"\xbb" * 10)  # junk straddling m1's end, out of order
        bodies = r.add(key, split, m1[split:])  # bridge the gap -> m1 completes whole
        assert len(bodies) == 1
        assert bodies[0] == m1[2:]  # the real m1 body, not junk
        b2 = r.add(key, len(m1), m2)  # the next message must still be accepted
        assert len(b2) == 1
        assert b2[0] == m2[2:]

    def test_default_cap_holds_a_max_size_message(self) -> None:
        # The largest length-prefixed DNS/TCP message is 2 + 65535 bytes; the default
        # per-flow cap must hold one, or that message alone would stall the window.
        assert DnsTcpReassembler().per_flow_cap >= 2 + 0xFFFF

    def test_non_dns_stream_is_not_tracked(self) -> None:
        r = DnsTcpReassembler()
        key = ("192.168.1.50", 51000, "93.184.216.34", 443)
        assert r.add(key, 0, b"\x16\x03\x01\x00\x05\x01 tls handshake bytes") == []
        assert not r.tracks(key)

    def test_total_cap_evicts_oldest_not_all(self) -> None:
        # Over the byte cap evicts the least-recently-updated stream, not every
        # in-flight one, so a burst ages out idle streams instead of dropping them all.
        r = DnsTcpReassembler(per_flow_cap=25, total_cap=40)
        a = self._prefixed("a.example.com")
        old, new = ("a", 1, "b", 2), ("c", 3, "d", 4)
        r.add(old, 0, a[:20])
        r.add(new, 0, a[:25])  # total 45 > 40 -> evict the oldest, keep the newest
        assert old not in r._flows
        assert new in r._flows
        assert r.cleared == 1
        assert r._total == r._flows[new].size

    def test_process_reassembles_tcp_dns_answer_across_segments(self) -> None:
        proc = local_processor("192.168.1.50")
        msg = DNS(
            qr=1,
            qd=DNSQR(qname="big.example.com"),
            an=DNSRR(rrname="big.example.com", type="A", ttl=300, rdata="93.184.216.34"),
        )
        seg1, seg2 = dns_tcp_segments(msg, split_at=20)
        first = [e for e in proc.process(seg1) if isinstance(e, DnsAnswerEvent)]
        second = [e for e in proc.process(seg2) if isinstance(e, DnsAnswerEvent)]
        assert first == []
        assert len(second) == 1
        assert second[0].value == "93.184.216.34"
        assert proc.names.lookup("93.184.216.34") == "big.example.com"

    def test_process_single_segment_tcp_dns_still_parses(self) -> None:
        proc = local_processor("192.168.1.50")
        msg = DNS(
            qr=1,
            qd=DNSQR(qname="whole.example.com"),
            an=DNSRR(rrname="whole.example.com", type="A", ttl=300, rdata="1.2.3.4"),
        )
        full = (
            Ether()
            / IP(src="8.8.8.8", dst="192.168.1.50")
            / TCP(sport=53, dport=40000, flags="PA", seq=5000)
            / msg
        )
        full = Ether(bytes(full))
        full.time = PKT_TIME
        answers = [e for e in proc.process(full) if isinstance(e, DnsAnswerEvent)]
        assert len(answers) == 1
        assert answers[0].value == "1.2.3.4"

    def test_dns_tcp_eviction_surfaces_in_coverage(self) -> None:
        proc = local_processor("192.168.1.50")
        proc.dns_tcp = DnsTcpReassembler(per_flow_cap=30, total_cap=40)
        proc.dns_tcp.add(("a", 1, "b", 2), 0, (b"\x00\x30" + b"\x00" * 20))
        proc.dns_tcp.add(("c", 3, "d", 4), 0, (b"\x00\x30" + b"\x00" * 25))
        assert proc.summary()["coverage"]["evicted"]["dns_tcp_streams"] == 1


class TestDnsNonStandardPorts:
    def test_query_on_nonstandard_port_parsed_like_53(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = dns_query_pkt("forwarder.test", dport=5300)
        queries = [e for e in proc.process(pkt) if isinstance(e, DnsQueryEvent)]
        assert len(queries) == 1
        assert queries[0].qname == "forwarder.test"

    def test_response_on_nonstandard_port_parsed(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = (
            Ether()
            / IP(src="127.0.0.1", dst="192.168.1.50")
            / UDP(sport=5335, dport=50000)
            / DNS(
                qr=1,
                qd=DNSQR(qname="split.test"),
                an=DNSRR(rrname="split.test", type="A", ttl=60, rdata="10.1.2.3"),
            )
        )
        pkt = Ether(bytes(pkt))
        pkt.time = PKT_TIME
        answers = [e for e in proc.process(pkt) if isinstance(e, DnsAnswerEvent)]
        assert len(answers) == 1
        assert answers[0].value == "10.1.2.3"

    def test_recognition_survives_reparse_without_port_binding(self) -> None:
        # Guard: the packet must NOT auto-bind DNS on the custom port, so this
        # exercises shape-based recognition rather than scapy's port table.
        pkt = dns_query_pkt("forwarder.test", dport=5300)
        assert not pkt.haslayer(DNS)

    def test_port_53_unchanged(self) -> None:
        proc = local_processor("192.168.1.50")
        queries = [
            e
            for e in proc.process(dns_query_pkt("std.test", dport=53))
            if isinstance(e, DnsQueryEvent)
        ]
        assert len(queries) == 1
        assert queries[0].qname == "std.test"

    def test_non_dns_udp_not_misparsed_as_dns(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = (
            Ether()
            / IP(src="192.168.1.50", dst="93.184.216.34")
            / UDP(sport=50000, dport=5300)
            / b"GET / HTTP/1.1\r\nHost: x.example\r\n\r\n"
        )
        pkt.time = PKT_TIME
        events = proc.process(pkt)
        assert [e for e in events if isinstance(e, DnsQueryEvent | DnsAnswerEvent)] == []
        assert any(isinstance(e, FlowEvent) for e in events)


class TestDnsTcpVsTlsRouting:
    def test_client_stream_start_rejects_dns_tcp_length_prefix(self) -> None:
        # A DNS/TCP message whose framed length high byte is 0x16 and whose DNS
        # flags2 byte is 0x01 (rcode FORMERR) must NOT be mistaken for a TLS
        # ClientHello — the TLS version byte (0x03) is the discriminator.
        dns_tcp_like = b"\x16\x00" + b"\x00\x00" + b"\x00" + b"\x01" + b"\x00" * 20
        assert _client_stream_start(dns_tcp_like) is StreamStart.REJECTED
        opens = _client_stream_start(b"\x16\x03\x01\x00\x19\x01" + b"\x00" * 20)
        assert opens is StreamStart.OPENS

    def _formerr_body_in_0x16_band(self) -> bytes:
        for pad in range(5560, 5920):
            body = bytes(
                DNS(
                    qr=1,
                    rcode=1,
                    qd=DNSQR(qname="big.example.com"),
                    an=DNSRR(rrname="big.example.com", type="TXT", ttl=60, rdata="x" * pad),
                )
            )
            if 0x1600 <= len(body) <= 0x16FF and body[3] == 0x01:
                return body
        raise AssertionError("could not size a DNS body into the 0x16xx length band")

    def test_dns_tcp_response_with_0x16_length_prefix_is_not_dropped(self) -> None:
        proc = local_processor("192.168.1.50")
        body = self._formerr_body_in_0x16_band()
        framed = len(body).to_bytes(2, "big") + body
        assert framed[0] == 0x16 and framed[5] == 0x01  # the exact collision
        first, second = framed[:3000], framed[3000:]
        seg1 = (
            Ether()
            / IP(src="8.8.8.8", dst="192.168.1.50")
            / TCP(sport=53, dport=40000, flags="A", seq=7000)
            / first
        )
        seg2 = (
            Ether()
            / IP(src="8.8.8.8", dst="192.168.1.50")
            / TCP(sport=53, dport=40000, flags="PA", seq=7000 + 3000)
            / second
        )
        seg1.time = seg2.time = PKT_TIME
        proc.process(seg1)
        answers = [e for e in proc.process(seg2) if isinstance(e, DnsAnswerEvent)]
        assert len(answers) == 1
        assert answers[0].rtype == "TXT"

    def test_tls_tracked_flow_keeps_continuation_that_looks_like_dns(self) -> None:
        # Once the TLS reassembler owns a flow, a continuation segment that happens to
        # begin like a DNS-over-TCP length prefix (a multi-record ClientHello whose
        # second record starts 0x16 0x03) must stay on the TLS path, not be re-routed
        # to the DNS reassembler and lose the SNI.
        proc = local_processor("192.168.1.50")
        payload = two_record_client_hello(b"boundary.example.com", alpn_extension(b"h2"))
        first, second = payload[:16389], payload[16389:]  # split exactly at the record edge
        assert _client_stream_start(first) is StreamStart.OPENS
        assert _client_stream_start(second) is StreamStart.REJECTED
        assert _dns_tcp_start(second)  # the collision that used to misroute it
        proc.process(tcp_segment(first, flags="A", seq=BASE_SEQ))
        done = proc.process(tcp_segment(second, flags="PA", seq=BASE_SEQ + len(first)))
        sni = [e for e in done if isinstance(e, TlsSniEvent)]
        assert len(sni) == 1
        assert sni[0].sni == "boundary.example.com"


TS = "2025-07-02T23:46:40.123+00:00"


def q(name: str = "example.com", dst: str = "10.0.0.1") -> DnsQueryEvent:
    return DnsQueryEvent(ts=TS, src="10.0.0.5", dst=dst, transport="udp", qname=name, qtype="A")


class _Clock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class TestRateBucketer:
    def test_counts_per_second_and_windows(self) -> None:
        r = RateBucketer(window=60)
        r.tick(1000.0)
        r.tick(1000.4)
        r.tick(1001.0)
        assert r.series(1001.0)[-1] == 1.0
        assert r.series(1001.0)[-2] == 2.0
        assert len(r.series(1001.0)) == 60

    def test_old_buckets_trimmed_beyond_window(self) -> None:
        r = RateBucketer(window=60)
        r.tick(1000.0)
        r.tick(2000.0)
        series = r.series(2000.0)
        assert series[-1] == 1.0
        assert sum(series) == 1.0  # the 1000.0 bucket aged out


class TestDashboardModelRing:
    def test_ring_caps_and_drops_oldest(self) -> None:
        m = DashboardModel(cap=10)
        for i in range(15):
            m.add_event(q(f"h{i}"))
        assert len(m.recent(1000)) == 10
        # the first 5 keys (seq 0..4) were evicted
        assert m.event_by_key("0") is None
        assert m.event_by_key("14") is not None

    def test_drain_new_returns_deltas_then_resets(self) -> None:
        m = DashboardModel(cap=100)
        m.add_event(q("a"))
        m.add_event(q("b"))
        added, evicted = m.drain_new()
        assert [k for k, _ in added] == ["0", "1"]
        assert evicted == []
        m.add_event(q("c"))
        added2, _ = m.drain_new()
        assert [k for k, _ in added2] == ["2"]

    def test_drain_reports_evicted_keys(self) -> None:
        m = DashboardModel(cap=2)
        for i in range(4):
            m.add_event(q(f"h{i}"))
        _, evicted = m.drain_new()
        assert evicted == ["0", "1"]

    def test_rate_series_uses_injected_clock(self) -> None:
        clk = _Clock(1000.0)
        m = DashboardModel(clock=clk)
        m.add_event(q("a"))
        m.add_event(q("b"))
        m.add_event(q("c"))
        clk.t = 1001.0
        m.add_event(q("d"))
        m.add_event(q("e"))
        series = m.rate_series()
        assert series[-1] == 2.0
        assert series[-2] == 3.0


def sni_to(host: str, dst: str = "1.2.3.4") -> TlsSniEvent:
    return TlsSniEvent(ts=TS, src="10.0.0.5", dst=dst, dport=443, sni=host)


class TestEventFilter:
    def test_default_passes_every_kind(self) -> None:
        f = EventFilter()
        assert all(f.matches(e) for e in sample_events())
        assert f.is_unconstrained()
        assert f.label() == "all"

    def test_or_within_a_dimension(self) -> None:
        f = EventFilter(kinds=frozenset({"dns_query", "tls_sni"}))
        assert f.matches(q("x")) and f.matches(sni_to("github.com"))
        assert not f.matches(
            HttpEvent(ts=TS, src="10.0.0.5", dst="1.2.3.4", dport=80, method="GET", path="/")
        )

    def test_and_across_dimensions(self) -> None:
        # An internet-bound SNI is excluded by a LAN-only scope even though its kind passes.
        f = EventFilter(kinds=frozenset({"tls_sni"}), scopes=frozenset({"lan"}))
        assert not f.matches(sni_to("github.com", dst="93.184.216.34"))
        assert f.matches(sni_to("nas.local", dst="192.168.1.9"))

    def test_scope_now_reaches_kinds_that_never_carried_one(self) -> None:
        # The whole point of the total projections: "show me only what left my network" must
        # include the DNS query and the SNI, which ARE the disclosure — not just the flow.
        f = EventFilter(scopes=frozenset({"internet"}))
        assert f.matches(q("x", dst="8.8.8.8"))
        assert not f.matches(q("x", dst="192.168.1.1"))

    def test_an_empty_dimension_passes_nothing(self) -> None:
        # "I ticked zero kinds" means zero kinds. Silently reinterpreting it as "all" would be
        # the tool overruling the operator, and the empty feed is signposted instead.
        f = EventFilter(kinds=frozenset())
        assert not any(f.matches(e) for e in sample_events())
        assert not f.is_unconstrained()

    def test_host_substring_is_case_insensitive_and_empty_matches_all(self) -> None:
        assert EventFilter(host="GITHUB").matches(sni_to("api.github.com"))
        assert EventFilter(host="").matches(q("x"))

    def test_label_names_what_is_hidden(self) -> None:
        f = EventFilter(kinds=frozenset({"tls_sni"}), scopes=frozenset({"internet"}))
        assert f.label() == "kind 1/12 · scope 1/6"


class TestDashboardModelFilter:
    def test_no_filter_passes_all(self) -> None:
        m = DashboardModel()
        assert m.passes(q("x")) is True

    def test_filter_selects_kinds(self) -> None:
        m = DashboardModel()
        m.filter = EventFilter(kinds=frozenset({"tls_sni"}))
        assert m.passes(sni_to("github.com")) is True
        assert m.passes(q("x")) is False

    def test_filter_never_drops_from_ring(self) -> None:
        m = DashboardModel(cap=100)
        m.filter = EventFilter(kinds=frozenset({"http"}))
        m.add_event(q("a"))  # filter is a view; the ring keeps everything
        assert len(m.recent(1000)) == 1


class TestEventDirection:
    def test_query_is_outbound(self) -> None:
        assert event_direction(q("x")) == "→"

    def test_answer_is_inbound(self) -> None:
        a = DnsAnswerEvent(
            ts=TS, resolver="10.0.0.1", qname="x", rtype="A", value="1.2.3.4", ttl=60
        )
        assert event_direction(a) == "←"

    def test_flow_uses_its_direction(self) -> None:
        def flow(direction: str) -> FlowEvent:
            return FlowEvent(
                ts=TS,
                proto="tcp",
                direction=direction,
                scope="internet",
                birth="observed",
                local_ip="10.0.0.5",
                local_port=51000,
                remote_ip="1.2.3.4",
                remote_port=443,
                service="https",
                hostname="github.com",
            )

        assert event_direction(flow("outbound")) == "→"
        assert event_direction(flow("inbound")) == "←"
        assert event_direction(flow("transit")) == "↔"
        assert event_direction(flow("local")) == "·"

    def test_arp_is_link_local_glyph(self) -> None:
        arp = ArpEvent(
            ts=TS,
            op="who-has",
            sender_ip="10.0.0.5",
            sender_mac="aa:bb:cc:dd:ee:ff",
            target_ip="10.0.0.1",
        )
        assert event_direction(arp) == "·"


class TestIso:
    def test_defaults_to_utc_under_conftest(self) -> None:
        # The suite is pinned to UTC (conftest), so iso() renders the UTC fixture value.
        assert iso(PKT_TIME) == EXPECTED_ISO

    def test_renders_local_time_with_offset(self) -> None:
        # netmon stamps events in the host's local zone: in +08:00, 23:46:40.123 UTC is
        # 07:46:40.123 the next day carrying a +08:00 offset.
        os.environ["TZ"] = "Asia/Shanghai"  # UTC+8, no DST
        time.tzset()
        assert iso(PKT_TIME) == "2025-07-03T07:46:40.123+08:00"

    def test_log_line_timestamp_is_local_with_offset(self) -> None:
        # structlog lines carry the same local-with-offset stamp as event ts.
        os.environ["TZ"] = "Asia/Shanghai"
        time.tzset()
        buf = io.StringIO()
        configure_logging(stream=buf)
        try:
            structlog.get_logger().info("capture_started", iface="eth0")
            line = json.loads(buf.getvalue())
        finally:
            configure_logging()
        assert line["event"] == "capture_started"
        assert line["timestamp"].endswith("+08:00")


def hostile_http() -> HttpEvent:
    return HttpEvent(
        ts=TS,
        src="10.0.0.5",
        dst="1.2.3.4",
        dport=80,
        method="GET",
        path="/a\x1b[2Jb\x00c",
        host="x.example",
        user_agent="curl\n  sni: bank.example.com",
    )


class TestPrintable:
    def test_control_bytes_become_visible_pictures(self) -> None:
        assert printable("a\x1b[31mb\x00") == "a␛[31mb␀"

    def test_no_control_byte_survives(self) -> None:
        scrubbed = printable("".join(chr(c) for c in range(0x20)) + "\x7f")
        assert not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in scrubbed)

    def test_a_wire_newline_cannot_forge_a_line(self) -> None:
        # The reason printable() has no newline exemption and is applied to leaf fields
        # only: a \n in a User-Agent must not write a line of its own into the detail
        # pane, or into what `y` puts on the operator's clipboard.
        assert "\n" not in printable("curl\n  sni: bank.example.com")

    def test_bidi_override_is_neutralised(self) -> None:
        # U+202E renders moc.live.knab as bank.evil.com — hostname spoofing inside a tool
        # whose entire job is naming the host that was contacted.
        assert "‮" not in printable("moc.live.knab‮")

    @pytest.mark.parametrize(
        "text", ["[2001:db8::1]:443", "/search?q=a[0]", "héllo.example.com", "�"]
    )
    def test_legitimate_text_survives_unchanged(self, text: str) -> None:
        # Brackets are legal in an IPv6 Host header and an HTTP path, and U+FFFD is the
        # parser's honest mark of an undecodable byte. None of it may be mangled.
        assert printable(text) == text

    def test_length_is_preserved(self) -> None:
        # One char in, one char out — so the DataTable's column widths are untouched.
        text = "a\x1b[2Jb\x00c‮d"
        assert len(printable(text)) == len(text)

    def test_event_to_cells_scrubs_wire_text(self) -> None:
        # Rich and Textual strip only BEL/BS/VT/FF/CR, so a Text-wrapped cell still
        # carries an ESC to the terminal. The cell projection is where that stops.
        cells = "".join(event_to_cells(hostile_http()))
        assert "\x1b" not in cells
        assert "\x00" not in cells

    def test_event_to_detail_scrubs_every_field(self) -> None:
        detail = event_to_detail(hostile_http())
        assert "\x1b" not in detail
        assert "\x00" not in detail

    def test_a_wire_newline_cannot_forge_a_detail_line(self) -> None:
        # The User-Agent tries to write "  sni: bank.example.com" as a line of its own — a
        # field this event never carried. It stays inside the user_agent line, visibly.
        detail = event_to_detail(hostile_http())
        assert "  sni: bank.example.com" not in detail.splitlines()
        assert "␊  sni: bank.example.com" in detail

    def test_event_to_detail_keeps_one_line_per_field(self) -> None:
        event = hostile_http()
        fields = len(event.model_dump(exclude_none=True)) - 2  # kind and ts share line one
        assert event_to_detail(event).count("\n") == fields


class TestEventToCells:
    def test_five_columns_and_time_slice(self) -> None:
        cells = event_to_cells(q("example.com"))  # q() carries the UTC TS literal
        assert len(cells) == 5
        assert cells[0] == "23:46:40.123"
        assert cells[1] == "dns_query"
        assert cells[3] == "example.com"

    def test_ech_only_sni_shows_cover_marker(self) -> None:
        sni = TlsSniEvent(ts=TS, src="10.0.0.5", dst="1.2.3.4", dport=443, sni="", ech=True)
        assert event_host(sni) == "(ech)"

    def test_inbound_flow_host_is_hostname_then_ip(self) -> None:
        named = FlowEvent(
            ts=TS,
            proto="tcp",
            direction="inbound",
            scope="internet",
            birth="pre-existing",
            local_ip="10.0.0.5",
            local_port=443,
            remote_ip="1.2.3.4",
            remote_port=51000,
            service="https",
            hostname="github.com",
        )
        anon = named.model_copy(update={"hostname": None})
        assert event_host(named) == "github.com"
        assert event_host(anon) == "1.2.3.4"

    def test_http_detail_has_method_and_path(self) -> None:
        h = HttpEvent(
            ts=TS,
            src="10.0.0.5",
            dst="1.2.3.4",
            dport=80,
            method="GET",
            host="neverssl.com",
            path="/",
            user_agent="curl",
        )
        assert event_detail(h) == "GET /"

    def test_every_event_kind_renders_without_error(self) -> None:
        for e in sample_events():
            cells = event_to_cells(e)
            assert len(cells) == 5
            assert all(isinstance(c, str) for c in cells)


class TestKindStyle:
    def test_every_emitted_kind_has_a_color(self) -> None:
        assert set(KIND_TO_FILE) <= set(KIND_STYLE)


class TestSampleEvents:
    def test_covers_every_emitted_kind(self) -> None:
        # The guard on the guard: the totality tests below are only as good as this list.
        assert {e.kind for e in sample_events()} == set(KIND_TO_FILE)


class TestEventProjectionsAreTotal:
    # scope and direction used to exist only on FlowEvent, so `query --scope internet`
    # silently matched flows alone -- even though the DNS query and the SNI *are* the
    # disclosure. These projections are total over every kind, and this is the drift guard
    # that keeps them that way when a thirteenth kind is added.
    def test_every_kind_has_a_peer_address(self) -> None:
        for e in sample_events():
            assert event_remote_addr(e), f"{e.kind} has no peer address"

    def test_every_kind_has_a_scope_from_the_vocabulary(self) -> None:
        for e in sample_events():
            assert event_scope(e) in SCOPE_VALUES, f"{e.kind} -> {event_scope(e)}"

    def test_every_kind_has_a_direction_from_the_vocabulary(self) -> None:
        for e in sample_events():
            assert event_direction_name(e) in DIRECTION_VALUES, f"{e.kind}"

    def test_kind_vocabulary_is_derived_from_the_file_map(self) -> None:
        assert set(KIND_VALUES) == set(KIND_TO_FILE)


class TestEventScope:
    def test_dns_query_to_a_public_resolver_is_internet(self) -> None:
        assert event_scope(q("x", dst="8.8.8.8")) == "internet"

    def test_dns_query_to_the_router_is_lan(self) -> None:
        assert event_scope(q("x", dst="192.168.1.1")) == "lan"

    def test_llmnr_is_multicast(self) -> None:
        e = LlmnrEvent(ts=TS, src="10.0.0.5", dst="224.0.0.252", qname="wpad", qtype="A")
        assert event_scope(e) == "multicast"

    def test_router_advertisement_is_link_local(self) -> None:
        e = Icmp6RaEvent(ts=TS, router="fe80::1")
        assert event_scope(e) == "linklocal"

    def test_a_recorded_flow_scope_agrees_with_the_derived_one(
        self, processor: PacketProcessor
    ) -> None:
        # remote_scope() is the one authority: a flow's recorded scope IS remote_scope of its
        # remote_ip by construction, so deriving instead of reading the field cannot disagree.
        # If this ever fails, the two authorities have forked and the filter is lying.
        flow = single_flow(processor.process(make_syn("192.168.1.50", "93.184.216.34", 4000, 443)))
        assert event_scope(flow) == flow.scope == "internet"


class TestRenderHelpersAcrossModuleCopies:
    # Running `netmon.py` as a script makes its Event classes `__main__.*`, while
    # netmon_tui imports the `netmon.*` copies — so class-identity dispatch (isinstance
    # / case ClassName()) silently misses every event and blanks HOST/DETAIL in the TUI.
    # Loading a second module copy reproduces that split; the helpers must dispatch on
    # .kind and keep working.
    def _alt_module(self) -> Any:
        import importlib.util

        import netmon

        spec = importlib.util.spec_from_file_location("netmon_altcopy", netmon.__file__)
        assert spec is not None and spec.loader is not None
        alt = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(alt)
        return alt

    def test_host_detail_direction_survive_foreign_event_classes(self) -> None:
        import netmon

        alt = self._alt_module()
        http = alt.HttpEvent(
            ts=TS,
            src="127.0.0.1",
            dst="127.0.0.1",
            dport=43383,
            method="GET",
            host="127.0.0.1:43383",
            path="/rest/system/error",
            user_agent=None,
        )
        flow = alt.FlowEvent(
            ts=TS,
            proto="tcp",
            direction="outbound",
            scope="internet",
            birth="observed",
            local_ip="127.0.0.1",
            local_port=1,
            remote_ip="160.79.104.10",
            remote_port=443,
            service="https",
            hostname="github.com",
        )
        assert not isinstance(http, netmon.HttpEvent)  # genuinely a different class object
        assert event_host(http) == "127.0.0.1:43383"
        assert event_detail(http) == "GET /rest/system/error"
        assert event_direction(flow) == "→"  # not the "·" fallback
        assert event_host(flow) == "github.com"
        assert event_to_cells(http)[3:] == ["127.0.0.1:43383", "GET /rest/system/error"]

    def test_classification_projections_survive_foreign_event_classes(self) -> None:
        # The filter and `query` are built on these three, so a class-identity dispatch here
        # would silently pass every event through every filter — the failure would look like
        # a filter that does nothing, not like a crash.
        alt = self._alt_module()
        sni = alt.TlsSniEvent(ts=TS, src="10.0.0.5", dst="93.184.216.34", dport=443, sni="e.com")
        assert event_remote_addr(sni) == "93.184.216.34"
        assert event_scope(sni) == "internet"
        assert event_direction_name(sni) == "outbound"


class TestRunTuiMode:
    async def test_tui_replay_writes_summary_jsonl_and_redirects_log(self, tmp_path: Path) -> None:
        pytest.importorskip("textual")
        pcap = tmp_path / "replay.pcap"
        write_replay_pcap(pcap)
        args = argparse.Namespace(
            read=str(pcap),
            iface=None,
            bpf=None,
            output=str(tmp_path / "logs"),
            quiet=True,
            keep_query=False,
            tui=True,
        )
        await run(args)  # run_dashboard runs headless (no tty), consumes replay, finalizes
        run_dir = next((tmp_path / "logs").iterdir())
        summary = json.loads((run_dir / "summary.json").read_text())
        assert summary["events"]["dns_query"] == 1
        assert summary["events"]["tls_sni"] == 1
        assert (run_dir / "dns.jsonl").exists()
        assert (run_dir / "tls.jsonl").exists()
        # structlog is redirected off stdout into the run dir while the TUI is up
        assert (run_dir / "netmon.log").exists()


class TestCliDispatch:
    def test_run_defaults_to_tui_and_ephemeral(self) -> None:
        args = _parse_run_args([])
        assert args.tui is True
        assert args.headless is False
        assert args.log is False

    def test_run_headless_disables_tui(self) -> None:
        assert _parse_run_args(["--headless"]).tui is False

    def test_run_log_sets_persistence_flag(self) -> None:
        args = _parse_run_args(["--log", "-i", "eth0"])
        assert args.log is True
        assert args.iface == "eth0"

    def test_run_carries_capture_flags(self) -> None:
        args = _parse_run_args(["-r", "x.pcap", "-q", "--bpf", "not port 22", "--keep-query"])
        assert args.read == "x.pcap"
        assert args.quiet is True
        assert args.bpf == "not port 22"
        assert args.keep_query is True

    def test_legacy_form_keeps_tui_flag_without_log(self) -> None:
        args = _legacy_parser().parse_args(["--tui", "-q"])
        assert args.tui is True
        assert not hasattr(args, "log")  # absent log => build_session keeps writing files

    def test_update_subcommand_dispatches_and_propagates_exit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import netmon

        seen: list[list[str]] = []

        def fake_update(a: list[str]) -> int:
            seen.append(a)
            return 3

        monkeypatch.setattr(netmon, "cmd_update", fake_update)
        with pytest.raises(SystemExit) as exc:
            main(["update", "--force"])
        assert exc.value.code == 3
        assert seen == [["--force"]]

    def test_service_subcommand_dispatches(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import netmon

        monkeypatch.setattr(netmon, "cmd_service", lambda a: 0)
        with pytest.raises(SystemExit) as exc:
            main(["service", "status"])
        assert exc.value.code == 0

    def test_run_parser_rejects_unknown_flag(self) -> None:
        with pytest.raises(SystemExit):
            _run_parser().parse_args(["--definitely-not-a-flag"])


def write_query_fixture(run_dir: Path) -> None:
    # A recorded run with a mix of kinds and deliberately-scrambled write order, so a
    # query that returns chronological output proves it sorts rather than echoes files.
    w = JsonlWriter(run_dir)
    w.write(
        FlowEvent(
            ts="2025-07-02T10:00:04.000+00:00",
            proto="tcp",
            direction="inbound",
            # "lan", not "local": remote_scope(192.168.1.1) can only ever return "lan", so a
            # recorded scope of "local" was a value no real run could produce. `local` is a
            # DIRECTION. The old free-string --scope hid the lie; the closed vocabulary does not.
            scope="lan",
            birth="observed",
            local_ip="192.168.1.50",
            local_port=50000,
            remote_ip="192.168.1.1",
            remote_port=445,
            service="microsoft-ds",
            hostname=None,
        )
    )
    w.write(
        DnsQueryEvent(
            ts="2025-07-02T10:00:01.000+00:00",
            src="192.168.1.50",
            dst="8.8.8.8",
            transport="udp",
            qname="alpha.example",
            qtype="A",
        )
    )
    w.write(
        TlsSniEvent(
            ts="2025-07-02T10:00:02.000+00:00",
            src="192.168.1.50",
            dst="93.184.216.34",
            dport=443,
            sni="beta.example",
        )
    )
    w.write(
        FlowEvent(
            ts="2025-07-02T10:00:03.000+00:00",
            proto="tcp",
            direction="outbound",
            scope="internet",
            birth="observed",
            local_ip="192.168.1.50",
            local_port=51000,
            remote_ip="93.184.216.34",
            remote_port=443,
            service="https",
            hostname="beta.example",
        )
    )
    w.close()


def query_lines(capsys: pytest.CaptureFixture[str], *argv: str) -> list[dict[str, object]]:
    with pytest.raises(SystemExit) as exc:
        main(["query", *argv])
    assert exc.value.code == 0
    out = capsys.readouterr().out.strip()
    return [json.loads(line) for line in out.splitlines()] if out else []


class TestNetmonQuery:
    def test_empty_filter_prints_all_events_chronologically(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        run = tmp_path / "run-x"
        write_query_fixture(run)
        rows = query_lines(capsys, str(run))
        assert [r["ts"] for r in rows] == [
            "2025-07-02T10:00:01.000+00:00",
            "2025-07-02T10:00:02.000+00:00",
            "2025-07-02T10:00:03.000+00:00",
            "2025-07-02T10:00:04.000+00:00",
        ]

    def test_kind_filter_selects_one_kind(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        run = tmp_path / "run-x"
        write_query_fixture(run)
        rows = query_lines(capsys, str(run), "--kind", "tls_sni")
        assert [r["kind"] for r in rows] == ["tls_sni"]
        assert rows[0]["sni"] == "beta.example"

    def test_host_substring_matches_sni_qname_and_hostname(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        run = tmp_path / "run-x"
        write_query_fixture(run)
        rows = query_lines(capsys, str(run), "--host", "example")
        # alpha.example (qname), beta.example (sni), beta.example (flow hostname);
        # the local flow's host is 192.168.1.1, which does not match.
        assert {r["kind"] for r in rows} == {"dns_query", "tls_sni", "flow"}
        assert len(rows) == 3

    def test_scope_matches_every_kind_not_just_flows(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Was: flows only, because the predicate read FlowEvent.scope with getattr. "What left
        # my network" has to include the lookup that named the host and the SNI that announced
        # it — those ARE the disclosure. The LAN flow to 192.168.1.1 is correctly excluded.
        run = tmp_path / "run-x"
        write_query_fixture(run)
        rows = query_lines(capsys, str(run), "--scope", "internet")
        assert {r["kind"] for r in rows} == {"dns_query", "tls_sni", "flow"}

    def test_kind_is_repeatable(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        run = tmp_path / "run-x"
        write_query_fixture(run)
        rows = query_lines(capsys, str(run), "--kind", "dns_query", "--kind", "tls_sni")
        assert {r["kind"] for r in rows} == {"dns_query", "tls_sni"}

    def test_direction_filter(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        run = tmp_path / "run-x"
        write_query_fixture(run)
        rows = query_lines(capsys, str(run), "--kind", "flow", "--direction", "inbound")
        assert [r["remote_ip"] for r in rows] == ["192.168.1.1"]

    def test_local_is_rejected_as_a_scope_and_the_choices_are_shown(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # `local` is a direction, not a scope. The old free-string flag accepted it silently
        # and returned whatever happened to match; now the user is told, and told what is valid.
        run = tmp_path / "run-x"
        write_query_fixture(run)
        with pytest.raises(SystemExit) as exc:
            main(["query", str(run), "--scope", "local"])
        assert exc.value.code == 2
        assert "invalid choice" in capsys.readouterr().err

    def test_filters_compose_with_and_semantics(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        run = tmp_path / "run-x"
        write_query_fixture(run)
        rows = query_lines(capsys, str(run), "--kind", "flow", "--host", "beta")
        assert len(rows) == 1
        assert rows[0]["hostname"] == "beta.example"
        assert rows[0]["scope"] == "internet"

    def test_hostname_less_flow_round_trips(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The writer drops None fields (exclude_none), so a flow with no resolved
        # hostname records without the key. query must still read it back, not silently
        # drop it for failing to re-validate a "required" field.
        run = tmp_path / "run-x"
        write_query_fixture(run)
        rows = query_lines(capsys, str(run), "--kind", "flow", "--scope", "lan")
        assert len(rows) == 1
        assert rows[0]["remote_ip"] == "192.168.1.1"
        assert "hostname" not in rows[0]  # stayed absent, did not resurrect as null

    def test_sort_uses_instant_not_lexical_across_offsets(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # An always-on run spanning a DST fall-back records two offsets. The later
        # instant has the smaller wall-clock string, so a lexical sort inverts them;
        # query must order by the parsed instant.
        def flow_at(ts: str, remote_ip: str) -> FlowEvent:
            return FlowEvent(
                ts=ts,
                proto="tcp",
                direction="outbound",
                scope="internet",
                birth="observed",
                local_ip="192.168.1.50",
                local_port=51000,
                remote_ip=remote_ip,
                remote_port=443,
                service="https",
            )

        run = tmp_path / "run-x"
        w = JsonlWriter(run)
        w.write(flow_at("2025-11-02T01:15:00.000-08:00", "1.1.1.1"))
        w.write(flow_at("2025-11-02T01:30:00.000-07:00", "2.2.2.2"))
        w.close()
        rows = query_lines(capsys, str(run))
        assert [r["ts"] for r in rows] == [
            "2025-11-02T01:30:00.000-07:00",  # 08:30Z — the earlier instant, sorted first
            "2025-11-02T01:15:00.000-08:00",  # 09:15Z — later, despite the smaller string
        ]

    def test_zero_event_run_is_recognized_not_rejected(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A completed run that captured nothing still has summary.json; querying it is a
        # valid empty result, not a "not a run directory" error.
        run = tmp_path / "run-x"
        run.mkdir()
        (run / "summary.json").write_text("{}", encoding="utf-8")
        assert query_lines(capsys, str(run)) == []

    def test_event_adapter_covers_every_recorded_kind(self) -> None:
        # Guard against drift: a kind added to KIND_TO_FILE but not the parse union would
        # make query silently drop every record of that kind (validate_json raises, and
        # the read loop swallows it). Mirrors the KIND_STYLE coverage assertion.
        mapping = EVENT_ADAPTER.json_schema()["discriminator"]["mapping"]
        assert set(mapping) == set(KIND_TO_FILE)

    def test_missing_run_dir_fails_cleanly(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["query", str(tmp_path / "does-not-exist")])
        assert exc.value.code == 1
        assert "run direct" in capsys.readouterr().err.lower()

    def test_directory_without_jsonl_fails_cleanly(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        empty = tmp_path / "not-a-run"
        empty.mkdir()
        with pytest.raises(SystemExit) as exc:
            main(["query", str(empty)])
        assert exc.value.code == 1
        assert capsys.readouterr().err  # a clear message, not a silent empty result

    def test_malformed_line_is_skipped_not_fatal(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        run = tmp_path / "run-x"
        write_query_fixture(run)
        with (run / "dns.jsonl").open("a", encoding="utf-8") as f:
            f.write("{ this is not valid json\n")
        rows = query_lines(capsys, str(run))  # must not raise
        assert len(rows) == 4  # the four good events survive; the junk line is dropped


class TestRunPersistence:
    async def test_headless_without_log_writes_nothing(self, tmp_path: Path) -> None:
        pcap = tmp_path / "replay.pcap"
        write_replay_pcap(pcap)
        args = argparse.Namespace(
            read=str(pcap),
            iface=None,
            bpf=None,
            output=str(tmp_path / "logs"),
            quiet=True,
            keep_query=False,
            tui=False,
            log=False,
        )
        await run(args)
        assert not (tmp_path / "logs").exists()  # ephemeral: no run dir, no JSONL

    async def test_tui_without_log_writes_nothing(self, tmp_path: Path) -> None:
        pytest.importorskip("textual")
        pcap = tmp_path / "replay.pcap"
        write_replay_pcap(pcap)
        args = argparse.Namespace(
            read=str(pcap),
            iface=None,
            bpf=None,
            output=str(tmp_path / "logs"),
            quiet=True,
            keep_query=False,
            tui=True,
            log=False,
        )
        await run(args)
        assert not (tmp_path / "logs").exists()

    async def test_tui_with_log_persists_record(self, tmp_path: Path) -> None:
        pytest.importorskip("textual")
        pcap = tmp_path / "replay.pcap"
        write_replay_pcap(pcap)
        args = argparse.Namespace(
            read=str(pcap),
            iface=None,
            bpf=None,
            output=str(tmp_path / "logs"),
            quiet=True,
            keep_query=False,
            tui=True,
            log=True,
        )
        await run(args)
        run_dir = next((tmp_path / "logs").iterdir())
        assert (run_dir / "dns.jsonl").exists()
        assert (run_dir / "netmon.log").exists()
