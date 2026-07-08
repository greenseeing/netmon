import argparse
import io
import json
import os
import random
import struct
import time
from pathlib import Path
from typing import Any

import pytest
import structlog
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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
    ICMPv6EchoRequest,
    ICMPv6ND_RA,
    ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptRDNSS,
    IPv6,
)
from scapy.layers.l2 import ARP, Ether
from scapy.layers.llmnr import LLMNRQuery
from scapy.layers.netbios import NBNSHeader, NBNSQueryRequest
from scapy.packet import Packet
from scapy.utils import wrpcap

from netmon import (
    KIND_STYLE,
    KIND_TO_FILE,
    QUIC_V1,
    QUIC_V2,
    RA_RDNSS_NAME,
    ArpEvent,
    BoundedCounter,
    DashboardModel,
    DnsAnswerEvent,
    DnsEcsEvent,
    DnsHttpsEvent,
    DnsQueryEvent,
    DnsResponseEvent,
    DnsTcpReassembler,
    Event,
    FlowEvent,
    HttpEvent,
    Icmp6RaEvent,
    JsonlWriter,
    LiveCapture,
    LlmnrEvent,
    LruSet,
    NameLedger,
    NbnsEvent,
    PacketProcessor,
    QuicReassembler,
    RateBucketer,
    ReplayCapture,
    TcpReassembler,
    TlsSniEvent,
    _client_stream_start,
    _legacy_parser,
    _parse_run_args,
    _run_parser,
    configure_logging,
    derive_initial_keys,
    event_detail,
    event_direction,
    event_host,
    event_to_cells,
    header_protection_mask,
    iso,
    main,
    packet_nonce,
    parse_client_hello,
    parse_http_request,
    question_list,
    remote_scope,
    run,
)

PKT_TIME = 1751500000.123
EXPECTED_ISO = "2025-07-02T23:46:40.123+00:00"


def sni_extension(name: bytes) -> bytes:
    entry = b"\x00" + struct.pack(">H", len(name)) + name
    server_name_list = struct.pack(">H", len(entry)) + entry
    return struct.pack(">H", 0) + struct.pack(">H", len(server_name_list)) + server_name_list


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
    return hello.sni if hello else None


def single_flow(events: list[Event]) -> FlowEvent:
    (flow,) = events
    assert isinstance(flow, FlowEvent)
    return flow


class TestParseClientHello:
    def test_valid_clienthello_with_grease_before_sni(self) -> None:
        extensions = padding_extension(6) + sni_extension(b"example.com")
        payload = build_client_hello(
            extensions=extensions,
            session_id=b"\xaa" * 4,
            cipher_suites=b"\x00\x2f\x00\x35\xc0\x2b",
        )
        assert sni_of(payload) == "example.com"

    def test_truncated_payload_returns_none(self) -> None:
        extensions = padding_extension(6) + sni_extension(b"example.com")
        payload = build_client_hello(extensions=extensions)
        truncated = payload[:50]
        assert len(truncated) >= 44
        assert parse_client_hello(truncated) is None

    def test_short_payload_below_minimum_length_returns_none(self) -> None:
        assert parse_client_hello(b"\x16\x03\x01\x00\x05\x01") is None

    def test_non_tls_payload_returns_none(self) -> None:
        assert parse_client_hello(b"not a tls record at all, just plain bytes") is None

    def test_non_clienthello_handshake_type_returns_none(self) -> None:
        extensions = sni_extension(b"example.com")
        payload = bytearray(build_client_hello(extensions=extensions))
        payload[5] = 0x02
        assert parse_client_hello(bytes(payload)) is None

    def test_clienthello_with_no_extensions_returns_none(self) -> None:
        payload = build_client_hello(extensions=b"")
        assert len(payload) >= 44
        assert parse_client_hello(payload) is None

    def test_no_ech_extension_leaves_flag_false(self) -> None:
        payload = build_client_hello(extensions=sni_extension(b"example.com"))
        hello = parse_client_hello(payload)
        assert hello is not None
        assert hello.sni == "example.com"
        assert hello.ech is False


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
CH_RECORD_HEADER = b"\x16\x03\x01\x00\x00\x01"  # TLS record + ClientHello handshake type


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

    def test_total_cap_evicts_all_buffers(self) -> None:
        r = TcpReassembler(per_flow_cap=100, total_cap=30)
        r.add(("a", 1, "b", 2), 0, CH_RECORD_HEADER + b"\x00" * 19)
        r.add(("c", 3, "d", 4), 0, CH_RECORD_HEADER + b"\x00" * 19)
        assert r._flows == {}
        assert r._total == 0

    def test_total_cap_clear_counts_wiped_streams(self) -> None:
        r = TcpReassembler(per_flow_cap=100, total_cap=30)
        r.add(("a", 1, "b", 2), 0, CH_RECORD_HEADER + b"\x00" * 19)
        r.add(("c", 3, "d", 4), 0, CH_RECORD_HEADER + b"\x00" * 19)
        assert r.cleared == 2

    def test_drop_removes_buffer_and_reclaims_total(self) -> None:
        r = TcpReassembler()
        key = ("a", 1, "b", 2)
        r.add(key, 0, CH_RECORD_HEADER + b"\x00" * 9)
        r.drop(key)
        assert key not in r._flows
        assert r._total == 0


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
            b"GET /index.html HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: pytest-agent/1.0\r\n"
            b"\r\n"
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
        p = Ether(bytes(Ether() / IP(src="10.0.0.5", dst="10.0.0.1")
                        / UDP(sport=40000, dport=53) / dns_bytes))
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
            bytes(DNS(qr=1, qd=DNSQR(qname="a.com"),
                      an=DNSRR(rrname="a.com", type="A", rdata="1.1.1.1"), ancount=1)),
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
        p = Ether(bytes(Ether() / IP(src="115.55.224.86", dst="192.168.11.32")
                        / UDP(sport=port, dport=port) / payload))
        p.time = PKT_TIME
        return p

    # A BitTorrent DHT find_node datagram (bencode) like the ones in the report.
    _DHT = (b"d1:ad2:id20:" + bytes(range(20)) + b"6:target20:" + bytes(range(20, 40))
            + b"e1:q9:find_node1:t4:abcd1:y1:qe")

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
        proc = PacketProcessor(local_ips=frozenset())
        fwd = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1111, dport=443, flags="S")
        rev = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=443, dport=1111, flags="SA")
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

    def test_first_observation_wins(self) -> None:
        ledger = NameLedger(cap=8)
        ledger.observe("1.2.3.4", "first.example.com")
        ledger.observe("1.2.3.4", "second.example.com")
        assert ledger.lookup("1.2.3.4") == "first.example.com"

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

    def test_scope_multicast_for_ipv4_multicast_target(
        self, processor: PacketProcessor
    ) -> None:
        assert remote_scope("239.255.255.250") == "multicast"

    def test_scope_multicast_for_ipv6_multicast_target(
        self, processor: PacketProcessor
    ) -> None:
        assert remote_scope("ff12::8384") == "multicast"


class TestServiceGuess:
    def test_tcp_443_is_https(self) -> None:
        processor = local_processor("192.168.1.50")
        pkt = make_syn("192.168.1.50", "93.184.216.34", 51000, 443)
        assert single_flow(processor.process(pkt)).service == "https"

    def test_udp_443_is_quic(self) -> None:
        processor = local_processor("192.168.1.50")
        pkt = (
            Ether()
            / IP(src="192.168.1.50", dst="93.184.216.34")
            / UDP(sport=51000, dport=443)
        )
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
        pkt = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(
            sport=51000, dport=443, flags="S"
        )
        pkt.time = PKT_TIME
        flow = single_flow(processor.process(pkt))
        assert flow.local_ip == "2001:db8::1"
        assert flow.remote_ip == "2001:db8::2"
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
            DnsQueryEvent(
                ts=EXPECTED_ISO, src="a", dst="b", transport="udp", qname="x", qtype="A"
            )
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
    syn = Ether() / IP(src="192.168.1.50", dst="93.184.216.34") / TCP(
        sport=51000, dport=443, flags="S"
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
        rrname=qname, type=rtype, ttl=300, svc_priority=priority,
        target_name=target, svc_params=params,
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
            "example.com", alpn=[b"h3", b"h2"], port=443,
            ipv4hint=["192.0.2.1"], ipv6hint=["2001:db8::1"], ech=b"\x00\x01\x02",
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
                ts=EXPECTED_ISO, resolver="8.8.8.8", qname="example.com", rtype="HTTPS",
                priority=1, target="", ttl=300,
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
            e for e in proc.process(self._http_get(b"captive.apple.com"))
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
            e for e in proc.process(self._http_get(b"captive.apple.com:80"))
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
            read=str(pcap), iface=None, bpf=None, output=str(tmp_path / "logs"),
            quiet=True, keep_query=False,
        )
        await run(args)
        run_dir = next((tmp_path / "logs").iterdir())
        summary = json.loads((run_dir / "summary.json").read_text())
        assert summary["capture"]["kernel_dropped"] == "unavailable"
        assert summary["capture"]["userspace_dropped"] == 0
        assert summary["events"]["dns_query"] == 1
        assert summary["events"]["tls_sni"] == 1
        assert (run_dir / "dns.jsonl").exists()


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

    def test_non_ip_frame_marked_non_ip(self) -> None:
        proc = local_processor("192.168.1.50")
        pkt = Ether(type=0x9999) / b"\x00\x01\x02\x03"  # not IP, not ARP
        pkt.time = PKT_TIME
        assert proc.process(pkt) == []
        assert proc.summary()["coverage"]["fate"]["non_ip"] == 1

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
                ts=EXPECTED_ISO, resolver="8.8.8.8", qname="nope.example.com",
                qtype="A", rcode="NXDOMAIN",
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
            Ether()
            / IP(src="8.8.8.8", dst="192.168.1.50")
            / UDP(sport=53, dport=54321)
            / truncated
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
            op=2, psrc="192.168.1.1", hwsrc="11:22:33:44:55:66",
            pdst="192.168.1.50", hwdst="aa:bb:cc:dd:ee:01",
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
            rrname="example.com", type="HTTPS", ttl=300, svc_priority=1,
            target_name=".", svc_params=[SvcParam(key="alpn", value=[b"h3"])],
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
                qr=1, rcode=0, qd=DNSQR(qname="example.com"),
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
                qr=1, rcode=3, qd=DNSQR(qname="sub.example.com"),
                ns=DNSRRSOA(
                    rrname="example.com", type="SOA", ttl=3600,
                    mname="ns1.example.com", rname="hostmaster.example.com",
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
                qr=1, qd=DNSQR(qname="example.com"),
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
    out = []
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
            DNS(qr=1, qd=DNSQR(qname=qname), an=DNSRR(rrname=qname, type="TXT", ttl=60,
                rdata="x" * payload_len))
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

    def test_non_dns_stream_is_not_tracked(self) -> None:
        r = DnsTcpReassembler()
        key = ("192.168.1.50", 51000, "93.184.216.34", 443)
        assert r.add(key, 0, b"\x16\x03\x01\x00\x05\x01 tls handshake bytes") == []
        assert not r.tracks(key)

    def test_total_cap_evicts_and_counts(self) -> None:
        r = DnsTcpReassembler(per_flow_cap=100, total_cap=40)
        a = self._prefixed("a.example.com")
        r.add(("a", 1, "b", 2), 0, a[:20])
        r.add(("c", 3, "d", 4), 0, a[:25])
        assert r._flows == {}
        assert r.cleared == 2

    def test_process_reassembles_tcp_dns_answer_across_segments(self) -> None:
        proc = local_processor("192.168.1.50")
        msg = DNS(
            qr=1, qd=DNSQR(qname="big.example.com"),
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
            qr=1, qd=DNSQR(qname="whole.example.com"),
            an=DNSRR(rrname="whole.example.com", type="A", ttl=300, rdata="1.2.3.4"),
        )
        full = Ether() / IP(src="8.8.8.8", dst="192.168.1.50") / TCP(
            sport=53, dport=40000, flags="PA", seq=5000
        ) / msg
        full = Ether(bytes(full))
        full.time = PKT_TIME
        answers = [e for e in proc.process(full) if isinstance(e, DnsAnswerEvent)]
        assert len(answers) == 1
        assert answers[0].value == "1.2.3.4"

    def test_dns_tcp_eviction_surfaces_in_coverage(self) -> None:
        proc = local_processor("192.168.1.50")
        proc.dns_tcp = DnsTcpReassembler(per_flow_cap=100, total_cap=40)
        proc.dns_tcp.add(("a", 1, "b", 2), 0, (b"\x00\x30" + b"\x00" * 20))
        proc.dns_tcp.add(("c", 3, "d", 4), 0, (b"\x00\x30" + b"\x00" * 25))
        assert proc.summary()["coverage"]["evicted"]["dns_tcp_streams"] == 2


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
            / DNS(qr=1, qd=DNSQR(qname="split.test"),
                  an=DNSRR(rrname="split.test", type="A", ttl=60, rdata="10.1.2.3"))
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
        queries = [e for e in proc.process(dns_query_pkt("std.test", dport=53))
                   if isinstance(e, DnsQueryEvent)]
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
        assert _client_stream_start(dns_tcp_like) is False
        assert _client_stream_start(b"\x16\x03\x01\x00\x05\x01" + b"\x00" * 20) is True

    def _formerr_body_in_0x16_band(self) -> bytes:
        for pad in range(5560, 5920):
            body = bytes(
                DNS(qr=1, rcode=1, qd=DNSQR(qname="big.example.com"),
                    an=DNSRR(rrname="big.example.com", type="TXT", ttl=60, rdata="x" * pad))
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
        seg1 = Ether() / IP(src="8.8.8.8", dst="192.168.1.50") / TCP(
            sport=53, dport=40000, flags="A", seq=7000) / first
        seg2 = Ether() / IP(src="8.8.8.8", dst="192.168.1.50") / TCP(
            sport=53, dport=40000, flags="PA", seq=7000 + 3000) / second
        seg1.time = seg2.time = PKT_TIME
        proc.process(seg1)
        answers = [e for e in proc.process(seg2) if isinstance(e, DnsAnswerEvent)]
        assert len(answers) == 1
        assert answers[0].rtype == "TXT"


TS = "2025-07-02T23:46:40.123+00:00"


def q(name: str = "example.com") -> DnsQueryEvent:
    return DnsQueryEvent(
        ts=TS, src="10.0.0.5", dst="10.0.0.1", transport="udp", qname=name, qtype="A"
    )


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


class TestDashboardModelFilter:
    def test_no_filter_passes_all(self) -> None:
        m = DashboardModel()
        assert m.passes(q("x")) is True

    def test_filter_matches_kind(self) -> None:
        m = DashboardModel()
        m.filter = "tls"
        sni = TlsSniEvent(ts=TS, src="10.0.0.5", dst="1.2.3.4", dport=443, sni="github.com")
        assert m.passes(sni) is True
        assert m.passes(q("x")) is False

    def test_filter_matches_host_substring(self) -> None:
        m = DashboardModel()
        m.filter = "github"
        sni = TlsSniEvent(ts=TS, src="10.0.0.5", dst="1.2.3.4", dport=443, sni="api.github.com")
        assert m.passes(sni) is True

    def test_filter_never_drops_from_ring(self) -> None:
        m = DashboardModel(cap=100)
        m.filter = "nomatch"
        m.add_event(q("a"))  # filter is a view; ring keeps everything
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
                ts=TS, proto="tcp", direction=direction, scope="internet", birth="observed",
                local_ip="10.0.0.5", local_port=51000, remote_ip="1.2.3.4", remote_port=443,
                service="https", hostname="github.com",
            )
        assert event_direction(flow("outbound")) == "→"
        assert event_direction(flow("inbound")) == "←"
        assert event_direction(flow("transit")) == "↔"

    def test_arp_is_link_local_glyph(self) -> None:
        arp = ArpEvent(
            ts=TS, op="who-has", sender_ip="10.0.0.5",
            sender_mac="aa:bb:cc:dd:ee:ff", target_ip="10.0.0.1",
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
            ts=TS, proto="tcp", direction="inbound", scope="internet", birth="pre-existing",
            local_ip="10.0.0.5", local_port=443, remote_ip="1.2.3.4", remote_port=51000,
            service="https", hostname="github.com",
        )
        anon = named.model_copy(update={"hostname": None})
        assert event_host(named) == "github.com"
        assert event_host(anon) == "1.2.3.4"

    def test_http_detail_has_method_and_path(self) -> None:
        h = HttpEvent(
            ts=TS, src="10.0.0.5", dst="1.2.3.4", dport=80, method="GET",
            host="neverssl.com", path="/", user_agent="curl",
        )
        assert event_detail(h) == "GET /"

    def test_every_event_kind_renders_without_error(self) -> None:
        samples = [
            q("x"),
            DnsAnswerEvent(
                ts=TS, resolver="10.0.0.1", qname="x", rtype="A", value="1.2.3.4", ttl=60
            ),
            DnsResponseEvent(ts=TS, resolver="10.0.0.1", qname="x", qtype="A", rcode="NXDOMAIN"),
            DnsHttpsEvent(
                ts=TS, resolver="10.0.0.1", qname="x", rtype="HTTPS", priority=1,
                target=".", alpn=["h3"], ech=True, ttl=60,
            ),
            DnsEcsEvent(
                ts=TS, src="10.0.0.5", dst="10.0.0.1", qname="x", client_subnet="1.2.3.0/24"
            ),
            TlsSniEvent(
                ts=TS, src="10.0.0.5", dst="1.2.3.4", dport=443, sni="github.com", alpn=["h2"]
            ),
            HttpEvent(
                ts=TS, src="10.0.0.5", dst="1.2.3.4", dport=80, method="GET",
                host="x", path="/", user_agent=None,
            ),
            FlowEvent(
                ts=TS, proto="udp", direction="outbound", scope="lan", birth="datagram",
                local_ip="10.0.0.5", local_port=5353, remote_ip="224.0.0.251",
                remote_port=5353, service="mdns", hostname=None,
            ),
            ArpEvent(
                ts=TS, op="who-has", sender_ip="10.0.0.5",
                sender_mac="aa:bb:cc:dd:ee:ff", target_ip="10.0.0.1",
            ),
            Icmp6RaEvent(
                ts=TS, router="fe80::1", prefixes=["2001:db8::/64"], rdnss=["2001:db8::1"]
            ),
            LlmnrEvent(ts=TS, src="10.0.0.5", dst="224.0.0.252", qname="wpad", qtype="A"),
            NbnsEvent(ts=TS, src="10.0.0.5", dst="10.0.0.255", qname="WORKGROUP"),
        ]
        seen = {e.kind for e in samples}
        assert seen == set(KIND_TO_FILE)  # one sample per emitted kind
        for e in samples:
            cells = event_to_cells(e)
            assert len(cells) == 5
            assert all(isinstance(c, str) for c in cells)


class TestKindStyle:
    def test_every_emitted_kind_has_a_color(self) -> None:
        assert set(KIND_TO_FILE) <= set(KIND_STYLE)


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
            ts=TS, src="127.0.0.1", dst="127.0.0.1", dport=43383, method="GET",
            host="127.0.0.1:43383", path="/rest/system/error", user_agent=None,
        )
        flow = alt.FlowEvent(
            ts=TS, proto="tcp", direction="outbound", scope="internet", birth="observed",
            local_ip="127.0.0.1", local_port=1, remote_ip="160.79.104.10", remote_port=443,
            service="https", hostname="github.com",
        )
        assert not isinstance(http, netmon.HttpEvent)  # genuinely a different class object
        assert event_host(http) == "127.0.0.1:43383"
        assert event_detail(http) == "GET /rest/system/error"
        assert event_direction(flow) == "→"  # not the "·" fallback
        assert event_host(flow) == "github.com"
        assert event_to_cells(http)[3:] == ["127.0.0.1:43383", "GET /rest/system/error"]


class TestRunTuiMode:
    async def test_tui_replay_writes_summary_jsonl_and_redirects_log(self, tmp_path: Path) -> None:
        pytest.importorskip("textual")
        pcap = tmp_path / "replay.pcap"
        write_replay_pcap(pcap)
        args = argparse.Namespace(
            read=str(pcap), iface=None, bpf=None, output=str(tmp_path / "logs"),
            quiet=True, keep_query=False, tui=True,
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
        monkeypatch.setattr(netmon, "cmd_update", lambda a: (seen.append(a), 3)[1])
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


class TestRunPersistence:
    async def test_headless_without_log_writes_nothing(self, tmp_path: Path) -> None:
        pcap = tmp_path / "replay.pcap"
        write_replay_pcap(pcap)
        args = argparse.Namespace(
            read=str(pcap), iface=None, bpf=None, output=str(tmp_path / "logs"),
            quiet=True, keep_query=False, tui=False, log=False,
        )
        await run(args)
        assert not (tmp_path / "logs").exists()  # ephemeral: no run dir, no JSONL

    async def test_tui_without_log_writes_nothing(self, tmp_path: Path) -> None:
        pytest.importorskip("textual")
        pcap = tmp_path / "replay.pcap"
        write_replay_pcap(pcap)
        args = argparse.Namespace(
            read=str(pcap), iface=None, bpf=None, output=str(tmp_path / "logs"),
            quiet=True, keep_query=False, tui=True, log=False,
        )
        await run(args)
        assert not (tmp_path / "logs").exists()

    async def test_tui_with_log_persists_record(self, tmp_path: Path) -> None:
        pytest.importorskip("textual")
        pcap = tmp_path / "replay.pcap"
        write_replay_pcap(pcap)
        args = argparse.Namespace(
            read=str(pcap), iface=None, bpf=None, output=str(tmp_path / "logs"),
            quiet=True, keep_query=False, tui=True, log=True,
        )
        await run(args)
        run_dir = next((tmp_path / "logs").iterdir())
        assert (run_dir / "dns.jsonl").exists()
        assert (run_dir / "netmon.log").exists()
