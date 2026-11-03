"""链路层 / 网络层 / 传输层解码（纯函数，可在 Windows 上单测）。

。输出统一的 `Packet` 字典：

===================  =====================================================
键                   含义
===================  =====================================================
ts                   float，epoch 秒（行为窗口/flow 老化用）
ts_iso               str，UTC ISO8601（写事件/告警用）
l2                   "eth"
ethertype            int，0x0800/0x86dd/...
src_mac/dst_mac      str
src_ip/dst_ip        str | None
proto                str | None，"tcp"/"udp"/"icmp"/"icmpv6"/"ipproto-N"
proto_num            int | None，IP 首部里的协议号
src_port/dst_port    int | None
ip_len               int，IP 层总长（含首部；截断时为实际可用长度）
payload_len          int，L4 载荷长度
flags                int，TCP 标志位（非 TCP 为 0）
ttl                  int | None（IPv4 ttl / IPv6 hop limit）
icmp_type/icmp_code  int | None
domain               str | None，DNS 查询名（小写、无末尾点，仅 53 端口）
dns_qtype            int | None，DNS 问题类型（A=1/AAAA=28...）
dns_is_response      bool，DNS 头 flags & 0x8000（仅 53 端口出现）
fragmented           bool
malformed            bool
raw_len              int，原始帧长度
===================  =====================================================

只依赖标准库；不做任何 socket 创建，全部按字节偏移解析。
"""

from __future__ import annotations

import socket
import struct
import time
from typing import Any

from .. import schema

# ---------------------------------------------------------------------------
# TCP 标志位（契约要求暴露常量）
# ---------------------------------------------------------------------------
FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10
FLAG_URG = 0x20
FLAG_ECE = 0x40
FLAG_CWR = 0x80

FLAG_NAMES: tuple[tuple[int, str], ...] = (
    (FLAG_FIN, "fin"),
    (FLAG_SYN, "syn"),
    (FLAG_RST, "rst"),
    (FLAG_PSH, "psh"),
    (FLAG_ACK, "ack"),
    (FLAG_URG, "urg"),
    (FLAG_ECE, "ece"),
    (FLAG_CWR, "cwr"),
)

ETH_HDR_LEN = 14
IPV4_MIN_HDR = 20
IPV6_HDR_LEN = 40
TCP_MIN_HDR = 20
UDP_HDR_LEN = 8
ICMP_MIN_LEN = 8

#: DNS
DNS_PORT = 53
DNS_HDR_LEN = 12
DNS_MAX_LABELS = 32
DNS_MAX_POINTER_HOPS = 8
DNS_MAX_QUESTIONS = 8

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_ARP = 0x0806
ETH_P_VLAN = 0x8100
ETH_P_QINQ = 0x88A8

IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMP = 1
IPPROTO_ICMPV6 = 58

#: 常见协议号 → 名称（其余回落为 "ipproto-N"，便于规则用 proto 字段匹配）
PROTO_NAMES: dict[int, str] = {
    IPPROTO_ICMP: "icmp",
    IPPROTO_TCP: "tcp",
    IPPROTO_UDP: "udp",
    IPPROTO_ICMPV6: "icmpv6",
}

#: IPv6 扩展头：值与「长度字段语义」的对应关系
_IPV6_EXT_HOPBYHOP = 0
_IPV6_EXT_ROUTING = 43
_IPV6_EXT_FRAGMENT = 44
_IPV6_EXT_AH = 51
_IPV6_EXT_DESTOPTS = 60
_IPV6_EXT_MOBILITY = 135
_IPV6_EXT_SKIP = {
    _IPV6_EXT_HOPBYHOP: "unit8",
    _IPV6_EXT_ROUTING: "unit8",
    _IPV6_EXT_DESTOPTS: "unit8",
    _IPV6_EXT_MOBILITY: "unit8",
    _IPV6_EXT_FRAGMENT: "fragment",
    _IPV6_EXT_AH: "ah",
}


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------
def proto_name(proto_num: int | None) -> str | None:
    """协议号 → 可读名（未知返回 None）。"""
    if proto_num is None:
        return None
    return PROTO_NAMES.get(proto_num) or f"ipproto-{int(proto_num)}"


def parse_flags(flags: int) -> set[str]:
    """把 TCP flags 整数拆成 {"syn","ack",...} 集合。"""
    value = int(flags or 0)
    return {name for bit, name in FLAG_NAMES if value & bit}


def format_flags(flags: int) -> str:
    """便于日志：把 flags 整数转成 "s..a." 形式的短串。"""
    value = int(flags or 0)
    return "".join(
        (name[0] if value & bit else ".") for bit, name in FLAG_NAMES
    )


def _mac(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def _ipv4(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def _ipv6(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6, raw)


def _ts_pair(ts: Any) -> tuple[float, str]:
    """把外部 ts 归一成 (epoch 秒, ISO 字符串)。"""
    if ts is None:
        now = time.time()
        return now, schema.to_utc(now)
    if isinstance(ts, (int, float)):
        return float(ts), schema.to_utc(float(ts))
    if isinstance(ts, str):
        iso = schema.to_utc(ts)
        try:
            from datetime import datetime, timezone

            epoch = datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(
                timezone.utc
            ).timestamp()
        except ValueError:
            epoch = time.time()
        return epoch, iso
    return time.time(), schema.utc_now()


def _new_packet(frame: bytes, ts: Any) -> dict:
    epoch, iso = _ts_pair(ts)
    return {
        "ts": epoch,
        "ts_iso": iso,
        "l2": "eth",
        "ethertype": None,
        "src_mac": None,
        "dst_mac": None,
        "src_ip": None,
        "dst_ip": None,
        "proto": None,
        "proto_num": None,
        "src_port": None,
        "dst_port": None,
        "ip_len": 0,
        "payload_len": 0,
        "flags": 0,
        "ttl": None,
        "icmp_type": None,
        "icmp_code": None,
        "fragmented": False,
        "malformed": False,
        "raw_len": len(frame) if frame else 0,
    }


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------
def decode(frame: bytes, ts: Any = None) -> dict | None:
    """解码一帧以太网报文；无法识别/空帧返回 None，畸形帧返回 malformed=True。"""
    if not frame or not isinstance(frame, (bytes, bytearray, memoryview)):
        return None
    data = bytes(frame)
    pkt = _new_packet(data, ts)

    # ---- 以太网 -----------------------------------------------------------
    if len(data) < ETH_HDR_LEN:
        pkt["malformed"] = True
        return pkt
    pkt["dst_mac"] = _mac(data[0:6])
    pkt["src_mac"] = _mac(data[6:12])
    ethertype = struct.unpack_from("!H", data, 12)[0]
    offset = ETH_HDR_LEN

    # 802.1Q / QinQ 单层 VLAN 标签
    if ethertype in (ETH_P_VLAN, ETH_P_QINQ) and len(data) >= offset + 4:
        ethertype = struct.unpack_from("!H", data, offset + 2)[0]
        offset += 4
    pkt["ethertype"] = ethertype

    try:
        if ethertype == ETH_P_IP:
            _decode_ipv4(pkt, data, offset)
        elif ethertype == ETH_P_IPV6:
            _decode_ipv6(pkt, data, offset)
        elif ethertype == ETH_P_ARP:
            # ARP 不算畸形，只是没有 IP/L4 字段
            pkt["proto"] = "arp"
        else:
            pkt["proto"] = f"ethertype-{ethertype:04x}"
    except (struct.error, IndexError, ValueError):
        pkt["malformed"] = True
    return pkt


# ---------------------------------------------------------------------------
# IPv4
# ---------------------------------------------------------------------------
def _decode_ipv4(pkt: dict, data: bytes, offset: int) -> None:
    available = len(data) - offset
    if available < IPV4_MIN_HDR:
        pkt["malformed"] = True
        return
    ver_ihl = data[offset]
    if (ver_ihl >> 4) != 4:
        pkt["malformed"] = True
        return
    ihl = (ver_ihl & 0x0F) * 4
    total_len = struct.unpack_from("!H", data, offset + 2)[0]
    proto_num = data[offset + 9]
    if ihl < IPV4_MIN_HDR:
        pkt["malformed"] = True
        return
    if total_len < ihl:
        pkt["malformed"] = True
        return
    declared_avail = min(total_len, available)
    if total_len > available:
        # 被 snaplen 截断的帧按畸形记一笔，但仍尽量解出五元组
        pkt["malformed"] = True

    frag = struct.unpack_from("!H", data, offset + 6)[0]
    frag_offset = (frag & 0x1FFF) * 8
    more_fragments = bool(frag & 0x2000)
    pkt["fragmented"] = bool(frag_offset or more_fragments)
    pkt["frag_off"] = frag_offset
    pkt["mf"] = more_fragments
    pkt["ttl"] = data[offset + 8]
    pkt["proto_num"] = proto_num
    pkt["proto"] = proto_name(proto_num)
    pkt["ip_len"] = declared_avail
    pkt["ip_id"] = struct.unpack_from("!H", data, offset + 4)[0]
    pkt["src_ip"] = _ipv4(data[offset + 12:offset + 16])
    pkt["dst_ip"] = _ipv4(data[offset + 16:offset + 20])

    if frag_offset:
        # 后续分片没有 L4 首部，无法取端口
        return
    l4 = data[offset + ihl:offset + declared_avail]
    pkt["payload_len"] = max(0, len(l4)) if proto_num not in (IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP) else 0
    _decode_l4(pkt, l4, proto_num)


# ---------------------------------------------------------------------------
# IPv6
# ---------------------------------------------------------------------------
def _decode_ipv6(pkt: dict, data: bytes, offset: int) -> None:
    available = len(data) - offset
    if available < IPV6_HDR_LEN:
        pkt["malformed"] = True
        return
    version = data[offset] >> 4
    if version != 6:
        pkt["malformed"] = True
        return
    payload_len = struct.unpack_from("!H", data, offset + 4)[0]
    next_header = data[offset + 6]
    pkt["ttl"] = data[offset + 7]
    pkt["src_ip"] = _ipv6(data[offset + 8:offset + 24])
    pkt["dst_ip"] = _ipv6(data[offset + 24:offset + 40])
    ip_end = offset + IPV6_HDR_LEN + payload_len
    if ip_end > len(data):
        pkt["malformed"] = True
        ip_end = len(data)
    pkt["ip_len"] = min(IPV6_HDR_LEN + payload_len, len(data) - offset)

    l4_off = offset + IPV6_HDR_LEN
    hops = 0
    while next_header in _IPV6_EXT_SKIP and hops < 4:
        hops += 1
        if l4_off + 8 > ip_end:
            pkt["malformed"] = True
            return
        kind = _IPV6_EXT_SKIP[next_header]
        nxt = data[l4_off]
        if kind == "fragment":
            frag = struct.unpack_from("!H", data, l4_off + 2)[0]
            frag_offset = (frag >> 3) * 8
            pkt["fragmented"] = pkt["fragmented"] or bool(frag_offset or (frag & 0x1))
            pkt["frag_off"] = frag_offset
            l4_off += 8
            next_header = nxt
            if frag_offset:
                return
            continue
        if kind == "ah":
            hdr_len = (data[l4_off + 1] + 2) * 4
        else:
            hdr_len = (data[l4_off + 1] + 1) * 8
        if hdr_len <= 0 or l4_off + hdr_len > ip_end:
            pkt["malformed"] = True
            return
        l4_off += hdr_len
        next_header = nxt

    pkt["proto_num"] = next_header
    pkt["proto"] = proto_name(next_header)
    _decode_l4(pkt, data[l4_off:ip_end], next_header)


# ---------------------------------------------------------------------------
# L4：TCP / UDP / ICMP
# ---------------------------------------------------------------------------
def _decode_l4(pkt: dict, l4: bytes, proto_num: int) -> None:
    if proto_num == IPPROTO_TCP:
        _decode_tcp(pkt, l4)
    elif proto_num == IPPROTO_UDP:
        _decode_udp(pkt, l4)
    elif proto_num in (IPPROTO_ICMP, IPPROTO_ICMPV6):
        _decode_icmp(pkt, l4)
    else:
        pkt["payload_len"] = len(l4)


def _decode_tcp(pkt: dict, tcp: bytes) -> None:
    if len(tcp) < TCP_MIN_HDR:
        pkt["malformed"] = True
        pkt["payload_len"] = len(tcp)
        return
    src_port, dst_port = struct.unpack_from("!HH", tcp, 0)
    data_offset = (tcp[12] >> 4) * 4
    flags = tcp[13]
    if data_offset < TCP_MIN_HDR or data_offset > len(tcp):
        pkt["malformed"] = True
        return
    pkt["src_port"] = src_port
    pkt["dst_port"] = dst_port
    pkt["flags"] = flags
    pkt["tcp_hdr_len"] = data_offset
    pkt["seq"] = struct.unpack_from("!I", tcp, 4)[0]
    pkt["ack"] = struct.unpack_from("!I", tcp, 8)[0]
    pkt["window"] = struct.unpack_from("!H", tcp, 14)[0]
    payload = tcp[data_offset:]
    pkt["payload_len"] = max(0, len(payload))
    if (src_port == DNS_PORT or dst_port == DNS_PORT) and payload:
        _decode_dns(pkt, payload, "tcp")
    # SYN+FIN / SYN+RST 属矛盾标志（XMAS/NULL 扫描特征之一）
    if flags & FLAG_SYN and flags & (FLAG_FIN | FLAG_RST):
        pkt["malformed"] = True


def _decode_udp(pkt: dict, udp: bytes) -> None:
    if len(udp) < UDP_HDR_LEN:
        pkt["malformed"] = True
        pkt["payload_len"] = len(udp)
        return
    src_port, dst_port, udp_len = struct.unpack_from("!HHH", udp, 0)
    pkt["src_port"] = src_port
    pkt["dst_port"] = dst_port
    pkt["udp_len"] = udp_len
    if udp_len < UDP_HDR_LEN or udp_len > len(udp):
        pkt["malformed"] = True
    payload = udp[UDP_HDR_LEN:min(udp_len, len(udp))]
    pkt["payload_len"] = max(0, len(payload))
    if (src_port == DNS_PORT or dst_port == DNS_PORT) and payload:
        _decode_dns(pkt, payload, "udp")


# ---------------------------------------------------------------------------
# DNS 查询名（仅取 QNAME，解析失败静默跳过，绝不污染 malformed）
# ---------------------------------------------------------------------------
def _read_dns_name(data: bytes, offset: int) -> tuple[str | None, int]:
    """读取 DNS 域名（支持压缩指针），返回 (小写域名, 下一个字段偏移)。

    压缩指针只做单层/有限跳转，防止恶意循环；任何越界/非法标签返回 (None, offset)。
    """
    labels: list[str] = []
    jumped = False
    end_offset = offset
    hops = 0
    while True:
        if offset < 0 or offset >= len(data):
            return None, end_offset
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end_offset = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                return None, end_offset
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end_offset = offset + 2
            jumped = True
            hops += 1
            if hops > DNS_MAX_POINTER_HOPS or pointer >= len(data):
                return None, end_offset
            offset = pointer
            continue
        if length & 0xC0:
            # 0x40/0x80 为保留标签类型，视为不可解析
            return None, end_offset
        offset += 1
        if offset + length > len(data):
            return None, end_offset
        try:
            labels.append(data[offset:offset + length].decode("ascii"))
        except UnicodeDecodeError:
            return None, end_offset
        offset += length
        if not jumped:
            end_offset = offset
        if len(labels) > DNS_MAX_LABELS:
            return None, end_offset
    if not labels:
        return None, end_offset
    return ".".join(labels).lower().rstrip("."), end_offset


def _decode_dns(pkt: dict, payload: bytes, proto: str) -> None:
    """解析 DNS 报文头与首个 QNAME，写入 domain/dns_qtype/dns_is_response。

    - UDP：载荷即 DNS 报文；
    - TCP：前 2 字节是报文长度，先跳过；
    - 任何解析失败直接返回（不设 malformed）。
    """
    data = payload
    if proto == "tcp":
        if len(data) < 2:
            return
        message_len = struct.unpack_from("!H", data, 0)[0]
        if message_len < DNS_HDR_LEN:
            return
        data = data[2:2 + message_len]
    if len(data) < DNS_HDR_LEN:
        return
    try:
        flags, qdcount = struct.unpack_from("!HH", data, 2)
        pkt["dns_is_response"] = bool(flags & 0x8000)
        if qdcount <= 0:
            return
        offset = DNS_HDR_LEN
        for _ in range(min(qdcount, DNS_MAX_QUESTIONS)):
            name, offset = _read_dns_name(data, offset)
            if not name:
                return
            if offset + 4 > len(data):
                return
            qtype, _qclass = struct.unpack_from("!HH", data, offset)
            pkt.setdefault("domain", name)
            pkt.setdefault("dns_qtype", int(qtype))
            # 只取第一个问题（查询名），后续问题不影响检测
            return
    except (struct.error, IndexError, ValueError):
        # 畸形 DNS 只是没有域名可解析，不应标记为网络层畸形包
        return



def _decode_icmp(pkt: dict, icmp: bytes) -> None:
    if len(icmp) < ICMP_MIN_LEN:
        pkt["malformed"] = True
        pkt["payload_len"] = len(icmp)
        return
    pkt["icmp_type"] = icmp[0]
    pkt["icmp_code"] = icmp[1]
    pkt["payload_len"] = max(0, len(icmp) - ICMP_MIN_LEN)


__all__ = [
    "FLAG_FIN",
    "FLAG_SYN",
    "FLAG_RST",
    "FLAG_PSH",
    "FLAG_ACK",
    "FLAG_URG",
    "FLAG_ECE",
    "FLAG_CWR",
    "FLAG_NAMES",
    "DNS_PORT",
    "decode",
    "parse_flags",
    "format_flags",
    "proto_name",
]
