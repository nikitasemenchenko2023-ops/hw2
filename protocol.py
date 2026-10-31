
import struct
from dataclasses import dataclass, field
from typing import Optional

from config import (
    CLASS_IN, FLAG_QR, FLAG_RA, FLAG_RD, HEADER_LEN,
    TYPE_A, TYPE_CNAME, TYPE_NS,
)





@dataclass
class DNSQuestion:
    qname: str
    qtype: int
    qclass: int


@dataclass
class DNSRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes
    target: Optional[str] = None  

    @property
    def address(self) -> Optional[str]:
        if self.rtype == TYPE_A and len(self.rdata) == 4:
            return ".".join(str(b) for b in self.rdata)
        return None


@dataclass
class DNSPacket:
    id: int
    flags: int
    questions: list[DNSQuestion] = field(default_factory=list)
    answers: list[DNSRecord] = field(default_factory=list)
    authorities: list[DNSRecord] = field(default_factory=list)
    additionals: list[DNSRecord] = field(default_factory=list)

    @property
    def rcode(self) -> int:
        return self.flags & 0x0F


def parse_qname(data: bytes, offset: int) -> tuple[str, int]:
    labels, curr, visited = [], offset, set()
    jumped, next_offset = False, offset
    while True:
        if curr >= len(data):
            break
        length = data[curr]
        if length == 0:
            if not jumped:
                next_offset = curr + 1
            break
        if (length & 0xC0) == 0xC0:
            if curr + 1 >= len(data):
                break
            if not jumped:
                next_offset, jumped = curr + 2, True
            ptr = struct.unpack("!H", data[curr:curr + 2])[0] & 0x3FFF
            if ptr in visited or ptr >= len(data):
                raise DNSFormatError("битый compression-pointer")
            visited.add(ptr)
            curr = ptr
            continue
        curr += 1
        if curr + length > len(data):
            raise DNSFormatError("метка за границей пакета")
        labels.append(data[curr:curr + length].decode("latin-1", "replace"))
        curr += length
    return ".".join(labels), next_offset


def _parse_question(data: bytes, offset: int) -> tuple[DNSQuestion, int]:
    qname, offset = parse_qname(data, offset)
    if offset + 4 > len(data):
        raise DNSFormatError("обрезанный вопрос")
    qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
    return DNSQuestion(qname, qtype, qclass), offset + 4


def _parse_record(data: bytes, offset: int) -> tuple[DNSRecord, int]:
    name, curr = parse_qname(data, offset)
    if curr + 10 > len(data):
        raise DNSFormatError("обрезанная RR")
    rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[curr:curr + 10])
    curr += 10
    if curr + rdlen > len(data):
        raise DNSFormatError("RDATA за границей пакета")
    rdata = data[curr:curr + rdlen]
    target = None
    if rtype in (TYPE_NS, TYPE_CNAME) and rdlen:
        try:
            target, _ = parse_qname(data, curr)
        except DNSFormatError:
            pass
    return DNSRecord(name, rtype, rclass, ttl, rdata, target), curr + rdlen


def parse_packet(data: bytes) -> DNSPacket:
    if len(data) < HEADER_LEN:
        raise DNSFormatError("пакет меньше заголовка")
    req_id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:HEADER_LEN])
    pkt = DNSPacket(req_id, flags)
    offset = HEADER_LEN
    for _ in range(qd):
        q, offset = _parse_question(data, offset)
        pkt.questions.append(q)
    for bucket, n in ((pkt.answers, an), (pkt.authorities, ns), (pkt.additionals, ar)):
        for _ in range(n):
            rr, offset = _parse_record(data, offset)
            bucket.append(rr)
    return pkt



def encode_qname(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        b = label.encode("latin-1")
        if len(b) > 63:
            raise ValueError(f"метка длиннее 63 байт: {label!r}")
        out += struct.pack("!B", len(b)) + b
    return out + b"\x00"


def build_query(qname: str, qtype: int, qclass: int = CLASS_IN,
                *, rd: bool = False, qid: int = 0x5555) -> bytes:
    flags = FLAG_RD if rd else 0
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
    return header + encode_qname(qname) + struct.pack("!HH", qtype, qclass)


def build_header(qid: int, flags: int, qd: int, an: int,
                 ns: int = 0, ar: int = 0) -> bytes:
    return struct.pack("!HHHHHH", qid, flags, qd, an, ns, ar)


def build_answer_a(ip: str, ttl: int, name_offset: int = 12) -> bytes:
    ptr = struct.pack("!H", 0xC000 | name_offset)
    rdata = bytes(int(x) for x in ip.split("."))
    return ptr + struct.pack("!HHIH", TYPE_A, CLASS_IN, ttl, len(rdata)) + rdata


def response_flags(request_flags: int, rcode: int) -> int:
    return FLAG_QR | FLAG_RA | (request_flags & FLAG_RD) | (rcode & 0x0F)