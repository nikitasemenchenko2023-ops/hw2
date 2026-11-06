import logging
import random
import socket
import struct

import protocol as proto
from config import (
    CLASS_IN, Config, RCODE_FORMERR, RCODE_NOERROR, RCODE_SERVFAIL,
    TYPE_A, TYPE_NS, TYPE_SOA,RCODE_NXDOMAIN
)

log = logging.getLogger(__name__)




class Resolver:
    def __init__(self, cfg: Config):
        self._cfg = cfg

    def resolve(self, qname: str, qtype: int, qclass: int):
        try:
            return self._iterate(qname, qtype, qclass, depth=0)
        except Exception:
            log.exception("[СЕТЬ] Сбой резолва %s", qname)
            return None

    def _iterate(self, qname, qtype, qclass, depth):
        if depth > self._cfg.max_iterative_depth:
            return None
        servers = list(self._cfg.root_servers)
        hops = 0
        while servers and hops < self._cfg.max_hops:
            hops += 1
            response = self._query(servers.pop(0), qname, qtype, qclass)
            if response is None:
                continue
            try:
                pkt = proto.parse_packet(response)
            except proto.DNSFormatError:
                continue

            if pkt.answers or pkt.rcode != RCODE_NOERROR:
                return response

            has_ns = any(r.rtype == TYPE_NS for r in pkt.authorities)
            has_soa = any(r.rtype == TYPE_SOA for r in pkt.authorities)
            if has_soa and not has_ns:
                return response

            ns_names = [r.target for r in pkt.authorities
                        if r.rtype == TYPE_NS and r.target]
            if not ns_names:
                break

            next_servers = [r.address for r in pkt.additionals
                            if r.rtype == TYPE_A and r.address]
            if not next_servers:
                for ns in ns_names[:5]:
                    ip = self._resolve_a(ns, depth + 1)
                    if ip:
                        next_servers.append(ip)
            if not next_servers:
                break
            servers = next_servers
        return None

    def _resolve_a(self, name: str, depth: int):
        response = self._iterate(name, TYPE_A, CLASS_IN, depth)
        if response is None:
            return None
        try:
            pkt = proto.parse_packet(response)
        except proto.DNSFormatError:
            return None
        for rr in pkt.answers:
            if rr.rtype == TYPE_A and rr.address:
                return rr.address
        return None

    def _query(self, server_ip, qname, qtype, qclass):
        query = proto.build_query(qname, qtype, qclass,
                                  rd=False, qid=random.randint(0, 0xFFFF))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self._cfg.query_timeout)
        try:
            sock.sendto(query, (server_ip, 53))
            return sock.recvfrom(4096)[0]
        except (socket.timeout, OSError):
            return None
        finally:
            sock.close()


class RequestHandler:
    def __init__(self, cfg: Config, resolver: Resolver):
        self._cfg = cfg
        self._resolver = resolver

    def process(self, request: bytes):
        if len(request) < proto.HEADER_LEN:
            return None
        try:
            pkt = proto.parse_packet(request)
        except proto.DNSFormatError:
            return self._error(request, RCODE_SERVFAIL, b"")

        if len(pkt.questions) != 1:
            return self._error(request, RCODE_FORMERR, b"")

        q = pkt.questions[0]
        try:
            _, q_end = proto.parse_qname(request, proto.HEADER_LEN)
            question_bytes = request[proto.HEADER_LEN:q_end + 4]
        except proto.DNSFormatError:
            return self._error(request, RCODE_FORMERR, b"")

        log.info("[СЕТЬ] Резолв %s (тип %d)", q.qname, q.qtype)
        response = self._resolver.resolve(q.qname, q.qtype, q.qclass)
        if response is None:
            return self._error(request, RCODE_NXDOMAIN, question_bytes)

        return self._to_client(response, pkt.id, pkt.flags)

    @staticmethod
    def _to_client(response: bytes, new_id: int, req_flags: int) -> bytes:
        if len(response) < proto.HEADER_LEN:
            return response
        upstream_flags = struct.unpack("!H", response[2:4])[0]
        rcode = upstream_flags & 0x0F
        flags = proto.response_flags(req_flags, rcode)
        return struct.pack("!HH", new_id, flags) + response[4:]

    @staticmethod
    def _error(request: bytes, rcode: int, question_bytes: bytes) -> bytes:
        req_id = struct.unpack("!H", request[:2])[0]
        req_flags = struct.unpack("!H", request[2:4])[0] if len(request) >= 4 else 0
        flags = proto.response_flags(req_flags, rcode)
        return proto.build_header(req_id, flags,
                                  1 if question_bytes else 0, 0) + question_bytes