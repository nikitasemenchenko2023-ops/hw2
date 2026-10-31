
import base64
import json
import logging
import os
import random
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

import protocol as proto
from config import (
    CLASS_IN, Config, RCODE_FORMERR, RCODE_NOERROR, RCODE_SERVFAIL,
    TYPE_A, TYPE_NS, TYPE_SOA,
)

log = logging.getLogger(__name__)


@dataclass
class _Entry:
    expire: float
    response: bytes


class DNSCache:
    def __init__(self, path: str):
        self._path = path
        self._data: dict[str, _Entry] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(qname, qtype, qclass) -> str:
        return f"{qname.lower()}|{qtype}|{qclass}"

    def get(self, qname, qtype, qclass) -> Optional[bytes]:
        key = self._key(qname, qtype, qclass)
        with self._lock:
            e = self._data.get(key)
            if e is None:
                return None
            if e.expire <= time.time():
                del self._data[key]
                return None
            return e.response

    def put(self, qname, qtype, qclass, response: bytes, ttl: int) -> None:
        key = self._key(qname, qtype, qclass)
        with self._lock:
            self._data[key] = _Entry(time.time() + max(ttl, 1), response)

    def load(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path, encoding="utf-8") as f:
                raw = json.load(f)
            now, loaded = time.time(), 0
            with self._lock:
                for key, item in raw.items():
                    try:
                        if item["expire"] > now:
                            self._data[key] = _Entry(
                                float(item["expire"]),
                                base64.b64decode(item["response"]),
                            )
                            loaded += 1
                    except (KeyError, TypeError, ValueError):
                        continue
            log.info("[КЭШ] Загружено записей: %d", loaded)
        except (OSError, json.JSONDecodeError) as e:
            log.warning("[КЭШ] Не удалось загрузить: %s", e)

    def save(self) -> None:
        now = time.time()
        with self._lock:
            data = {
                k: {"expire": e.expire,
                    "response": base64.b64encode(e.response).decode("ascii")}
                for k, e in self._data.items() if e.expire > now
            }
        try:
            tmp = self._path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, self._path)
            log.info("[КЭШ] Сохранено записей: %d", len(data))
        except OSError as e:
            log.warning("[КЭШ] Не удалось сохранить: %s", e)


class Resolver:
    def __init__(self, cfg: Config):
        self._cfg = cfg

    def resolve(self, qname: str, qtype: int, qclass: int) -> Optional[bytes]:
        try:
            return self._iterate(qname, qtype, qclass, depth=0)
        except Exception:
            log.exception("[СЕТЬ] Сбой резолва %s", qname)
            return None

    def _iterate(self, qname, qtype, qclass, depth) -> Optional[bytes]:
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
            if has_soa and not has_ns:  # NODATA — кэшируем как есть
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

    def _resolve_a(self, name: str, depth: int) -> Optional[str]:
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

    def _query(self, server_ip, qname, qtype, qclass) -> Optional[bytes]:
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


@dataclass
class QueryContext:
    req_id: int
    qname: str
    qtype: int
    qclass: int
    question_bytes: bytes
    request_flags: int


FeatureHandler = Callable[[QueryContext], Optional[bytes]]


def _multiply_handler(ctx: QueryContext) -> Optional[bytes]:
    if ".multiply." not in ctx.qname.lower():
        return None
    numbers = []
    for part in ctx.qname.split("."):
        if part.lower() == "multiply":
            break
        if part.isdigit():
            numbers.append(int(part))
    product = 1
    for n in numbers:
        product *= n
    ip = f"127.0.0.{product % 256}"
    log.info("[MULTIPLY] %s -> %s -> %s", ctx.qname, numbers, ip)
    flags = proto.response_flags(ctx.request_flags, RCODE_NOERROR)
    header = proto.build_header(ctx.req_id, flags, 1, 1)
    return header + ctx.question_bytes + proto.build_answer_a(ip, ttl=60)


_FEATURES: list[FeatureHandler] = [_multiply_handler]


def _run_features(ctx: QueryContext) -> Optional[bytes]:
    for h in _FEATURES:
        r = h(ctx)
        if r is not None:
            return r
    return None


class RequestHandler:
    def __init__(self, cfg: Config, cache: DNSCache, resolver: Resolver):
        self._cfg = cfg
        self._cache = cache
        self._resolver = resolver

    def process(self, request: bytes) -> Optional[bytes]:
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

        cached = self._cache.get(q.qname, q.qtype, q.qclass)
        if cached is not None:
            log.info("[КЭШ] ХИТ: %s (тип %d)", q.qname, q.qtype)
            return self._to_client(cached, pkt.id, pkt.flags)

        ctx = QueryContext(pkt.id, q.qname, q.qtype, q.qclass,
                           question_bytes, pkt.flags)
        custom = _run_features(ctx)
        if custom is not None:
            return custom

        log.info("[СЕТЬ] Резолв %s (тип %d)", q.qname, q.qtype)
        response = self._resolver.resolve(q.qname, q.qtype, q.qclass)
        if response is None:
            return self._error(request, RCODE_SERVFAIL, question_bytes)


        try:
            rp = proto.parse_packet(response)
            ttl = self._extract_ttl(rp)
            self._cache.put(q.qname, q.qtype, q.qclass, response, ttl)
            log.info("[КЭШ] Сохранено %s (TTL=%d)", q.qname, ttl)
        except proto.DNSFormatError:
            pass
        return self._to_client(response, pkt.id, pkt.flags)

    @staticmethod
    def _to_client(response: bytes, new_id: int, req_flags: int) -> bytes:
        if len(response) < proto.HEADER_LEN:
            return response
        upstream_flags = struct.unpack("!H", response[2:4])[0]
        rcode = upstream_flags & 0x0F
        flags = proto.response_flags(req_flags, rcode)
        return struct.pack("!HH", new_id, flags) + response[4:]

    def _extract_ttl(self, pkt: proto.DNSPacket) -> int:
        ttls = [rr.ttl for rr in pkt.answers if rr.ttl > 0]
        if ttls:
            return min(ttls)
        for rr in pkt.authorities:
            if rr.rtype == TYPE_SOA and len(rr.rdata) >= 4:
                minimum = struct.unpack("!I", rr.rdata[-4:])[0]
                return min(rr.ttl, minimum) or self._cfg.default_ttl
        return self._cfg.default_ttl

    @staticmethod
    def _error(request: bytes, rcode: int, question_bytes: bytes) -> bytes:
        req_id = struct.unpack("!H", request[:2])[0]
        req_flags = struct.unpack("!H", request[2:4])[0] if len(request) >= 4 else 0
        flags = proto.response_flags(req_flags, rcode)
        return proto.build_header(req_id, flags,
                                  1 if question_bytes else 0, 0) + question_bytes