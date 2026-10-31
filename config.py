import os
from dataclasses import dataclass

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
CLASS_IN = 1

RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3

FLAG_QR = 0x8000
FLAG_RD = 0x0100
FLAG_RA = 0x0080
HEADER_LEN = 12


@dataclass(frozen=True)
class Config:
    host: str = "127.0.0.1"
    port: int = 53
    cache_file: str = "cache.json"
    max_iterative_depth: int = 10
    max_hops: int = 30
    query_timeout: float = 2.5
    tcp_idle_timeout: float = 5.0
    max_workers: int = 100
    default_ttl: int = 300
    root_servers: tuple[str, ...] = (
        "198.41.0.4", "199.7.91.13", "192.228.79.201", "192.33.4.12",
    )

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            host=os.environ.get("DNS_HOST", "127.0.0.1"),
            port=int(os.environ.get("DNS_PORT", "53")),
            cache_file=os.environ.get("DNS_CACHE_FILE", "cache.json"),
            max_workers=int(os.environ.get("DNS_MAX_WORKERS", "100")),
            query_timeout=float(os.environ.get("DNS_QUERY_TIMEOUT", "2.5")),
        )