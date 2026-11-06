
import logging
import signal
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from config import Config
from core import RequestHandler, Resolver

log = logging.getLogger("server")


class DNSServer:
    def __init__(self, cfg: Config, handler: RequestHandler):
        self._cfg = cfg
        self._handler = handler
        self._pool = ThreadPoolExecutor(
            max_workers=cfg.max_workers, thread_name_prefix="dns"
        )
        self._stop = threading.Event()

    def start(self) -> None:
        for name, target in (("udp", self._run_udp), ("tcp", self._run_tcp)):
            threading.Thread(target=target, name=f"dns-{name}",
                             daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        self._pool.shutdown(wait=False)

    def _run_udp(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self._cfg.host, self._cfg.port))
        except OSError as e:
            log.error("[UDP] Не удалось привязать %s:%d — %s",
                      self._cfg.host, self._cfg.port, e)
            sock.close()
            return
        sock.settimeout(1.0)
        log.info("[UDP] Слушаю %s:%d", self._cfg.host, self._cfg.port)
        try:
            while not self._stop.is_set():
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                self._pool.submit(self._handle_udp, sock, data, addr)
        finally:
            sock.close()

    def _handle_udp(self, sock, data, addr) -> None:
        try:
            resp = self._handler.process(data)
            if resp:
                sock.sendto(resp, addr)
        except Exception:
            log.exception("[UDP] Ошибка обработки от %s", addr)

    def _run_tcp(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self._cfg.host, self._cfg.port))
            sock.listen(32)
        except OSError as e:
            log.error("[TCP] Не удалось привязать %s:%d — %s",
                      self._cfg.host, self._cfg.port, e)
            sock.close()
            return
        sock.settimeout(1.0)
        log.info("[TCP] Слушаю %s:%d", self._cfg.host, self._cfg.port)
        try:
            while not self._stop.is_set():
                try:
                    conn, addr = sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                self._pool.submit(self._handle_tcp, conn, addr)
        finally:
            sock.close()

    def _handle_tcp(self, conn, addr) -> None:
        with conn:
            conn.settimeout(self._cfg.tcp_idle_timeout)
            try:
                while not self._stop.is_set():
                    head = self._recv_exact(conn, 2)
                    if not head:
                        break
                    length = struct.unpack("!H", head)[0]
                    if length == 0:
                        break
                    req = self._recv_exact(conn, length)
                    if not req:
                        break
                    resp = self._handler.process(req)
                    if not resp:
                        break
                    conn.sendall(struct.pack("!H", len(resp)) + resp)
            except (socket.timeout, OSError):
                pass
            except Exception:
                log.exception("[TCP] Ошибка обработки от %s", addr)

    @staticmethod
    def _recv_exact(conn, n: int) -> bytes | None:
        buf = b""
        while len(buf) < n:
            try:
                chunk = conn.recv(n - len(buf))
            except (socket.timeout, OSError):
                return None
            if not chunk:
                return None
            buf += chunk
        return buf


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    cfg = Config.from_env()


    handler = RequestHandler(cfg, Resolver(cfg))
    server = DNSServer(cfg, handler)
    server.start()
    log.info("DNS-сервер запущен на %s:%d", cfg.host, cfg.port)

    def shutdown(signum, _frame):
        log.info("Остановка (сигнал %d)...", signum)
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown(signal.SIGINT, None)


if __name__ == "__main__":
    main()