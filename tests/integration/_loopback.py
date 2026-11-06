"""
Loopback listeners and a scripted resolver for the outbound-request tests.

Two loopback addresses stand in for the two sides of the SSRF guard:
127.0.0.2 plays a public host (the tests tell the guard to treat that one
address as public) and 127.0.0.1 plays an internal service. Real sockets and
real HTTP are used, and nothing leaves the machine.
"""

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from darkweb_scanner.dashboard import http_client

PUBLIC_STAND_IN = "127.0.0.2"
INTERNAL = "127.0.0.1"

_REAL_GETADDRINFO = socket.getaddrinfo


class Listener:
    """A small HTTP server that records each request and answers with a fixed response."""

    def __init__(self, address, port=0, status=200, headers=None, body=b"", tls_context=None):
        self.hits = []  # (method, path, Host header)
        self.sni = []  # TLS server names offered by clients
        listener = self

        class Handler(BaseHTTPRequestHandler):
            def _answer(self):
                listener.hits.append((self.command, self.path, self.headers.get("Host")))
                self.send_response(status)
                for name, value in (headers or {}).items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            do_GET = do_HEAD = _answer

            def log_message(self, *args):  # keep test output quiet
                pass

        self.server = ThreadingHTTPServer((address, port), Handler)
        if tls_context is not None:
            tls_context.sni_callback = lambda sock, name, ctx: listener.sni.append(name)
            self.server.socket = tls_context.wrap_socket(self.server.socket, server_side=True)
        self.address = address
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class ScriptedDNS:
    """Stands in for socket.getaddrinfo.

    ``table`` maps a name to a list of answers: the first lookup gets the first
    answer, the next lookup the next one, and the last answer repeats. An
    answer is a list of addresses. Every lookup is recorded in ``calls``,
    including the address literals the socket layer passes when it connects,
    so ``calls`` also shows every connection target.
    """

    def __init__(self, table):
        self.table = table
        self.calls = []

    def lookups(self, name):
        return self.calls.count(name)

    def __call__(self, host, port, *args, **kwargs):
        name = host if isinstance(host, str) else host.decode()
        if name not in self.table and name.rsplit(":", 1)[0] in self.table:
            name = name.rsplit(":", 1)[0]  # the old probe passed "host:port" to the resolver
        self.calls.append(name)
        if name not in self.table:
            return _REAL_GETADDRINFO(host, port, *args, **kwargs)
        answers = self.table[name]
        answer = answers[min(self.lookups(name), len(answers)) - 1]
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (addr, port or 0))
            for addr in answer
        ]


@pytest.fixture
def loopback(monkeypatch):
    """Factory for listeners; treats 127.0.0.2 as a public address for the guard."""
    try:
        probe = socket.socket()
        probe.bind((PUBLIC_STAND_IN, 0))
        probe.close()
    except OSError:
        pytest.skip("needs a second loopback address (127.0.0.2), as on Linux")

    real_check = http_client._is_private_ip
    monkeypatch.setattr(
        http_client,
        "_is_private_ip",
        lambda addr: False if addr == PUBLIC_STAND_IN else real_check(addr),
    )

    listeners = []

    def start(address, **kwargs):
        listener = Listener(address, **kwargs)
        listeners.append(listener)
        return listener

    yield start
    for listener in listeners:
        listener.close()


@pytest.fixture
def scripted_dns(monkeypatch):
    """Factory: install a ScriptedDNS for the whole process and return it."""

    def install(table):
        dns = ScriptedDNS(table)
        monkeypatch.setattr(socket, "getaddrinfo", dns)
        return dns

    return install


def same_port_pair(start, public_kwargs=None, internal_kwargs=None):
    """A public stand-in listener and an internal one on the same port number."""
    for _ in range(20):
        public = start(PUBLIC_STAND_IN, **(public_kwargs or {}))
        try:
            internal = start(INTERNAL, port=public.port, **(internal_kwargs or {}))
        except OSError:
            continue
        return public, internal
    raise RuntimeError("no port free on both loopback addresses")
