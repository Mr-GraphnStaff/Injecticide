"""Bounded public HTTPS retrieval with per-connection DNS pinning."""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit
from .apis import is_github_releases_url

USER_AGENT = "InjecticideResearch/0.3 (+https://github.com/Mr-GraphnStaff/Injecticide)"
MAX_BYTES = 1024 * 1024


def canonical_url(url: str) -> str:
    parts = urlsplit(url)
    if (parts.scheme != "https" or not parts.hostname or parts.username
            or parts.password or parts.port not in (None, 443)):
        raise ValueError("Only HTTPS URLs without credentials or custom ports are supported")
    if parts.query and not (is_github_releases_url(url) and parts.query in ("per_page=1", "per_page=5")):
        raise ValueError("Queries are restricted to the GitHub releases per_page=1 or 5 API contract")
    if len(url) > 2048 or any(ord(c) < 33 for c in url):
        raise ValueError("Invalid URL")
    path = parts.path or "/"
    decoded = unquote(path)
    if "\\" in decoded or any(p in (".", "..") for p in decoded.split("/")):
        raise ValueError("Ambiguous URL path")
    return urlunsplit(("https", parts.hostname.lower(), path, parts.query, ""))


def in_scope(url: str, scopes: list[str]) -> bool:
    try:
        candidate = urlsplit(canonical_url(url))
        for scope in scopes:
            root = urlsplit(canonical_url(scope))
            prefix = root.path.rstrip("/")
            if candidate.hostname == root.hostname and candidate.query == root.query and (
                candidate.path == prefix or candidate.path.startswith(prefix + "/")
            ):
                return True
    except ValueError:
        pass
    return False


def public_address(host: str) -> str:
    addresses = list(dict.fromkeys(
        info[4][0] for info in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    ))
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise ValueError("Source DNS must resolve exclusively to public addresses")
    return addresses[0]


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def connect(self) -> None:
        address = public_address(self.host)
        connection = socket.create_connection((address, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(connection, server_hostname=self.host)
        except BaseException:
            connection.close()
            raise


@dataclass(frozen=True)
class Response:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes


def fetch(url: str, scopes: list[str], headers: dict[str, str] | None = None,
          redirect_guard=None) -> Response:
    """No proxies, cookies, JS, compression, credentials or uploaded URL execution."""
    deadline = time.monotonic() + 20
    for _ in range(5):
        url = canonical_url(url)
        if not in_scope(url, scopes):
            raise ValueError("URL or redirect leaves configured source scopes")
        parts = urlsplit(url)
        connection = PinnedHTTPSConnection(parts.hostname, timeout=8,
                                          context=ssl.create_default_context())
        try:
            target = (parts.path or "/") + ("?" + parts.query if parts.query else "")
            connection.request("GET", target, headers={
                "User-Agent": USER_AGENT, "Accept-Encoding": "identity", **(headers or {})
            })
            response = connection.getresponse()
            meta = {k.lower(): v for k, v in response.getheaders()}
            if response.status in (301, 302, 303, 307, 308):
                if time.monotonic() > deadline:
                    raise TimeoutError("Redirect deadline exceeded")
                url = urljoin(url, meta.get("location", ""))
                if not in_scope(url, scopes):
                    raise ValueError("Redirect leaves configured source scopes")
                if redirect_guard:
                    redirect_guard(url)
                continue
            if meta.get("content-encoding", "identity").lower() != "identity":
                raise ValueError("Compressed responses are not accepted")
            if int(meta.get("content-length", "0")) > MAX_BYTES:
                raise ValueError("Response exceeds 1 MiB collection budget")
            chunks, count = [], 0
            while True:
                if time.monotonic() > deadline:
                    raise TimeoutError("Response deadline exceeded")
                block = response.read1(min(16384, MAX_BYTES + 1 - count))
                if not block:
                    break
                count += len(block)
                if count > MAX_BYTES:
                    raise ValueError("Response exceeds 1 MiB collection budget")
                chunks.append(block)
            return Response(url, response.status, meta, b"".join(chunks))
        finally:
            connection.close()
    raise ValueError("Too many redirects")
