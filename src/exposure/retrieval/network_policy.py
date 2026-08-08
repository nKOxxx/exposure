"""SSRF-safe networking: resolve, validate, and pin connections to a safe IP.

The retriever is one of the highest-risk components (spec section 8). The core
defense against DNS rebinding is to make resolution, validation, and connection
*atomic*: we resolve the hostname, reject the request if any resolved address is
in a blocked range, and then connect to the exact validated IP literal. Because
the socket connects to that pinned IP (not to the name), an attacker cannot swap
the answer between our check and the connection.

TLS still uses the original hostname for SNI and certificate verification —
``httpcore`` passes the origin host to ``start_tls`` regardless of the address
``connect_tcp`` connected to — so certificate validation is unaffected.
"""

from __future__ import annotations

import socket

import httpcore
import httpx

from exposure.security.validation import UrlPolicyError, is_blocked_address, is_blocked_hostname


def _getaddrinfo(host: str, port: int) -> list[str]:
    """Return the list of resolved IP strings for ``host``.

    Wrapped in a module function so tests can simulate DNS rebinding.
    """
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    return [str(info[4][0]) for info in infos]


def resolve_and_validate(host: str, port: int) -> str:
    """Resolve ``host`` and return a single validated IP literal to connect to.

    Raises ``UrlPolicyError`` if the hostname is blocked, if resolution fails,
    or if *any* resolved address falls in a blocked range (fail-closed: a mixed
    public/private answer is treated as hostile).
    """
    host = host.strip().strip("[]")
    if is_blocked_hostname(host):
        raise UrlPolicyError("blocked_hostname")

    # A literal IP needs validation but no DNS.
    try:
        import ipaddress

        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None
    if addr is not None:
        if is_blocked_address(addr):
            raise UrlPolicyError("blocked_ip_literal")
        return str(addr)

    try:
        resolved = _getaddrinfo(host, port)
    except OSError as exc:
        raise UrlPolicyError("dns_resolution_failed") from exc
    if not resolved:
        raise UrlPolicyError("dns_no_records")

    for ip in resolved:
        if is_blocked_address(ip):
            raise UrlPolicyError("dns_resolves_to_blocked")
    return resolved[0]


class GuardedBackend(httpcore.SyncBackend):
    """A network backend that pins each connection to a validated IP."""

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: object = None,
    ) -> httpcore.NetworkStream:
        safe_ip = resolve_and_validate(host, port)
        return super().connect_tcp(
            safe_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,  # type: ignore[arg-type]
        )


class GuardedTransport(httpx.HTTPTransport):
    """An httpx transport whose connection pool uses :class:`GuardedBackend`.

    We let httpx build its pool (so the SSL context and limits are configured
    normally) and then swap the pool's network backend before any connection is
    opened. No connections exist yet at construction time, so the swap is safe.
    """

    def __init__(
        self,
        *,
        verify: bool = True,
        limits: httpx.Limits | None = None,
    ) -> None:
        super().__init__(
            verify=verify,
            retries=0,
            limits=limits or httpx.Limits(max_connections=8, max_keepalive_connections=2),
        )
        self._pool._network_backend = GuardedBackend()
