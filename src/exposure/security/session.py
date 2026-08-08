"""Runtime session control for the local application.

'localhost' is not sufficient protection (spec section 20). A malicious page in
the user's browser can attempt DNS-rebinding or CSRF against the loopback API.
We defend with three checks on every mutating request:

* a cryptographically random session token minted at startup, which the
  frontend must echo back in the ``X-Exposure-Session`` header;
* strict ``Host`` header validation (defeats DNS rebinding — a rebound page
  reaches us with a foreign Host);
* strict ``Origin`` validation for state-changing methods (CSRF).

The token is written to a file readable only by the current user, and the
served ``index.html`` is templated with it at request time, so a same-origin
page can read it but a cross-origin page cannot.
"""

from __future__ import annotations

import ipaddress
import secrets
from urllib.parse import urlsplit

SESSION_HEADER = "x-exposure-session"

# Methods that change state must carry a valid Origin and session token.
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class SessionGuard:
    """Validates Host/Origin/token for the loopback API."""

    def __init__(self, host: str, port: int, token: str | None = None) -> None:
        self.host = host
        self.port = port
        self.token = token or secrets.token_urlsafe(32)
        # Allowed Host header values: loopback names/addresses on our port.
        self._allowed_hosts = {
            f"127.0.0.1:{port}",
            f"localhost:{port}",
            f"[::1]:{port}",
            f"::1:{port}",
        }
        self._allowed_origins = {
            f"http://127.0.0.1:{port}",
            f"http://localhost:{port}",
            f"http://[::1]:{port}",
        }

    # -- individual checks (unit-testable in isolation) --------------------- #

    def host_ok(self, host_header: str | None) -> bool:
        if not host_header:
            return False
        host_header = host_header.strip().lower()
        if host_header in self._allowed_hosts:
            return True
        # Accept a bare loopback IP literal only if it parses as loopback and
        # carries our port.
        name, _, port = host_header.rpartition(":")
        if not port.isdigit() or int(port) != self.port:
            return False
        candidate = name.strip("[]")
        try:
            return ipaddress.ip_address(candidate).is_loopback
        except ValueError:
            return False

    def origin_ok(self, origin: str | None) -> bool:
        # Absent Origin is allowed for same-origin navigations (browsers omit
        # it for top-level GETs); mutating requests additionally require the
        # session token, which a cross-origin caller cannot read.
        if origin is None:
            return True
        origin = origin.strip().lower()
        if origin == "null":
            return False
        if origin in self._allowed_origins:
            return True
        parts = urlsplit(origin)
        if parts.scheme != "http":
            return False
        hostname = (parts.hostname or "").strip("[]")
        try:
            is_loop = ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            is_loop = hostname == "localhost"
        return is_loop and parts.port == self.port

    def token_ok(self, provided: str | None) -> bool:
        if not provided:
            return False
        return secrets.compare_digest(provided, self.token)

    # -- combined decision --------------------------------------------------- #

    def check(
        self,
        method: str,
        host_header: str | None,
        origin: str | None,
        token: str | None,
    ) -> tuple[bool, str]:
        """Return ``(allowed, reason)``. ``reason`` is safe to log."""
        if not self.host_ok(host_header):
            return False, "bad_host"
        if method.upper() in _MUTATING_METHODS:
            if not self.origin_ok(origin):
                return False, "bad_origin"
            if not self.token_ok(token):
                return False, "bad_session"
        return True, "ok"
