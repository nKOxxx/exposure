"""Launcher: start the local Exposure server on loopback and open the UI.

Binds to 127.0.0.1 only. Refuses to bind a non-loopback address (spec section
20). Prints the URL and confirms the session token is embedded in the page.
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import sys
import threading
import webbrowser

import uvicorn

from exposure import APP_VERSION
from exposure.app.main import create_app
from exposure.app.service import Service
from exposure.config import Settings
from exposure.security.session import SessionGuard
from exposure.storage.database import Database


def _is_loopback(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _free_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return int(s.getsockname()[1])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="exposure", description="Local personal exposure engine")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0, help="0 = pick a free port")
    parser.add_argument("--workspace", default=None, help="override the workspace directory")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args(argv)

    if not _is_loopback(args.host):
        print(f"refusing to bind non-loopback host: {args.host}", file=sys.stderr)
        return 2

    host = "127.0.0.1" if args.host == "localhost" else args.host
    port = args.port or _free_port(host)

    settings = Settings(host=host, port=port)
    if args.workspace:
        from pathlib import Path

        settings.workspace = Path(args.workspace).expanduser().resolve()
    settings.ensure_dirs()

    db = Database(settings)
    db.connect()
    service = Service(settings, db)
    guard = SessionGuard(host, port)
    app = create_app(settings, service, guard)

    url = f"http://{host}:{port}"
    print(f"Exposure {APP_VERSION}")
    print(f"  → {url}")
    print(f"  workspace: {settings.workspace}")
    print("  Local-first: no account, no telemetry, no required cloud backend.")

    if not args.no_browser:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()

    uvicorn.run(app, host=host, port=port, log_level="warning")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
