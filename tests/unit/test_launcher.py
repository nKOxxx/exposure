"""Launcher behaviour (`exposure.__main__`).

The launcher is a release gate in its own right: it must never bind a
non-loopback interface (spec section 20).
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from exposure import __main__ as launcher


@pytest.mark.parametrize(
    "host,expected",
    [
        ("127.0.0.1", True),
        ("localhost", True),
        ("::1", True),
        ("0.0.0.0", False),  # noqa: S104 - asserting we REFUSE all-interfaces
        ("192.168.1.10", False),
        ("example.com", False),
        ("", False),
    ],
)
def test_is_loopback(host: str, expected: bool) -> None:
    assert launcher._is_loopback(host) is expected


def test_free_port_returns_bindable_port() -> None:
    port = launcher._free_port("127.0.0.1")
    assert 1024 < port < 65536
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", port))  # still free


def test_refuses_non_loopback_host(capsys: pytest.CaptureFixture[str]) -> None:
    rc = launcher.main(["--host", "0.0.0.0", "--no-browser"])  # noqa: S104
    assert rc == 2
    assert "refusing to bind non-loopback" in capsys.readouterr().err


def test_main_starts_server_on_loopback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """main() wires everything and hands a loopback-bound app to uvicorn."""
    captured: dict[str, object] = {}

    def fake_run(app: object, host: str, port: int, log_level: str) -> None:
        captured["host"] = host
        captured["port"] = port
        captured["app"] = app

    monkeypatch.setattr(launcher.uvicorn, "run", fake_run)

    rc = launcher.main(
        ["--no-browser", "--port", "8912", "--workspace", str(tmp_path / "ws")]
    )
    assert rc == 0
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 8912
    assert (tmp_path / "ws").is_dir()

    out = capsys.readouterr().out
    assert "http://127.0.0.1:8912" in out
    assert "no account, no telemetry" in out


def test_localhost_is_normalised_to_127(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        launcher.uvicorn,
        "run",
        lambda app, host, port, log_level: captured.update(host=host),
    )
    launcher.main(
        ["--no-browser", "--host", "localhost", "--port", "8913",
         "--workspace", str(tmp_path / "ws")]
    )
    assert captured["host"] == "127.0.0.1"


def test_browser_opens_when_not_suppressed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    timers: list[object] = []

    class FakeTimer:
        def __init__(self, delay: float, fn: object) -> None:
            timers.append(fn)

        def start(self) -> None:
            pass

    monkeypatch.setattr(launcher.threading, "Timer", FakeTimer)
    monkeypatch.setattr(launcher.uvicorn, "run", lambda **kw: None)
    monkeypatch.setattr(
        launcher.uvicorn, "run", lambda app, host, port, log_level: None
    )
    launcher.main(["--port", "8914", "--workspace", str(tmp_path / "ws")])
    assert timers, "expected a browser-open timer to be scheduled"


def test_port_zero_picks_free_port(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        launcher.uvicorn,
        "run",
        lambda app, host, port, log_level: captured.update(port=port),
    )
    launcher.main(["--no-browser", "--port", "0", "--workspace", str(tmp_path / "ws")])
    assert isinstance(captured["port"], int) and captured["port"] > 0
