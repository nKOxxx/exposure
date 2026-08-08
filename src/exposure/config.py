"""Application configuration and filesystem locations.

All persistent state lives under a single workspace directory so that "delete
all Exposure data" (spec section 21) is a single, auditable operation.
"""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass, field
from pathlib import Path


def default_workspace() -> Path:
    """Return the default workspace directory, honoring ``EXPOSURE_HOME``."""
    override = os.environ.get("EXPOSURE_HOME")
    if override:
        return Path(override).expanduser().resolve()
    base = os.environ.get("XDG_DATA_HOME")
    if base:
        return Path(base).expanduser().resolve() / "exposure"
    return Path.home() / ".exposure"


@dataclass(slots=True)
class Settings:
    """Runtime settings. Deliberately not read from the network."""

    workspace: Path = field(default_factory=default_workspace)
    host: str = "127.0.0.1"
    port: int = 0  # 0 => choose a free ephemeral port at startup

    # Retrieval budget (spec sections 8, 37).
    connect_timeout_s: float = 5.0
    total_timeout_s: float = 10.0
    max_redirects: int = 5
    max_html_bytes: int = 5 * 1024 * 1024
    max_pdf_bytes: int = 15 * 1024 * 1024
    global_concurrency: int = 8
    per_domain_concurrency: int = 2
    max_documents_per_scan: int = 100
    max_scan_bytes: int = 100 * 1024 * 1024

    # Discovery budget (spec section 7).
    max_queries: int = 15
    max_results_per_query: int = 10
    max_candidate_urls: int = 100

    # AI is off by default (spec section 25).
    ai_mode: str = "NO_AI"  # NO_AI | LOCAL_AI | REMOTE_AI

    @property
    def db_path(self) -> Path:
        return self.workspace / "exposure.sqlite3"

    @property
    def cache_dir(self) -> Path:
        return self.workspace / "cache"

    @property
    def export_dir(self) -> Path:
        return self.workspace / "exports"

    @property
    def secrets_path(self) -> Path:
        return self.workspace / ".secrets.enc"

    @property
    def log_path(self) -> Path:
        return self.workspace / "exposure.log"

    def ensure_dirs(self) -> None:
        self.workspace.mkdir(parents=True, exist_ok=True)
        # Workspace may contain sensitive data — restrict to the owner.
        with contextlib.suppress(OSError):
            os.chmod(self.workspace, 0o700)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.export_dir.mkdir(parents=True, exist_ok=True)
