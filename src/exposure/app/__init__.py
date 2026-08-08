"""Local web application (FastAPI + embedded single-page UI)."""

from __future__ import annotations

from exposure.app.main import create_app
from exposure.app.service import Service, ServiceError

__all__ = ["create_app", "Service", "ServiceError"]
