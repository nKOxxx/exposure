"""Shared test fixtures."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from exposure.app.service import Service
from exposure.config import Settings
from exposure.retrieval.client import SecureRetriever
from exposure.storage.database import Database


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(host="127.0.0.1", port=8799, workspace=tmp_path / "ws")


@pytest.fixture
def db(settings: Settings) -> Database:
    database = Database(settings)
    database.connect()
    yield database
    database.close()


def make_mock_retriever_factory(
    handler: Callable[[httpx.Request], httpx.Response],
) -> Callable[[Settings], SecureRetriever]:
    """Build a retriever factory whose retrievers use a MockTransport."""

    def factory(s: Settings) -> SecureRetriever:
        return SecureRetriever(s, transport=httpx.MockTransport(handler))

    return factory


@pytest.fixture
def service(settings: Settings, db: Database) -> Service:
    return Service(settings, db)
