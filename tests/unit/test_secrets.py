"""Secret storage: data-key handling, API-key vault, and purge.

Both backends are exercised: the encrypted-file fallback and a stubbed OS
keyring.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from exposure.storage import secrets as secrets_mod
from exposure.storage.secrets import SecretStore

# --------------------------------------------------------------------------- #
# File-backed fallback
# --------------------------------------------------------------------------- #


def test_field_encryption_roundtrip(tmp_path: Path) -> None:
    store = SecretStore(tmp_path, use_keyring=False)
    token = store.encrypt_field("jane@example.com")
    assert b"jane@example.com" not in token
    assert store.decrypt_field(token) == "jane@example.com"


def test_data_key_is_persisted_and_reused(tmp_path: Path) -> None:
    first = SecretStore(tmp_path, use_keyring=False)
    token = first.encrypt_field("secret")
    # A fresh store over the same workspace must decrypt what the first wrote.
    second = SecretStore(tmp_path, use_keyring=False)
    assert second.decrypt_field(token) == "secret"


def test_key_file_permissions_are_owner_only(tmp_path: Path) -> None:
    store = SecretStore(tmp_path, use_keyring=False)
    store.encrypt_field("x")
    mode = stat.S_IMODE((tmp_path / ".datakey").stat().st_mode)
    assert mode == 0o600


def test_api_key_vault_roundtrip(tmp_path: Path) -> None:
    store = SecretStore(tmp_path, use_keyring=False)
    assert store.get_api_key("brave") is None
    store.set_api_key("brave", "sk-test-123")
    assert store.get_api_key("brave") == "sk-test-123"

    # Reload from disk.
    assert SecretStore(tmp_path, use_keyring=False).get_api_key("brave") == "sk-test-123"


def test_api_key_is_encrypted_at_rest(tmp_path: Path) -> None:
    store = SecretStore(tmp_path, use_keyring=False)
    store.set_api_key("brave", "sk-plaintext-should-not-appear")
    blob = (tmp_path / ".secrets.enc").read_bytes()
    assert b"sk-plaintext-should-not-appear" not in blob


def test_vault_file_permissions(tmp_path: Path) -> None:
    store = SecretStore(tmp_path, use_keyring=False)
    store.set_api_key("brave", "k")
    mode = stat.S_IMODE((tmp_path / ".secrets.enc").stat().st_mode)
    assert mode == 0o600


def test_delete_api_key(tmp_path: Path) -> None:
    store = SecretStore(tmp_path, use_keyring=False)
    store.set_api_key("brave", "k")
    store.delete_api_key("brave")
    assert store.get_api_key("brave") is None
    store.delete_api_key("missing")  # no error


def test_env_var_overrides_vault(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = SecretStore(tmp_path, use_keyring=False)
    store.set_api_key("brave", "from-vault")
    monkeypatch.setenv("EXPOSURE_BRAVE_API_KEY", "from-env")
    assert store.get_api_key("brave") == "from-env"


def test_purge_removes_all_local_material(tmp_path: Path) -> None:
    store = SecretStore(tmp_path, use_keyring=False)
    store.set_api_key("brave", "k")
    store.encrypt_field("x")
    assert (tmp_path / ".datakey").exists() and (tmp_path / ".secrets.enc").exists()
    store.purge()
    assert not (tmp_path / ".datakey").exists()
    assert not (tmp_path / ".secrets.enc").exists()
    store.purge()  # idempotent


def test_chmod_failure_is_tolerated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: object, **__: object) -> None:
        raise OSError("no chmod on this filesystem")

    monkeypatch.setattr(os, "chmod", boom)
    store = SecretStore(tmp_path, use_keyring=False)
    assert store.decrypt_field(store.encrypt_field("v")) == "v"


# --------------------------------------------------------------------------- #
# Keyring-backed path (stubbed)
# --------------------------------------------------------------------------- #


class _FakeKeyring:
    def __init__(self) -> None:
        self.store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, name: str) -> str | None:
        return self.store.get((service, name))

    def set_password(self, service: str, name: str, value: str) -> None:
        self.store[(service, name)] = value

    def delete_password(self, service: str, name: str) -> None:
        del self.store[(service, name)]  # raises KeyError if absent


@pytest.fixture
def fake_keyring(monkeypatch: pytest.MonkeyPatch) -> _FakeKeyring:
    fake = _FakeKeyring()
    monkeypatch.setattr(secrets_mod, "_keyring", fake)
    monkeypatch.setattr(secrets_mod, "_HAVE_KEYRING", True)
    return fake


def test_keyring_data_key_roundtrip(tmp_path: Path, fake_keyring: _FakeKeyring) -> None:
    store = SecretStore(tmp_path, use_keyring=True)
    token = store.encrypt_field("hello")
    assert store.decrypt_field(token) == "hello"
    # Key lives in the keyring, not on disk.
    assert not (tmp_path / ".datakey").exists()
    assert fake_keyring.store

    # A second store reuses the same key from the keyring.
    assert SecretStore(tmp_path, use_keyring=True).decrypt_field(token) == "hello"


def test_keyring_api_key_roundtrip(tmp_path: Path, fake_keyring: _FakeKeyring) -> None:
    store = SecretStore(tmp_path, use_keyring=True)
    store.set_api_key("brave", "sk-keyring")
    assert store.get_api_key("brave") == "sk-keyring"
    assert not (tmp_path / ".secrets.enc").exists()
    store.delete_api_key("brave")
    assert store.get_api_key("brave") is None


def test_keyring_delete_missing_key_is_tolerated(
    tmp_path: Path, fake_keyring: _FakeKeyring
) -> None:
    SecretStore(tmp_path, use_keyring=True).delete_api_key("never-set")


def test_keyring_purge_tolerates_backend_error(
    tmp_path: Path, fake_keyring: _FakeKeyring
) -> None:
    store = SecretStore(tmp_path, use_keyring=True)
    store.encrypt_field("x")
    fake_keyring.store.clear()  # make delete_password raise KeyError
    store.purge()  # must not propagate
