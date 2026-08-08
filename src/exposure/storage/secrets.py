"""Secret storage: at-rest field encryption key and API-key vault.

Two kinds of secret:

* **Data key** — a symmetric key used to encrypt sensitive identifier values
  (emails, phones) stored in SQLite. Without it, a leaked ``.sqlite3`` file does
  not disclose those values.
* **API keys** — Brave / AI provider credentials. These must never appear in
  SQLite, logs, exports, or query strings (spec sections 20-22).

Preferred backend is the OS keyring (``keyring`` extra). When it is not
available we fall back to a Fernet-encrypted file with ``0o600`` permissions.
The fallback is honest about its limitation: the data key then lives next to the
data, protected by file permissions rather than the OS secret service.
"""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet

_KEYRING_SERVICE = "exposure-scan"
_DATA_KEY_NAME = "data-key"

try:  # optional dependency
    import keyring as _keyring

    _HAVE_KEYRING = True
except Exception:  # pragma: no cover - depends on environment
    _keyring = None
    _HAVE_KEYRING = False


class SecretStore:
    """Manages the data key and the API-key vault for one workspace."""

    def __init__(self, workspace: Path, use_keyring: bool | None = None) -> None:
        self._workspace = workspace
        self._key_file = workspace / ".datakey"
        self._vault_file = workspace / ".secrets.enc"
        self._use_keyring = _HAVE_KEYRING if use_keyring is None else use_keyring
        self._fernet: Fernet | None = None

    # -- data key ----------------------------------------------------------- #

    def _load_or_create_data_key(self) -> bytes:
        # 1) OS keyring
        if self._use_keyring and _keyring is not None:
            existing = _keyring.get_password(_KEYRING_SERVICE, _DATA_KEY_NAME)
            if existing:
                return str(existing).encode("ascii")
            key = Fernet.generate_key()
            _keyring.set_password(_KEYRING_SERVICE, _DATA_KEY_NAME, key.decode("ascii"))
            return key
        # 2) file fallback (0o600)
        if self._key_file.exists():
            return self._key_file.read_bytes().strip()
        self._workspace.mkdir(parents=True, exist_ok=True)
        key = Fernet.generate_key()
        self._key_file.write_bytes(key)
        with contextlib.suppress(OSError):
            os.chmod(self._key_file, 0o600)
        return key

    def _get_fernet(self) -> Fernet:
        if self._fernet is None:
            self._fernet = Fernet(self._load_or_create_data_key())
        return self._fernet

    def encrypt_field(self, plaintext: str) -> bytes:
        return self._get_fernet().encrypt(plaintext.encode("utf-8"))

    def decrypt_field(self, token: bytes) -> str:
        return self._get_fernet().decrypt(token).decode("utf-8")

    # -- API-key vault ------------------------------------------------------ #

    def set_api_key(self, name: str, value: str) -> None:
        if self._use_keyring and _keyring is not None:
            _keyring.set_password(_KEYRING_SERVICE, f"api:{name}", value)
            return
        vault = self._read_vault()
        vault[name] = value
        self._write_vault(vault)

    def get_api_key(self, name: str) -> str | None:
        env = os.environ.get(f"EXPOSURE_{name.upper()}_API_KEY")
        if env:
            return env
        if self._use_keyring and _keyring is not None:
            result = _keyring.get_password(_KEYRING_SERVICE, f"api:{name}")
            return str(result) if result is not None else None
        return self._read_vault().get(name)

    def delete_api_key(self, name: str) -> None:
        if self._use_keyring and _keyring is not None:
            with contextlib.suppress(Exception):  # pragma: no cover - backend specific
                _keyring.delete_password(_KEYRING_SERVICE, f"api:{name}")
            return
        vault = self._read_vault()
        vault.pop(name, None)
        self._write_vault(vault)

    def _read_vault(self) -> dict[str, str]:
        if not self._vault_file.exists():
            return {}
        raw = self._get_fernet().decrypt(self._vault_file.read_bytes())
        data = json.loads(raw.decode("utf-8"))
        return {str(k): str(v) for k, v in data.items()}

    def _write_vault(self, vault: dict[str, str]) -> None:
        self._workspace.mkdir(parents=True, exist_ok=True)
        token = self._get_fernet().encrypt(json.dumps(vault).encode("utf-8"))
        self._vault_file.write_bytes(token)
        with contextlib.suppress(OSError):
            os.chmod(self._vault_file, 0o600)

    # -- teardown ----------------------------------------------------------- #

    def purge(self) -> None:
        """Remove local key material and the vault (part of delete-all)."""
        for f in (self._key_file, self._vault_file):
            with contextlib.suppress(FileNotFoundError):
                f.unlink()
        if self._use_keyring and _keyring is not None:
            for name in (_DATA_KEY_NAME,):
                with contextlib.suppress(Exception):  # pragma: no cover
                    _keyring.delete_password(_KEYRING_SERVICE, name)
        self._fernet = None
