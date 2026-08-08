from __future__ import annotations

import sqlite3

import pytest

from exposure.domain.models import Name, SecretField, Subject
from exposure.security.redaction import mask_email
from exposure.storage.database import Database


def test_subject_roundtrip_encrypts_sensitive(db: Database) -> None:
    subject = Subject(
        names=[Name(value="Jane Example", is_primary=True)],
        emails=[SecretField(value="jane@example.com", display=mask_email("jane@example.com"))],
    )
    db.create_subject(subject)
    loaded = db.get_subject(subject.id)
    assert loaded is not None
    assert loaded.primary_name == "Jane Example"
    assert loaded.emails[0].value == "jane@example.com"  # decrypts

    # Raw value must NOT be stored in plaintext.
    raw = sqlite3.connect(db.settings.db_path).execute(
        "SELECT value_enc FROM subject_identifiers"
    ).fetchone()[0]
    assert b"jane@example.com" not in raw


def test_provider_settings_rejects_secret_fields(db: Database) -> None:
    with pytest.raises(ValueError):
        db.set_provider("brave", "search", True, {"api_key": "leak"})


def test_delete_all_removes_db_file(db: Database) -> None:
    subject = Subject(names=[Name(value="Jane", is_primary=True)])
    db.create_subject(subject)
    path = db.settings.db_path
    assert path.exists()
    db.delete_all()
    assert not path.exists()


def test_migrations_are_idempotent(db: Database) -> None:
    # Re-running migrate on an already-migrated DB must be a no-op.
    db.migrate()
    count = db.conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
    db.migrate()
    assert db.conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == count
