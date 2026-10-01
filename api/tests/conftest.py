import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, "/app")

# Point the data dir at a temp location BEFORE importing anything that
# reads settings - tests must never touch the production database.
os.environ.setdefault("DATA_DIR", "/tmp/soc_test_data")

import pytest


@pytest.fixture()
def fresh_db(tmp_path, monkeypatch):
    """Re-point the DB to a fresh temp file per test (module-level
    constants are already bound, so we patch the path directly)."""
    import database
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(database, "DB_PATH", str(db_path))
    database.init_db()
    return database