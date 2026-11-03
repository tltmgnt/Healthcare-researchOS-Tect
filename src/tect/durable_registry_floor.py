"""Atomic SQLite anti-rollback floor for signed reviewer registries.

Deploy database under a separate security authority. Local SQLite does not
itself guarantee independent custody or rollback-proof infrastructure.
"""
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime

from .signed_trust_registry import verify_release_with_signed_registry

SCHEMA = "tect.durable-registry-floor.v1"


class RegistryFloorStore:
    """Persistent floor with SQLite write-lock serialization and monotonic CAS."""

    def __init__(self, path: str):
        if not isinstance(path, str) or not path.strip() or path == ":memory:":
            raise ValueError("Persistent SQLite file path required")
        self.path = path

    @contextmanager
    def locked(self):
        # Do not silently create a new floor database: that would permit reset.
        if not os.path.isfile(self.path):
            raise FileNotFoundError("Provisioned registry floor database required")
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            db.execute("PRAGMA busy_timeout=10000")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def provision(path: str, *, initial_sequence: int) -> "RegistryFloorStore":
        """One-time trusted bootstrap; refuses existing paths."""
        if type(initial_sequence) is not int or initial_sequence < 1:
            raise ValueError("Positive initial sequence required")
        if not isinstance(path, str) or not path.strip() or path == ":memory:":
            raise ValueError("Persistent SQLite file path required")
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        try:
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE registry_floor (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), sequence INTEGER NOT NULL CHECK(sequence >= 1))")
                db.execute("INSERT INTO registry_floor VALUES (1, ?)", (initial_sequence,))
                db.commit()
        except BaseException:
            os.unlink(path)
            raise
        return RegistryFloorStore(path)

    @staticmethod
    def _read(db) -> int:
        try:
            rows = db.execute("SELECT singleton, sequence FROM registry_floor").fetchall()
        except sqlite3.DatabaseError as exc:
            raise ValueError("Invalid floor database") from exc
        if (len(rows) != 1 or rows[0][0] != 1
                or type(rows[0][1]) is not int or rows[0][1] < 1):
            raise ValueError("Missing or corrupt floor state")
        return rows[0][1]

    def read(self) -> int:
        with self.locked() as db:
            return self._read(db)

    def compare_and_advance(self, *, expected_floor: int, new_sequence: int) -> bool:
        """Advance only if the independently stored floor matches expectation."""
        if (type(expected_floor) is not int or expected_floor < 1
                or type(new_sequence) is not int or new_sequence < expected_floor):
            raise ValueError("Invalid sequence")
        with self.locked() as db:
            current = self._read(db)
            if current != expected_floor:
                return False
            if new_sequence > current:
                db.execute("UPDATE registry_floor SET sequence=? WHERE singleton=1 AND sequence=?",
                           (new_sequence, current))
                if db.execute("SELECT changes()").fetchone()[0] != 1:
                    raise RuntimeError("Floor update failed")
            return True


def verify_release_with_durable_floor(release_envelope: dict, artifacts: dict,
                                      registry_envelope: dict, trusted_authorities: dict,
                                      store: RegistryFloorStore, *,
                                      expected_submitter_id: str,
                                      assessed_at: datetime) -> dict:
    """Serialize verification and floor advancement within a single write lock."""
    if not isinstance(store, RegistryFloorStore):
        raise ValueError("RegistryFloorStore required")
    with store.locked() as db:
        minimum = store._read(db)
        result = verify_release_with_signed_registry(
            release_envelope, artifacts, registry_envelope, trusted_authorities,
            minimum_sequence=minimum, expected_submitter_id=expected_submitter_id,
            assessed_at=assessed_at)
        if not result.get("release_evidence_ready"):
            return {**result, "schema": SCHEMA, "floor_before": minimum,
                    "floor_after": minimum, "floor_advanced": False}
        sequence = result["registry_sequence"]
        if type(sequence) is not int or sequence < minimum:
            raise ValueError("Invalid verified registry sequence")
        if sequence > minimum:
            db.execute("UPDATE registry_floor SET sequence=? WHERE singleton=1 AND sequence=?",
                       (sequence, minimum))
            if db.execute("SELECT changes()").fetchone()[0] != 1:
                raise RuntimeError("Floor update failed")
        return {**result, "schema": SCHEMA, "floor_before": minimum,
                "floor_after": sequence, "floor_advanced": sequence > minimum,
                "limitations": "SQLite is durable only within its own trust boundary; independent protected storage, backups, access controls and rollback resistance remain deployment obligations"}
