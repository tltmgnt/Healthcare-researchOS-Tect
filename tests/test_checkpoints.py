import json

from tect.checkpoints import export_checkpoint, verify_checkpoint, write_checkpoint
from tect.models import Claim
from tect.storage import save_claim


def test_checkpoint_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "db.sqlite3"))
    save_claim(Claim(id="one", text="Synthetic"), expected_version=0)
    manifest = export_checkpoint()
    assert verify_checkpoint(manifest)["valid"] is True
    path = tmp_path / "checkpoint.json"
    write_checkpoint(path)
    assert verify_checkpoint(json.loads(path.read_text()))["valid"] is True


def test_checkpoint_detects_manifest_tampering(tmp_path, monkeypatch):
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "db.sqlite3"))
    save_claim(Claim(id="one", text="Synthetic"), expected_version=0)
    manifest = export_checkpoint()
    manifest["head_hash"] = "0" * 64
    assert verify_checkpoint(manifest)["valid"] is False


def test_checkpoint_detects_later_head(tmp_path, monkeypatch):
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "db.sqlite3"))
    save_claim(Claim(id="one", text="Synthetic"), expected_version=0)
    manifest = export_checkpoint()
    save_claim(Claim(id="two", text="Synthetic"), expected_version=0)
    assert verify_checkpoint(manifest)["reason"] == "head_mismatch"


def test_checkpoint_refuses_overwrite(tmp_path, monkeypatch):
    import pytest
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "db.sqlite3"))
    path = tmp_path / "anchor.json"
    write_checkpoint(path)
    with pytest.raises(FileExistsError):
        write_checkpoint(path)
