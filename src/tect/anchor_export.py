"""Portable signed checkpoint export for separately controlled anchor storage.

This module writes a file; it does not upload or independently retain anchors.
"""
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .ed25519_checkpoints import sign_checkpoint
from .historical_audit import verify_historical_signed_checkpoint


def export_signed_anchor(path: str | Path, private_key: Ed25519PrivateKey, key_id: str) -> dict:
    """Create a new, exclusive file with a signed checkpoint; never overwrite."""
    envelope = sign_checkpoint(private_key, key_id)
    target = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(target, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(envelope, stream, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            target.unlink()
        except OSError:
            pass
        raise
    return envelope


def verify_anchor_file(path: str | Path, trusted_public_keys: dict[str, Ed25519PublicKey]) -> dict:
    """Verify externally retrieved anchor against the local historical audit log."""
    try:
        with Path(path).open("r", encoding="utf-8") as stream:
            envelope = json.load(stream)
    except (OSError, ValueError, UnicodeError):
        return {"valid": False, "reason": "unreadable_anchor"}
    return verify_historical_signed_checkpoint(envelope, trusted_public_keys)
