"""Portable Ed25519 composite anchors; storage remains operator-controlled."""
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .composite_anchors import sign_composite_anchor, verify_composite_anchor
from .storage import canonical

MAX_ANCHOR_BYTES = 64 * 1024


def export_composite_anchor(path: str | Path, private_key: Ed25519PrivateKey, key_id: str) -> dict:
    """Write an exclusively created 0600 file; never overwrite an existing anchor."""
    envelope = sign_composite_anchor(private_key, key_id)
    content = (canonical(envelope) + "\n").encode("utf-8")
    if len(content) > MAX_ANCHOR_BYTES:
        raise ValueError("Anchor exceeds maximum size")
    target = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(target, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            target.unlink()
        except OSError:
            pass
        raise
    return envelope


def verify_composite_anchor_file(path: str | Path, trusted_public_keys: dict[str, Ed25519PublicKey]) -> dict:
    """Verify a separately retained anchor against both live audit histories."""
    try:
        with Path(path).open("rb") as stream:
            body = stream.read(MAX_ANCHOR_BYTES + 1)
        if len(body) > MAX_ANCHOR_BYTES:
            return {"valid": False, "reason": "anchor_too_large"}
        envelope = json.loads(body.decode("utf-8"))
    except (OSError, UnicodeError, ValueError):
        return {"valid": False, "reason": "unreadable_anchor"}
    return verify_composite_anchor(envelope, trusted_public_keys)
