"""Detached Ed25519 signatures over the canonical bytes of a binding manifest.

The signature is DETACHED and the manifest never carries it, for the reason
section 3 of the contract gives: a record that contained its own signature
would have to define what the signature covers by excluding a field from
itself, and every such rule is one more thing two implementations can read
differently. The manifest is a file, the signature is a file beside it, and the
preimage is the manifest's bytes exactly as stored.

Key handling is deliberately small. A private key is a raw Ed25519 seed of
``SEED_LENGTH`` bytes, read from a file or from an environment variable holding
its hexadecimal form. There is no key server, no certificate and no
transparency log: verification is offline, and a contract whose checking needs
a service is one a relying party cannot re-run in five years.

Dependency note: this module needs ``cryptography`` (already declared by this
repository for the vector generators). The reference verification RAIL under
``packaging/`` stays stdlib-only and is untouched by this tool.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

SEED_LENGTH = 32
SIGNATURE_LENGTH = 64


class KeyError_(ValueError):
    """A key could not be read, and the tool refuses rather than guessing."""


def public_bytes(private_seed: bytes) -> bytes:
    """The raw 32-byte public key for *private_seed*."""
    key = Ed25519PrivateKey.from_private_bytes(private_seed)
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def key_id(public_key: bytes) -> str:
    """The identity a consumer pins: SHA-256 over the raw public key bytes."""
    return hashlib.sha256(public_key).hexdigest()


def load_seed(path: Path | None = None, env_var: str = "AEE_BIND_KEY") -> bytes:
    """Read a private seed from a file, or from *env_var* holding its hex form."""
    if path is not None:
        raw = path.read_bytes().strip()
        seed = bytes.fromhex(raw.decode("utf-8")) if len(raw) == SEED_LENGTH * 2 else raw
    else:
        value = os.environ.get(env_var)
        if not value:
            raise KeyError_(
                f"no signing key: pass a key file or set {env_var} to a 64-character "
                "hexadecimal Ed25519 seed"
            )
        seed = bytes.fromhex(value.strip())
    if len(seed) != SEED_LENGTH:
        raise KeyError_(f"an Ed25519 seed is {SEED_LENGTH} bytes, got {len(seed)}")
    return seed


def load_public(path: Path) -> bytes:
    """Read a raw or hexadecimal 32-byte public key."""
    raw = path.read_bytes().strip()
    key = bytes.fromhex(raw.decode("utf-8")) if len(raw) == SEED_LENGTH * 2 else raw
    if len(key) != SEED_LENGTH:
        raise KeyError_(f"an Ed25519 public key is {SEED_LENGTH} bytes, got {len(key)}")
    return key


def sign_bytes(private_seed: bytes, message: bytes) -> bytes:
    """A detached 64-byte signature over *message*."""
    return Ed25519PrivateKey.from_private_bytes(private_seed).sign(message)


def verify_bytes(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Whether *signature* verifies over *message* under *public_key*."""
    if len(signature) != SIGNATURE_LENGTH:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except Exception:
        return False
    return True
