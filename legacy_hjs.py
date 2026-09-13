"""Explicit integrity-only reader for historical raw Ed25519 HJS events.

No new legacy events are emitted. Historical JCS bytes and sig fields remain
unchanged. This is not a Core 0.6, chain, policy or replay acceptance result.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from hjs_jcs import canonicalize_jcs
from jep_conformance.jep_validate import b64u_decode, ValidationFault


def verify_legacy_event(event, trusted_public_key_pem):
    try:
        if not isinstance(event, dict) or not isinstance(event.get("sig"), str):
            raise ValueError("Historical event and raw signature required")
        key = serialization.load_pem_public_key(trusted_public_key_pem.encode())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("An Ed25519 public key is required")
        signature = b64u_decode(event["sig"], label="legacy signature")
        key.verify(
            signature, canonicalize_jcs({k: v for k, v in event.items() if k != "sig"})
        )
        return {
            "valid": True,
            "profile": "hjs-legacy-raw-ed25519",
            "scopes": ["legacy_signature"],
            "core_conformance": False,
            "acceptance_checked": False,
        }
    except (ValueError, TypeError, InvalidSignature, ValidationFault) as exc:
        return {
            "valid": False,
            "profile": "hjs-legacy-raw-ed25519",
            "errors": [str(exc)],
        }
