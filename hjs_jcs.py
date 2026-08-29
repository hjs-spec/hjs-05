"""RFC 8785 canonicalization and HJS-Core-1 behavior-record digests.

HJS draft -05 section 4.5 hashes the UTF-8 octets of the entire
JCS-canonicalized behavior-record JSON object. This module intentionally
does not remove fields, omit null values, or apply protocol-specific
preprocessing before canonicalization.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

import jcs


HJS_CORE1_REQUIRED_FIELDS = frozenset(
    {"hjs_record", "record_type", "agent", "action", "created_at", "evidence"}
)


def canonicalize_jcs(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 representation of ``value``."""

    return jcs.canonicalize(value)


def canonical_sha256(value: Any) -> str:
    """Return lowercase SHA-256 hex over the JCS canonical bytes."""

    return hashlib.sha256(canonicalize_jcs(value)).hexdigest()


def validate_hjs_core1_behavior_record(record: Mapping[str, Any]) -> None:
    """Validate the minimal structural requirements used by HJS-Core-1."""

    if not isinstance(record, Mapping):
        raise TypeError("an HJS behavior record must be a JSON object")

    missing = sorted(HJS_CORE1_REQUIRED_FIELDS.difference(record))
    if missing:
        raise ValueError(f"missing HJS-Core-1 fields: {', '.join(missing)}")

    if record["hjs_record"] != "1":
        raise ValueError('hjs_record must be "1"')
    if record["record_type"] != "behavior":
        raise ValueError('record_type must be "behavior"')

    agent = record["agent"]
    if not isinstance(agent, Mapping) or not agent.get("id"):
        raise ValueError("agent must be an object containing a non-empty id")

    action = record["action"]
    if not isinstance(action, Mapping) or not action.get("type"):
        raise ValueError("action must be an object containing a non-empty type")

    if not isinstance(record["evidence"], Mapping):
        raise ValueError("evidence must be a JSON object")

    if "event_hash" in record or "jep_event_hash" in record:
        raise ValueError(
            "HJS-Core-1 behavior records must not contain the signing JEP event hash"
        )


def digest_behavior_record(record: Mapping[str, Any]) -> str:
    """Return the HJS/JEP algorithm-tagged digest of a whole behavior record."""

    validate_hjs_core1_behavior_record(record)
    return f"sha256:{canonical_sha256(record)}"
