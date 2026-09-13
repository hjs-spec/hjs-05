"""HJS companion helpers over the pinned JEP-Core-0.6 validator.

HJS behavior-record canonical bytes remain in hjs_jcs.py. Core events use
jep_conformance, not an independent interpretation of JEP signatures.
"""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import threading
import time
import uuid
from urllib.parse import urljoin

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from jep_conformance import jep_validate as core

IMMUTABLE_FIELDS = tuple(sorted(core.TOP_LEVEL_FIELDS))
HUMAN_CONFIGURABLE_FIELDS = ["who"]  # Configurable before signing only.


def compute_event_hash(event):
    return core.event_hash(event)


def algorithm_tagged_digest(content, alg="sha256"):
    if alg != "sha256":
        raise ValueError("This implementation supports sha256 only")
    if isinstance(content, str):
        content = content.encode("utf-8")
    return "sha256:" + hashlib.sha256(content).hexdigest()


def public_jwk(public_key, kid=None):
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("An Ed25519 public key is required")
    raw = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "Ed25519",
        "use": "sig",
        "key_ops": ["verify"],
        "x": core.b64u(raw),
        "kid": kid or "hjs-" + hashlib.sha256(raw).hexdigest(),
    }


class HJSEvent:
    """Build a Core event; string content becomes a digest, objects stay typed."""

    def __init__(
        self,
        verb,
        who_raw,
        what_content,
        aud=None,
        ref=None,
        privacy_mode="plaintext",
        salt=None,
        ttl_minutes=0,
        identity_rotation=False,
    ):
        if not isinstance(who_raw, str) or not who_raw.strip():
            raise ValueError("who is required")
        if privacy_mode not in {
            "plaintext",
            "digest_only",
            "ephemeral_did",
            "pubkey_hash",
        }:
            raise ValueError("Unsupported privacy mode")
        if type(ttl_minutes) is not int or ttl_minutes < 0:
            raise ValueError("TTL must be a non-negative integer")
        self.jep, self.verb = "1", verb
        self.when, self.nonce, self.ref = (
            int(time.time()),
            str(uuid.uuid4()),
            deepcopy(ref),
        )
        self.what = (
            algorithm_tagged_digest(what_content)
            if isinstance(what_content, str)
            else deepcopy(what_content)
        )
        self.who = who_raw
        if privacy_mode == "digest_only":
            if not isinstance(salt, str) or not salt:
                raise ValueError(
                    "A caller-supplied salt is required for digest-only mode"
                )
            self.who = algorithm_tagged_digest(who_raw + ":" + salt)
        elif privacy_mode == "ephemeral_did":
            self.who = "did:hjs:tmp:" + uuid.uuid4().hex
        elif privacy_mode == "pubkey_hash":
            # This mode must hash a real public key, not an arbitrary identity string.
            key = serialization.load_pem_public_key(who_raw.encode())
            self.who = algorithm_tagged_digest(
                key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        self.aud, self.sig = aud, None
        self.extensions = {}
        if privacy_mode != "plaintext" or identity_rotation:
            self.extensions["https://hjs.org/privacy"] = {
                "mode": privacy_mode,
                "rotation_requested": bool(identity_rotation),
            }
        if ttl_minutes:
            self.extensions["https://hjs.org/retention"] = {
                "expires_at": self.when + ttl_minutes * 60,
                "metadata_only": True,
            }
        self._signed_dict = None

    def to_dict(self, include_sig=True):
        data = {
            "jep": self.jep,
            "verb": self.verb,
            "who": self.who,
            "when": self.when,
            "what": deepcopy(self.what),
            "nonce": self.nonce,
            "ref": deepcopy(self.ref),
        }
        if self.aud is not None:
            data["aud"] = self.aud
        if self.extensions:
            data["ext"] = deepcopy(self.extensions)
        if include_sig and self.sig is not None:
            data["sig"] = self.sig
        return data

    def canonicalize(self):
        return core.canonicalize(self.to_dict(include_sig=False))

    def sign(self, signer):
        if self.sig is not None:
            raise ValueError("Create a new event to change signed content")
        self.sig = signer.sign(self.canonicalize())
        self._signed_dict = self.to_dict()
        return self.to_dict()

    def check_immutability(self, modified_dict):
        original = (
            self._signed_dict if self._signed_dict is not None else self.to_dict()
        )
        equal = original == modified_dict
        return equal, (
            "Signed members unchanged"
            if equal
            else "IMMUTABILITY VIOLATION: signed members changed or removed"
        )


class HJSSigner:
    def __init__(self, private_key=None):
        self.private_key = private_key or Ed25519PrivateKey.generate()
        if not isinstance(self.private_key, Ed25519PrivateKey):
            raise ValueError("An Ed25519 private key is required")
        self.public_key = self.private_key.public_key()
        self.jwk = public_jwk(self.public_key)

    def get_public_key_pem(self):
        return self.public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def sign(self, payload_bytes):
        event = core.parse_json_text(payload_bytes.decode("utf-8"))
        if not isinstance(event, dict) or "sig" in event:
            raise ValueError("Sign an unsigned Core event object")
        payload = core.canonicalize(event)
        header = core.b64u(
            core.canonicalize({"alg": "Ed25519", "kid": self.jwk["kid"]})
        )
        signature = core.b64u(
            self.private_key.sign((header + "." + core.b64u(payload)).encode("ascii"))
        )
        detached = header + ".." + signature
        result = core.validate_event_obj(
            {**event, "sig": detached}, keys={self.jwk["kid"]: self.jwk}
        )
        if not result["valid"]:
            raise ValueError(json.dumps(result["errors"]))
        return detached


class HJSValidator:
    """Core Level 1 with explicit local reference availability and acceptance state.

    PEM keys are supplied by a caller's trust policy. Reference availability does
    not prove a complete chain, actor binding or authority. Acceptance requires a
    persistent replay file; archival verification never consumes nonces.
    """

    def __init__(self, clock_skew=300, replay_cache_path=None, require_references=True):
        if type(clock_skew) is not int or clock_skew < 0:
            raise ValueError("Clock skew must be a non-negative integer")
        self.clock_skew = clock_skew
        self.replay_cache_path = Path(replay_cache_path) if replay_cache_path else None
        self.require_references = require_references
        self._chain_registry = {}
        self._lock = threading.RLock()

    @property
    def chain_registry(self):
        with self._lock:
            return deepcopy(self._chain_registry)

    def verify_result(
        self, event_dict, public_key_pem, mode="archival", expected_audience=None
    ):
        try:
            core.canonicalize(
                event_dict
            )  # Reject non-JSON keys before JSON serialization can coerce them.
            event = core.parse_json_text(json.dumps(event_dict, allow_nan=False))
            keys = {}
            sig = event.get("sig") if isinstance(event, dict) else None
            if isinstance(sig, str) and len(sig.split(".")) == 3:
                header = core.parse_json_text(
                    core.b64u_decode(
                        sig.split(".")[0], label="protected header"
                    ).decode()
                )
                if isinstance(header, dict) and isinstance(header.get("kid"), str):
                    key = serialization.load_pem_public_key(public_key_pem.encode())
                    keys[header["kid"]] = public_jwk(key, header["kid"])
            with self._lock:
                result = core.validate_event_obj(
                    event,
                    keys=keys,
                    mode=mode,
                    replay_cache_path=self.replay_cache_path,
                    max_age=self.clock_skew,
                    max_future_skew=self.clock_skew,
                    expected_audience=expected_audience,
                    known_hashes=(
                        self._chain_registry if self.require_references else None
                    ),
                )
                if result["valid"]:
                    self._chain_registry[result["event_hash"]] = deepcopy(event)
            return {
                **result,
                "local_checks": (
                    ["reference_availability"] if self.require_references else []
                ),
                "acceptance_state": (
                    "persistent-file"
                    if mode == "acceptance" and self.replay_cache_path
                    else "not-consumed"
                ),
            }
        except (ValueError, TypeError, UnicodeError, core.ValidationFault) as exc:
            return {
                "valid": False,
                "profile": core.CORE_PROFILE,
                "level": 0,
                "mode": mode,
                "scopes": [],
                "errors": [{"code": "HJS_ERR_INPUT", "message": str(exc)}],
            }

    def verify(self, event_dict, signature_b64, public_key_pem, mode="archival"):
        if not isinstance(event_dict, dict):
            return False, "HJS_ERR_INPUT: event must be an object"
        if "sig" in event_dict and event_dict["sig"] != signature_b64:
            return (
                False,
                "HJS_ERR_SIGNATURE_MISMATCH: detached signature differs from event",
            )
        result = self.verify_result(
            {**event_dict, "sig": signature_b64}, public_key_pem, mode
        )
        return result["valid"], json.dumps(result)


SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
SCHEMAS = {
    path.name: json.loads(path.read_text()) for path in SCHEMA_DIR.glob("*.schema.json")
}
REGISTRY = Registry().with_resources(
    (uri, Resource.from_contents(schema))
    for name, schema in SCHEMAS.items()
    for uri in (schema["$id"], urljoin(schema["$id"], name))
)
RECEIPT_SCHEMA = Draft202012Validator(
    SCHEMAS["hjs-archive-receipt.schema.json"], registry=REGISTRY
)


class HJSReceiptValidator:
    """Validate metadata and optional hash binding, without asserting authenticity."""

    def validate_archive_receipt(self, receipt, jep_event=None):
        try:
            core.canonicalize(receipt)
            receipt = core.parse_json_text(json.dumps(receipt, allow_nan=False))
            errors = list(RECEIPT_SCHEMA.iter_errors(receipt))
            if errors:
                return False, {
                    "code": "HJS_ERR_RECEIPT_SCHEMA",
                    "errors": [e.message for e in errors],
                }
            if (
                not isinstance(receipt["archive_actor"], str)
                or not receipt["archive_actor"].strip()
            ):
                raise ValueError("archive_actor must be non-empty")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", receipt["jep_event_hash"]):
                raise ValueError("A sha256 event hash is required")
            if any(
                type(receipt[k]) is not int or receipt[k] < 0
                for k in ("receipt_time", "archive_time")
            ):
                raise ValueError("Receipt times must be non-negative integers")
            scopes = ["receipt_structure"]
            if jep_event is not None:
                if not isinstance(jep_event, dict):
                    raise ValueError("Event must be an object")
                expected = compute_event_hash(jep_event)
                if receipt["jep_event_hash"] != expected:
                    return False, {
                        "code": "HJS_ERR_EVENT_HASH_MISMATCH",
                        "expected": expected,
                    }
                scopes.append("event_hash_binding")
            return True, {
                "valid": True,
                "profile": receipt["profile"],
                "scopes": scopes,
                "jep_event_hash": receipt["jep_event_hash"],
                "signature_verified": False,
            }
        except (ValueError, TypeError, KeyError, core.ValidationFault) as exc:
            return False, {"code": "HJS_ERR_RECEIPT_INPUT", "message": str(exc)}


class HJSArchiveReceipt:
    def __init__(
        self,
        jep_event,
        archive_actor="did:example:hjs-archive",
        retention_policy="default-retention",
        redaction_manifest=None,
        selective_disclosure_manifest=None,
        evidence_refs=None,
    ):
        # Preserve signed objects; this constructor does not assert their authenticity.
        core.canonicalize(jep_event)
        event = core.parse_json_text(json.dumps(jep_event, allow_nan=False))
        core.validate_event_shape(event)
        parts = event["sig"].split(".")
        if len(parts) != 3 or parts[1] or not parts[0] or not parts[2]:
            raise ValueError(
                "Core archive receipt requires a detached JWS event; select legacy explicitly elsewhere"
            )
        instant = int(time.time())
        self.event_hash = compute_event_hash(event)
        self._data = {
            "hjs": "0.5",
            "type": "hjs.archive_receipt",
            "profile": "jep-profile:hjs-archive:0",
            "archive_actor": archive_actor,
            "jep_event_hash": self.event_hash,
            "receipt_time": instant,
            "archive_time": instant,
            "retention_policy": retention_policy,
            "redaction_manifest": (
                deepcopy(redaction_manifest)
                if redaction_manifest is not None
                else {"mode": "none", "redacted_fields": [], "retained_hashes": []}
            ),
            "selective_disclosure_manifest": (
                deepcopy(selective_disclosure_manifest)
                if selective_disclosure_manifest is not None
                else {"mode": "none", "audience_bound": False, "disclosed_fields": []}
            ),
            "evidence_refs": (
                deepcopy(evidence_refs) if evidence_refs is not None else []
            ),
            "boundary": {
                "does_not_redefine_jep_core": True,
                "does_not_prove_external_truth": True,
                "does_not_prove_complete_log": True,
            },
        }
        valid, result = HJSReceiptValidator().validate_archive_receipt(
            self._data, event
        )
        if not valid:
            raise ValueError(json.dumps(result))

    def to_dict(self):
        return deepcopy(self._data)


class HJSArchiveStore:
    """In-memory copied snapshots; no durable retention or signature trust claim."""

    def __init__(self):
        self._events, self._receipts = {}, {}
        self._lock = threading.RLock()

    @property
    def events(self):
        with self._lock:
            return deepcopy(self._events)

    @property
    def receipts(self):
        with self._lock:
            return deepcopy(self._receipts)

    def ingest_jep_event(self, jep_event, **kwargs):
        event = deepcopy(jep_event)
        receipt = HJSArchiveReceipt(event, **kwargs)
        with self._lock:
            # Identical event re-ingestion preserves its original receipt.
            if receipt.event_hash not in self._events:
                self._events[receipt.event_hash] = deepcopy(event)
                self._receipts[receipt.event_hash] = receipt.to_dict()
            return deepcopy(self._receipts[receipt.event_hash])

    def get_receipt(self, event_hash):
        with self._lock:
            return deepcopy(self._receipts.get(event_hash))
