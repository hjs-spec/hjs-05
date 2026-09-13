import json
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor

import pytest
from jep_conformance import jep_validate as core
from hjs_core import (
    HJSEvent,
    HJSSigner,
    HJSValidator,
    HJSArchiveReceipt,
    HJSArchiveStore,
    HJSReceiptValidator,
)
from legacy_hjs import verify_legacy_event
from hjs_jcs import canonicalize_jcs


def signed(**kwargs):
    signer = HJSSigner()
    event = HJSEvent(
        kwargs.pop("verb", "J"),
        "did:example:agent",
        kwargs.pop("what", "decision"),
        **kwargs
    )
    return event.sign(signer), signer


def test_all_verbs_match_core_and_resolve_verified_references():
    validator = HJSValidator()
    parent, signer = signed()
    assert validator.verify_result(parent, signer.get_public_key_pem())["valid"]
    ref = core.event_hash(parent)
    for verb, what in [
        ("J", {"claim": "followup"}),
        ("D", {"claim": "delegate", "delegatee": "did:example:b", "scope": "read"}),
        ("T", {"claim": "terminate", "target": ref, "termination_scope": "read"}),
        ("V", {"verification_scope": ["syntax"]}),
    ]:
        event, signer = signed(verb=verb, what=what, ref=ref)
        baseline = core.validate_event_obj(event, keys={signer.jwk["kid"]: signer.jwk})
        result = validator.verify_result(event, signer.get_public_key_pem())
        assert baseline["valid"] and result["valid"]
        assert result["event_hash"] == baseline["event_hash"]
        assert result["level"] == 1


def test_archival_repeatable_and_acceptance_survives_new_validator(tmp_path):
    event, signer = signed(aud="local-archive")
    key = signer.get_public_key_pem()
    path = tmp_path / "state" / "nonces.json"
    validator = HJSValidator(replay_cache_path=path)
    assert validator.verify_result(event, key)["valid"]
    assert validator.verify_result(event, key)["valid"]
    assert not path.exists()
    assert validator.verify_result(event, key, "acceptance")["valid"]
    replay = HJSValidator(replay_cache_path=path).verify_result(
        event, key, "acceptance"
    )
    assert not replay["valid"]
    assert replay["errors"][0]["code"] == "ERR_NONCE_REPLAY"
    assert validator.verify_result(event, key)["valid"]


def test_failed_validation_does_not_consume_nonce(tmp_path):
    event, signer = signed(aud="local-archive")
    key = signer.get_public_key_pem()
    validator = HJSValidator(replay_cache_path=tmp_path / "state.json")
    assert not validator.verify_result(dict(event, when=0), key, "acceptance")["valid"]
    assert not validator.verify_result(event, key, "acceptance", "wrong-audience")[
        "valid"
    ]
    assert validator.verify_result(event, key, "acceptance", "local-archive")["valid"]


def test_concurrent_acceptance_consumes_once(tmp_path):
    event, signer = signed()
    key = signer.get_public_key_pem()
    path = tmp_path / "state.json"
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(
            pool.map(
                lambda _: HJSValidator(replay_cache_path=path).verify_result(
                    event, key, "acceptance"
                ),
                range(4),
            )
        )
    assert sum(r["valid"] for r in results) == 1


def test_stale_signed_event_is_archival_only(tmp_path):
    signer = HJSSigner()
    builder = HJSEvent("J", "did:example:agent", "past")
    builder.when = 1
    event = builder.sign(signer)
    validator = HJSValidator(replay_cache_path=tmp_path / "state.json")
    assert validator.verify_result(event, signer.get_public_key_pem())["valid"]
    assert not validator.verify_result(
        event, signer.get_public_key_pem(), "acceptance"
    )["valid"]
    assert not (tmp_path / "state.json").exists()


@pytest.mark.parametrize(
    "bad",
    [None, [], {"sig": []}, {"sig": "broken"}, {"sig": "W10..AA"}, {1: "coerced"}],
)
def test_bad_event_returns_error(bad):
    assert not HJSValidator().verify_result(bad, "not a key")["valid"]


def test_signed_identity_and_nested_data_are_immutable():
    signer = HJSSigner()
    builder = HJSEvent(
        "J", "did:example:agent", {"claim": "decision", "detail": {"value": 1}}
    )
    event = builder.sign(signer)
    for modified in [
        dict(event, who="other"),
        {k: v for k, v in event.items() if k != "who"},
    ]:
        assert not builder.check_immutability(modified)[0]
    builder.what["detail"]["value"] = 2
    assert not builder.check_immutability(builder.to_dict())[0]
    assert event["what"]["detail"]["value"] == 1


def test_archive_store_copies_inputs_outputs_and_preserves_first_receipt():
    event, _ = signed(what={"claim": "decision", "detail": {"value": 1}})
    original = deepcopy(event)
    store = HJSArchiveStore()
    refs = [{"proof": ["one"]}]
    receipt = store.ingest_jep_event(event, evidence_refs=refs)
    digest = receipt["jep_event_hash"]
    expected = deepcopy(receipt)
    event["what"]["detail"]["value"] = 99
    refs[0]["proof"].append("two")
    receipt["evidence_refs"].clear()
    store.events[digest]["who"] = "changed"
    store.receipts[digest]["archive_actor"] = "changed"
    store.get_receipt(digest)["evidence_refs"].clear()
    assert store.events[digest] == original
    assert store.get_receipt(digest) == expected
    assert store.ingest_jep_event(original, archive_actor="another-actor") == expected


@pytest.mark.parametrize(
    "field,value",
    [
        ("profile", "wrong"),
        ("archive_actor", ""),
        ("archive_actor", []),
        ("receipt_time", True),
        ("archive_time", "now"),
        ("archive_time", -1),
        ("jep_event_hash", "sha256:abc"),
        ("redaction_manifest", {"mode": "none"}),
        (
            "selective_disclosure_manifest",
            {"mode": "none", "audience_bound": "yes", "disclosed_fields": []},
        ),
    ],
)
def test_invalid_receipt_metadata_fails(field, value):
    event, _ = signed()
    receipt = HJSArchiveReceipt(event).to_dict()
    receipt[field] = value
    assert not HJSReceiptValidator().validate_archive_receipt(receipt, event)[0]


def test_receipt_required_fields_and_scope():
    event, _ = signed()
    receipt = HJSArchiveReceipt(event).to_dict()
    validator = HJSReceiptValidator()
    for field in (
        "hjs",
        "type",
        "profile",
        "archive_actor",
        "jep_event_hash",
        "receipt_time",
        "archive_time",
    ):
        assert not validator.validate_archive_receipt(
            {k: v for k, v in receipt.items() if k != field}
        )[0]
    ok, result = validator.validate_archive_receipt(receipt, event)
    assert ok and result["scopes"] == ["receipt_structure", "event_hash_binding"]
    assert result["signature_verified"] is False
    assert not validator.validate_archive_receipt(receipt, dict(event, who="changed"))[
        0
    ]


def test_legacy_signature_requires_explicit_reader():
    event, signer = signed()
    body = {k: v for k, v in event.items() if k != "sig"}
    legacy = dict(body, sig=core.b64u(signer.private_key.sign(canonicalize_jcs(body))))
    key = signer.get_public_key_pem()
    assert not HJSValidator().verify_result(legacy, key)["valid"]
    result = verify_legacy_event(legacy, key)
    assert result["valid"] and result["core_conformance"] is False
    assert not verify_legacy_event(dict(legacy, who="other"), key)["valid"]


def test_ui_uses_core_extensions_and_retains_replay_state(tmp_path, monkeypatch):
    import app

    monkeypatch.setenv("HJS_STATE_DIR", str(tmp_path))
    generated = app.generate_hjs_event(
        "J",
        "person",
        "content",
        "archive",
        "No reference",
        "",
        "digest_only",
        "unique-salt",
        1,
        True,
    )
    event = json.loads(generated[0])
    assert set(event["ext"]) == {"https://hjs.org/privacy", "https://hjs.org/retention"}
    assert event["sig"].count(".") == 2
    assert json.loads(app.verify_hjs_event(generated[0], generated[3]))["valid"]
    assert json.loads(
        app.verify_hjs_event(generated[0], generated[3], mode="acceptance")
    )["valid"]
    assert not json.loads(
        app.verify_hjs_event(generated[0], generated[3], mode="acceptance")
    )["valid"]
    assert not json.loads(app.verify_hjs_event('{"jep":"1","jep":"2"}', generated[3]))[
        "valid"
    ]
    assert not json.loads(
        app.verify_hjs_event(
            generated[0],
            generated[3],
            mode="acceptance",
            event_format="legacy-raw-ed25519",
        )
    )["valid"]
