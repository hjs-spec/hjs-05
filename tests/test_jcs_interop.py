import hashlib
import json
import math
from pathlib import Path

import pytest

from hjs_jcs import (
    canonical_sha256,
    canonicalize_jcs,
    digest_behavior_record,
    validate_hjs_core1_behavior_record,
)


ROOT = Path(__file__).resolve().parents[1]
HJS_FIXTURES = ROOT / "fixtures" / "canonical-bytes" / "hjs-behavior-record-jcs-v1.json"
APS_FIXTURES = (
    ROOT
    / "fixtures"
    / "external"
    / "aps"
    / "aps-canonical-bytes-70d503f-distinct.json"
)


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_rfc8785_section_3_2_sample():
    source = r'''
    {
      "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
      "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
      "literals": [null, true, false]
    }
    '''
    value = json.loads(source)
    expected_hex = (
        "7b226c69746572616c73223a5b6e756c6c2c747275652c66616c73655d2c"
        "226e756d62657273223a5b3333333333333333332e333333333333332c3165"
        "2b33302c342e352c302e3030322c31652d32375d2c22737472696e67223a22"
        "e282ac245c75303030665c6e4127425c225c5c5c5c5c222f227d"
    )
    assert canonicalize_jcs(value).hex() == expected_hex


def test_rfc8785_section_3_2_3_sorts_by_utf16_code_units():
    value = {
        "€": "Euro Sign",
        "\r": "Carriage Return",
        "דּ": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "😀": "Emoji: Grinning Face",
        "\u0080": "Control",
        "ö": "Latin Small Letter O With Diaeresis",
    }
    expected = (
        '{"\\r":"Carriage Return","1":"One","\u0080":"Control",'
        '"ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign",'
        '"😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}'
    ).encode("utf-8")
    assert canonicalize_jcs(value) == expected


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_rfc8785_rejects_non_json_numbers(value):
    with pytest.raises(ValueError, match="Invalid JSON number"):
        canonicalize_jcs({"value": value})


def test_pinned_aps_vectors_match_at_byte_and_digest_levels():
    fixture = load_json(APS_FIXTURES)
    assert fixture["source_commit"] == "70d503ffd5f29d84f2100731bd0511667e851131"
    assert len(fixture["vectors"]) == 10

    for vector in fixture["vectors"]:
        canonical = canonicalize_jcs(vector["input"])
        assert canonical.hex() == vector["canonical_bytes_hex"], vector["name"]
        assert hashlib.sha256(canonical).hexdigest() == vector["canonical_sha256"], vector[
            "name"
        ]


def test_hjs_core1_fixtures_pin_whole_record_bytes_and_digests():
    fixture = load_json(HJS_FIXTURES)
    assert fixture["input_rule"].startswith("Canonicalize the entire input member")

    for vector in fixture["vectors"]:
        record = vector["input"]
        validate_hjs_core1_behavior_record(record)
        canonical = canonicalize_jcs(record)
        assert canonical.decode("utf-8") == vector["canonical"], vector["name"]
        assert canonical.hex() == vector["canonical_bytes_hex"], vector["name"]
        assert canonical_sha256(record) == vector["canonical_sha256"], vector["name"]
        assert digest_behavior_record(record) == f'sha256:{vector["canonical_sha256"]}'


def test_hjs_digest_preserves_explicit_null_and_empty_string():
    fixture = load_json(HJS_FIXTURES)
    record = next(
        vector["input"]
        for vector in fixture["vectors"]
        if vector["name"] == "hjs-core1-unicode-null-and-array-boundaries"
    )
    canonical = canonicalize_jcs(record).decode("utf-8")
    assert '"notes":""' in canonical
    assert '"observed":null' in canonical

    without_observed = json.loads(json.dumps(record, ensure_ascii=False))
    del without_observed["context"]["observed"]
    assert canonical_sha256(without_observed) != canonical_sha256(record)


def test_hjs_core1_rejects_circular_event_hash_member():
    fixture = load_json(HJS_FIXTURES)
    record = dict(fixture["vectors"][0]["input"])
    record["jep_event_hash"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="must not contain"):
        digest_behavior_record(record)


def test_published_behavior_record_example_matches_pinned_draft_vector():
    fixture = load_json(HJS_FIXTURES)
    draft_vector = next(
        vector
        for vector in fixture["vectors"]
        if vector["name"] == "hjs-core1-draft05-tool-call"
    )
    published_example = load_json(ROOT / "examples" / "hjs-behavior-record.json")
    assert published_example == draft_vector["input"]
    assert digest_behavior_record(published_example) == (
        "sha256:bdcc830a1d2dd8c334163b7fcbaad4584a7b7612e001050945dc3a954525d4c7"
    )


def test_published_event_and_manifest_reference_the_behavior_record_digest():
    behavior_record = load_json(ROOT / "examples" / "hjs-behavior-record.json")
    event = load_json(ROOT / "examples" / "hjs-jep-bound-event.json")
    manifest = load_json(ROOT / "examples" / "hjs-receipt-manifest.json")
    expected_digest = digest_behavior_record(behavior_record)

    assert event["what"] == expected_digest
    assert event["ext"]["https://hjs.org/receipt"]["record_digest"] == expected_digest
    assert manifest["records"][0]["digest"] == expected_digest
