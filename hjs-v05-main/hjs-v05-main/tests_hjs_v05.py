from app import HJSEvent, HJSSigner, HJSArchiveReceipt, HJSArchiveStore, HJSReceiptValidator, compute_event_hash


def signed_event_dict():
    event = HJSEvent("J", "did:example:agent", "content", aud="https://archive.example.com")
    signer = HJSSigner()
    event.sig = signer.sign(event.canonicalize())
    return event.to_dict()


def test_jep_event_hash_binding():
    event_dict = signed_event_dict()
    event_hash = compute_event_hash(event_dict)
    assert event_hash.startswith("sha256:")
    assert len(event_hash) == len("sha256:") + 64


def test_hjs_archive_receipt_binds_to_jep_event_hash():
    event_dict = signed_event_dict()
    receipt = HJSArchiveReceipt(event_dict).to_dict()
    assert receipt["hjs"] == "0.5"
    assert receipt["type"] == "hjs.archive_receipt"
    assert receipt["jep_event_hash"] == compute_event_hash(event_dict)
    assert receipt["boundary"]["does_not_redefine_jep_core"] is True


def test_hjs_archive_store_ingest():
    event_dict = signed_event_dict()
    store = HJSArchiveStore()
    receipt = store.ingest_jep_event(event_dict)
    assert store.get_receipt(receipt["jep_event_hash"]) == receipt


def test_hjs_receipt_validator():
    event_dict = signed_event_dict()
    receipt = HJSArchiveReceipt(event_dict).to_dict()
    validator = HJSReceiptValidator()
    ok, result = validator.validate_archive_receipt(receipt, event_dict)
    assert ok is True
    assert result["profile"] == "jep-profile:hjs-archive:0"
