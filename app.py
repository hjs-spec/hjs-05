"""Local HJS companion demo; no live deployment is performed by this repository."""

import json
import os
from pathlib import Path
import threading
import gradio as gr
from jep_conformance import jep_validate as core
from hjs_core import (
    HJSEvent,
    HJSSigner,
    HJSValidator,
    HJSArchiveReceipt,
    HJSArchiveStore,
    HJSReceiptValidator,
    compute_event_hash,
    IMMUTABLE_FIELDS,
    HUMAN_CONFIGURABLE_FIELDS,
)
from legacy_hjs import verify_legacy_event

_VALIDATORS = {}
_VALIDATORS_LOCK = threading.Lock()


def generate_hjs_event(
    verb,
    who_raw,
    what_content,
    aud,
    ref_mode,
    ref_hash,
    privacy_mode,
    salt,
    ttl_minutes,
    identity_rotation,
):
    try:
        if int(ttl_minutes) != ttl_minutes:
            raise ValueError("TTL must be an integer")
        ref = ref_hash if ref_mode == "Reference existing event (ref)" else None
        # UI accepts structured what objects as JSON, otherwise treats text as digest input.
        what = (
            core.parse_json_text(what_content)
            if what_content.lstrip().startswith("{")
            else what_content
        )
        event = HJSEvent(
            verb,
            who_raw,
            what,
            aud=aud or None,
            ref=ref,
            privacy_mode=privacy_mode,
            salt=salt,
            ttl_minutes=int(ttl_minutes),
            identity_rotation=identity_rotation,
        )
        signer = HJSSigner()
        wire = event.sign(signer)
        return (
            json.dumps(wire, indent=2, ensure_ascii=False),
            event.canonicalize().decode(),
            event.sig,
            signer.get_public_key_pem(),
            "All Core members are covered by the signature, including who.",
        )
    except (ValueError, TypeError, core.ValidationFault) as exc:
        return f"Generation failed: {exc}", "", "", "", ""


def verify_hjs_event(
    event_json,
    public_key_pem,
    clock_skew=300,
    mode="archival",
    event_format="core-0.6",
    expected_audience="",
):
    try:
        event = core.parse_json_text(event_json)
        if event_format == "legacy-raw-ed25519":
            if mode != "archival":
                raise ValueError("Legacy verification is archival integrity only")
            result = verify_legacy_event(event, public_key_pem)
        elif event_format == "core-0.6":
            if type(clock_skew) not in (int, float) or int(clock_skew) != clock_skew:
                raise ValueError("Clock skew must be an integer")
            path = (
                Path(os.environ.get("HJS_STATE_DIR", ".hjs-state")).resolve()
                / "accepted-nonces.json"
            )
            key = (str(path), int(clock_skew))
            with _VALIDATORS_LOCK:
                validator = _VALIDATORS.setdefault(
                    key, HJSValidator(int(clock_skew), replay_cache_path=path)
                )
            result = validator.verify_result(
                event, public_key_pem, mode, expected_audience or None
            )
        else:
            raise ValueError("Select an explicit supported event format")
        return json.dumps(result, indent=2, ensure_ascii=False)
    except (ValueError, TypeError, core.ValidationFault) as exc:
        return json.dumps({"valid": False, "errors": [str(exc)]})


def generate_hjs_archive_receipt(event_json):
    try:
        event = core.parse_json_text(event_json)
        receipt = HJSArchiveReceipt(event).to_dict()
        return json.dumps(receipt, indent=2, ensure_ascii=False)
    except (ValueError, TypeError, core.ValidationFault) as exc:
        return json.dumps({"valid": False, "errors": [str(exc)]})


with gr.Blocks(title="HJS 0.5 companion for JEP Core 0.6") as demo:
    gr.Markdown("""# HJS archive companion
Create Core 0.6 events, verify them with a caller-trusted public key, and bind archive metadata to an event hash.
Verification reports the checks actually performed. Signatures do not prove identity, authority, external truth or complete logging.
""")
    with gr.Tab("Create event"):
        verb = gr.Dropdown(["J", "D", "T", "V"], value="J", label="Verb")
        who = gr.Textbox(
            value="did:example:participant", label="Actor or public key PEM"
        )
        what = gr.Textbox(
            value="example decision", label="Content text or typed what JSON"
        )
        aud = gr.Textbox(value="https://archive.example.com", label="Audience")
        ref_mode = gr.Radio(
            ["No reference", "Reference existing event (ref)"],
            value="No reference",
            label="Reference",
        )
        ref = gr.Textbox(
            label="Referenced event hash",
            info="V requires a reference. Verify referenced events first to make them available to the local verifier.",
        )
        privacy = gr.Dropdown(
            ["plaintext", "digest_only", "ephemeral_did", "pubkey_hash"],
            value="plaintext",
            label="Identity representation",
        )
        salt = gr.Textbox(
            label="Salt",
            type="password",
            info="Required for digest-only; no fixed fallback is supplied.",
        )
        ttl = gr.Number(
            value=0,
            minimum=0,
            precision=0,
            label="Retention hint in minutes",
            info="Metadata only; this demo does not delete or anonymize records automatically.",
        )
        rotation = gr.Checkbox(
            value=False,
            label="Record identity rotation request",
            info="A metadata request does not itself rotate an identity.",
        )
        create = gr.Button("Create and sign", variant="primary")
        event_json = gr.Textbox(label="Signed Core event", lines=14)
        canonical = gr.Textbox(label="Canonical unsigned payload", lines=3)
        sig = gr.Textbox(label="Detached JWS")
        public_key = gr.Textbox(
            label="Public key PEM",
            lines=4,
            info="Retain the key for historical verification. A new demo signing key is generated for each event.",
        )
        note = gr.Textbox(label="Signature scope")
        create.click(
            generate_hjs_event,
            inputs=[verb, who, what, aud, ref_mode, ref, privacy, salt, ttl, rotation],
            outputs=[event_json, canonical, sig, public_key, note],
        )
    with gr.Tab("Verify event"):
        verify_json = gr.Textbox(label="Event JSON", lines=12)
        verify_key = gr.Textbox(label="Independently trusted public key PEM", lines=4)
        mode = gr.Radio(
            ["archival", "acceptance"],
            value="archival",
            label="Mode",
            info="Archival is repeatable. Acceptance checks freshness and consumes a nonce in the local persistent state directory.",
        )
        event_format = gr.Dropdown(
            ["core-0.6", "legacy-raw-ed25519"], value="core-0.6", label="Format"
        )
        skew = gr.Number(
            value=300, minimum=0, precision=0, label="Acceptance time window (seconds)"
        )
        expected_aud = gr.Textbox(label="Expected audience (optional)")
        verify = gr.Button("Verify")
        result = gr.Textbox(label="Verification result and scope", lines=12)
        verify.click(
            verify_hjs_event,
            inputs=[verify_json, verify_key, skew, mode, event_format, expected_aud],
            outputs=result,
        )
    with gr.Tab("Archive receipt"):
        receipt_input = gr.Textbox(label="Core event JSON", lines=12)
        receipt_button = gr.Button("Create hash-bound receipt metadata")
        receipt_output = gr.Textbox(label="Archive metadata", lines=12)
        gr.Markdown(
            "This operation records metadata and hash binding. It does not verify the event's signature, authenticate an archive actor or prove durable retention."
        )
        receipt_button.click(
            generate_hjs_archive_receipt, inputs=receipt_input, outputs=receipt_output
        )
    gr.Markdown(
        "HJS covers archive, privacy and evidence lifecycle. JEP defines atomic signed events. JAC describes declared dependencies. Higher-scope validation requires its own evidence and implementation."
    )

if __name__ == "__main__":
    demo.launch(server_name="127.0.0.1", share=False)
