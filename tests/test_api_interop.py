"""Bidirectional integration with the pinned, real API checkout in CI."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jep_conformance import jep_validate as core
from hjs_core import HJSEvent, HJSSigner, HJSValidator


def test_real_api_and_hjs_accept_each_others_signatures(tmp_path):
    api_path = os.environ.get("JEP_API_REPO")
    if not api_path:
        pytest.skip(
            "Set JEP_API_REPO to the API checkout; CI always runs this integration"
        )
    signer = HJSSigner()
    event = HJSEvent("J", "did:example:hjs", {"claim": "interop", "number": 1.0}).sign(
        signer
    )
    script = """
import json, sys
from fastapi.testclient import TestClient
import main
incoming = json.load(sys.stdin)
main.STATE.register_public_key(incoming['jwk']['kid'], incoming['jwk'])
client = TestClient(main.app)
verified = client.post('/events/verify', json={'event': incoming['event']})
assert verified.status_code == 200 and verified.json()['valid'], verified.text
created = client.post('/events/create', json={'verb': 'J', 'what': {'claim': 'return interop'}})
assert created.status_code == 200, created.text
print(json.dumps({'verified': verified.json(), 'event': created.json()['event'], 'keys': main.KEYS.jwks()}))
"""
    env = dict(os.environ, JEP_STATE_DIR=str(tmp_path / "api-state"))
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(api_path).resolve(),
        env=env,
        input=json.dumps({"event": event, "jwk": signer.jwk}),
        text=True,
        capture_output=True,
        check=True,
    )
    returned = json.loads(result.stdout)
    api_event = returned["event"]
    header = core.parse_json_text(
        core.b64u_decode(api_event["sig"].split(".")[0], label="header").decode()
    )
    jwk = next(k for k in returned["keys"]["keys"] if k["kid"] == header["kid"])
    key = Ed25519PublicKey.from_public_bytes(core.b64u_decode(jwk["x"], label="key"))
    pem = key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    validation = HJSValidator().verify_result(api_event, pem)
    assert validation["valid"] and validation["event_hash"] == core.event_hash(
        api_event
    )
