---
title: HJS v0.5 Archive
emoji: 🛡️
colorFrom: gray
colorTo: blue
sdk: gradio
sdk_version: 6.27.0
app_file: app.py
pinned: false
---

# HJS v0.5 — JEP-aware Accountability Archive for AI Agents

**Archive, privacy, receipt, and evidence-lifecycle companion layer for JEP v0.6.**

This repository hosts the interactive reference implementation of **HJS v0.5**.

HJS v0.5 upgrades the previous v0.4 implementation into a **JEP v0.6-compatible companion implementation**. It can generate Core 0.6 detached-JWS signed events, preserve human privacy controls, and create archive receipts bound to JEP event hashes.

## Positioning

```text
JEP = atomic signed judgment events
HJS = archive, privacy, receipt, and evidence lifecycle
JAC = causality and accountability chains
```

HJS v0.5 does **not** redefine JEP-Core verbs, signatures, event hashes, validation levels, validation modes, or failure codes.

## Core Features

| Area | v0.5 Capability |
|---|---|
| JEP event support | J/D/T/V event generation and validation baseline |
| Event hash binding | Core RFC 8785 algorithm-tagged event hash over signed event object |
| Archive receipt | `hjs.archive_receipt` with receipt_time and archive_time |
| Redaction | `redaction_manifest` seed structure |
| Selective disclosure | `selective_disclosure_manifest` seed structure |
| Evidence lifecycle | `evidence_refs` and retention policy metadata |
| Privacy | plaintext, ephemeral DID, public key hash, salted digest |
| Boundary | no external truth, legal liability, or complete-log determination |

## Current implementation and verification limits

Core events use the released `jep-v06-conformance-seed==0.7.0` validator
(JEP-Core-0.6, wire `jep: "1"`) for signing inputs, hashes and validation.
The HJS wire receipt version remains `0.5`.

- All signed fields, including `who`, are immutable after signing. Identity
  choices must be applied before signing; digest-only mode requires your salt.
- Default verification is repeatable **archival** Level 1 verification with a
  caller-trusted Ed25519 PEM key. Verify referenced events first; a missing
  local parent fails. Availability does not establish complete chains or authority.
- **Acceptance** additionally checks freshness and consumes nonces atomically
  in a persistent file. The UI uses `HJS_STATE_DIR` (default `.hjs-state`). Keep
  this directory across restarts. Reference availability is process-local and
  parents must be verified again after a restart. This is a local demo, not a
  distributed acceptance service or a complete actor/key trust policy.
- Old raw Ed25519 events require the explicit `legacy-raw-ed25519` archival
  reader. It verifies historical signature integrity only and never upgrades
  old bytes or reports Core conformance.
- Archive storage returns deep copies and preserves the first receipt on
  identical re-ingestion. The store is in memory, not durable storage.
- Receipts are schema-checked metadata. Validation reports `receipt_structure`
  and optional `event_hash_binding`; it does not authenticate the event or
  archive actor. Retention, redaction and rotation fields are declarations,
  not automatic deletion, anonymization or enforcement.

The Gradio app starts on localhost without public sharing. No deployment is
required to use or test this code. See [alignment and migration](docs/HJS-v0.5-JEP-v0.6-Alignment.md).

## New in v0.5

- JEP v0.6 alignment document
- HJS archive receipt schema
- HJS redaction manifest schema
- HJS selective disclosure manifest schema
- HJS receipt bundle schema
- Example archive receipt
- Example redacted JEP event metadata
- JEP-aware archive store and receipt validator classes
- Tests for archive receipt binding and boundary preservation

## HJS-Core-1 behavior-record digest path

The implementation follows `draft-wang-hjs-accountability-05` section 4.5:

1. validate the minimal HJS-Core-1 behavior-record structure;
2. canonicalize the entire top-level JSON object with RFC 8785 JCS;
3. compute SHA-256 over the canonical UTF-8 bytes;
4. represent the HJS/JEP digest as `sha256:<lowercase-hex>`.

No field is excluded from the digest input. Explicit null values are retained.
The implementation uses `jcs==0.2.1`; it does not use Python's standard JSON
serializer as a substitute for RFC 8785.

Pinned HJS and external APS cross-run fixtures are under `fixtures/`. The
cross-run report preserves both the pre-fix differences and post-fix results
under `reports/interop/`.

## Run locally

```bash
pip install -r requirements.txt
python app.py
```

## Test

```bash
pytest -q
```

## Related drafts

- JEP-Core: https://datatracker.ietf.org/doc/draft-wang-jep-judgment-event-protocol/
- JEP-Profiles: https://datatracker.ietf.org/doc/draft-wang-jep-profiles/
- JEP-Conformance: https://datatracker.ietf.org/doc/draft-wang-jep-conformance/
- HJS Accountability: https://datatracker.ietf.org/doc/draft-wang-hjs-accountability/

## License

Apache-2.0 for implementation artifacts unless otherwise stated. Internet-Draft text is governed by IETF Trust Legal Provisions where applicable.
