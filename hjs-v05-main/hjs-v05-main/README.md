---
title: HJS v0.5 Archive
emoji: 🛡️
colorFrom: gray
colorTo: blue
sdk: gradio
sdk_version: 5.20.0
app_file: app.py
pinned: false
---

# HJS v0.5 — JEP-aware Accountability Archive for AI Agents

**Archive, privacy, receipt, and evidence-lifecycle companion layer for JEP v0.6.**

This repository hosts the interactive reference implementation of **HJS v0.5**.

HJS v0.5 upgrades the previous v0.4 implementation into a **JEP v0.6-compatible companion implementation**. It can generate HJS/JEP-style signed events, preserve human privacy controls, and create archive receipts bound to JEP event hashes.

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
| Event hash binding | JEP-style algorithm-tagged event hash over signed event object |
| Archive receipt | `hjs.archive_receipt` with receipt_time and archive_time |
| Redaction | `redaction_manifest` seed structure |
| Selective disclosure | `selective_disclosure_manifest` seed structure |
| Evidence lifecycle | `evidence_refs` and retention policy metadata |
| Privacy | plaintext, ephemeral DID, public key hash, salted digest |
| Boundary | no external truth, legal liability, or complete-log determination |

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
