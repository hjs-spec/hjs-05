# HJS v0.5 Alignment with JEP v0.6

HJS v0.5 is an archive, privacy, receipt, and evidence-lifecycle companion layer for JEP v0.6 events.

This document describes how the HJS v0.5 implementation aligns with JEP v0.6 without redefining JEP-Core semantics.

## Current alignment

HJS v0.5 can:

- generate JEP-shaped J/D/T/V events;
- preserve JEP event hashes;
- generate HJS archive receipts bound to JEP event hashes;
- record `receipt_time` and `archive_time`;
- maintain redaction and selective disclosure manifests;
- reference evidence through digest-style references;
- preserve privacy modes for human identifiers;
- validate receipt-to-event hash binding.

## Boundary

HJS v0.5 does not redefine:

- JEP-Core event verbs;
- JEP-Core event format;
- JEP-Core signature semantics;
- JEP-Core event hash semantics;
- JEP-Core validation levels;
- JEP-Core validation modes;
- JEP-Core failure codes.

## What HJS v0.5 does not prove

A valid HJS archive receipt does not prove:

- external truth;
- legal liability;
- regulatory compliance;
- moral responsibility;
- complete log availability;
- human understanding;
- model correctness.

## Relationship to JAC

JAC may compose JEP events and HJS archive receipts into causality or accountability chains. HJS provides archive and evidence lifecycle metadata; JAC defines chain interpretation.

## Future work

- Full JEP v0.6 validation-result integration.
- HJS archive profile test vectors.
- Selective disclosure conformance suite.
- Automated integration with JEP-Conformance.
