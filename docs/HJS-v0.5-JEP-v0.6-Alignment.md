# HJS v0.5 Alignment with JEP v0.6

HJS v0.5 is an archive, privacy, receipt, and evidence-lifecycle companion layer for JEP v0.6 events.

This document describes how the HJS v0.5 implementation aligns with JEP v0.6 without redefining JEP-Core semantics.

## Current alignment

HJS v0.5 can:

- generate and verify Core 0.6 detached-JWS J/D/T/V events using the pinned Core validator;
- preserve JEP event hashes;
- generate HJS archive receipts bound to JEP event hashes;
- record `receipt_time` and `archive_time`;
- maintain redaction and selective disclosure manifests;
- reference evidence through digest-style references;
- preserve privacy modes for human identifiers;
- validate receipt-to-event hash binding.
- compute HJS-Core-1 behavior-record digests over the whole RFC 8785
  JCS-canonicalized top-level JSON object;
- reproduce pinned canonical bytes and SHA-256 outputs across implementations.

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

- Higher-level actor binding, authority and evidence profile implementations.
- Additional HJS archive profile test vectors.
- Selective disclosure conformance suite.
- Broader cross-service acceptance policy interoperability.

## Migration from the previous demo

New events use RFC 8785 canonical unsigned payloads and detached compact JWS
with `alg: Ed25519` and a protected `kid`. Extensions live under `ext`. Existing
raw signatures are not silently rewritten; use `legacy_hjs.verify_legacy_event`
with a separately trusted PEM key for integrity-only historical verification.
HJS-Core-1 behavior-record canonicalization, signed fixtures, APS interop
fixtures and historical reports are unchanged.

Use `event.sign(signer)` to retain the signed snapshot for immutability checks.
`HJSSigner.sign(event.canonicalize())` still returns a signature, now in Core
format. D/T object payloads must include their Core required fields; V requires
a non-null reference and object payloads include `verification_scope`. J can
have a reference; unresolved parents fail the default local verifier.

`HJSValidator.verify_result` returns the Core result plus local check metadata.
Archival checks do not consume a nonce. Library callers opting into acceptance
must pass a persistent `replay_cache_path`; acceptance without it fails closed.
Receipt validation covers all required fields and resolves nested schemas
locally without fetching remote resources. A receipt's presence proves neither
signature authenticity nor retention; verify the event separately before using
it in a trusted archive.
