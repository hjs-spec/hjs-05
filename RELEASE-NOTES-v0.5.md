# HJS v0.5 Release Notes

HJS v0.5 upgrades HJS v0.4 into a JEP v0.6-compatible companion implementation.

## Added

- JEP v0.6 alignment document.
- JEP-style event hash binding.
- HJS archive receipt object.
- In-memory archive store.
- HJS receipt validator.
- Redaction manifest schema.
- Selective disclosure manifest schema.
- Receipt bundle schema.
- Archive receipt examples.
- Additional tests.
- RFC 8785-conformant JCS path pinned to `jcs==0.2.1`.
- HJS-Core-1 whole-record canonicalization and algorithm-tagged SHA-256 helper.
- Canonical-byte fixtures aligned with `draft-wang-hjs-accountability-05`.
- APS cross-run fixtures and a preserved pre-fix interoperability baseline.

## Boundary

HJS v0.5 remains an archive, privacy, receipt, and evidence-lifecycle layer. It does not redefine JEP-Core semantics.
