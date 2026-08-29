# APS × HJS RFC 8785 cross-run

## Scope

This report compares canonical UTF-8 bytes and SHA-256 outputs only. It does
not claim semantic equivalence, protocol adoption, external-truth validation,
or full APS/HJS interoperability.

## Pins

### APS side

- Repository: `Agent-Authority-Conformance/aps-conformance-suite`
- Commit: `70d503ffd5f29d84f2100731bd0511667e851131`
- Files:
  - `fixtures/canonical-bytes/canonical-bytes-jcs-v1.json`
  - `fixtures/canonical-bytes/canonical-bytes-jcs-v2.json`
- Input: each vector's `input` member
- Expected bytes: `canonical_bytes_hex`
- Expected digest: `canonical_sha256`
- Implementation declared by APS: `agent-passport-system 4.5.1`, `canonicalizeJCS`

The v2 file carries the eight v1 cases unchanged and adds two cases, giving
ten distinct vectors.

### HJS pre-fix side

- Repository: `hjs-spec/hjs-05`
- Commit: `9808c97f99e91392c15a5336c5e81465230516f7`
- Local dependency used for the baseline: `canonicaljson==2.0.0`
- Path exercised: the canonicalizer imported by `app.py`

## Preserved pre-fix baseline

The unmodified HJS implementation matched 6 of 10 vectors at both the byte
and digest levels.

| Vector | Canonical bytes | SHA-256 |
|---|---:|---:|
| `float-tenth` | agree | agree |
| `float-1e21-boundary` | agree | agree |
| `negative-zero` | agree | agree |
| `integer-above-2pow53` | agree | agree |
| `small-exponent-vs-decimal` | differ | differ |
| `astral-key-ordering` | differ | differ |
| `nfd-key-used-as-given` | agree | agree |
| `nested-object-and-array` | agree | agree |
| `integer-2pow60-inside-int64` | differ | differ |
| `integer-2pow68-above-int64` | differ | differ |

### Pre-fix differences

| Vector | Pre-fix canonical text | Pre-fix SHA-256 |
|---|---|---|
| `small-exponent-vs-decimal` | `{"dec":1e-06,"exp":1e-07}` | `99cb29f9a8496c67133f8a37a4462bfdfb1fb8884e1d5b21dcaa1747d7808776` |
| `astral-key-ordering` | `{"｡":1,"𝌆":2}` | `82476fb77b7d619e1ef56cfe179e6d108baf52bb9cd7ab7b1eed99c979fd5efc` |
| `integer-2pow60-inside-int64` | `{"value":1152921504606846976}` | `4a6dd55aad5394f2bcb6f3d9b304136d773d22411cebc1590540f34e6569d89e` |
| `integer-2pow68-above-int64` | `{"value":295147905179352825856}` | `ddf07dfbafdb059cc27251b827d08421790c56720806f515f85b64fa74e1435b` |

## Attribution of the differences

The pre-fix dependency implemented a different canonical-JSON profile:

- Python-style exponent rendering differed from ECMAScript number rendering.
- Object keys were sorted by Unicode code point rather than UTF-16 code unit.
- Python arbitrary-precision integers were emitted exactly rather than using
  the IEEE 754 binary64/ECMAScript serialization required by RFC 8785.

These are implementation deviations from the already published HJS draft's
JCS requirement. They are not HJS profile differences and are not corrected
by changing HJS record semantics.

## Standards-first correction

The correction is constrained by the following order:

1. RFC 8785 determines canonicalization behavior.
2. `draft-wang-hjs-accountability-05` section 4.5 determines the HJS digest
   input: the entire top-level behavior-record JSON object.
3. The HJS implementation follows those two specifications without omitting
   fields, removing null values, or adding APS-specific branches.
4. The APS vectors provide external verification after the rules are fixed.

## Post-fix result

The corrected HJS path was verified in a clean Python 3.12 virtual environment
with the repository's pinned `jcs==0.2.1` dependency:

| Verification set | Canonical bytes | SHA-256 |
|---|---:|---:|
| RFC 8785 section 3.2 serialization sample | pass | n/a |
| RFC 8785 section 3.2.3 UTF-16 key-order sample | pass | n/a |
| APS pinned distinct vectors | 10/10 agree | 10/10 agree |
| HJS behavior-record vectors | 3/3 agree | 3/3 agree |

All three HJS vectors also matched an independent Node.js implementation of
the RFC 8785 Appendix A canonicalizer at both byte and digest levels. The
published behavior-record example, the JEP-bound event, and the receipt
manifest resolve to the same pinned digest.

The post-fix result changes only the canonicalization implementation and the
examples/fixtures needed to exercise the published draft. It does not change
the HJS behavior-record digest boundary or add APS-specific behavior.
