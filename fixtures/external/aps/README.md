# APS RFC 8785 cross-run fixture pin

This directory mirrors the ten distinct RFC 8785 inputs and expected outputs
from the following externally maintained pin:

- Repository: `Agent-Authority-Conformance/aps-conformance-suite`
- Commit: `70d503ffd5f29d84f2100731bd0511667e851131`
- Upstream files:
  - `fixtures/canonical-bytes/canonical-bytes-jcs-v1.json`
  - `fixtures/canonical-bytes/canonical-bytes-jcs-v2.json`
- Upstream file SHA-256:
  - v1: `914803e87ce165f59958835519b30274623f2afab9a8ef5059bd2902ff0c9a8a`
  - v2: `9502d72102b10f083ce91529e025e4a9c8a18881c5a9ec8f9ac46b1c0e48f593`

The v2 file carries the eight v1 cases unchanged and adds two integer-domain
cases, so `aps-canonical-bytes-70d503f-distinct.json` contains ten distinct
vectors. The `input` member is canonicalized as written. The expected outputs
are `canonical_bytes_hex` and `canonical_sha256`.

The mirrored vectors are from a repository licensed under Apache-2.0 and are
attributed to Tymofii Pidlisnyi and the Agent Authority Conformance project.
No APS protocol semantics are imported into HJS by this mirror.
