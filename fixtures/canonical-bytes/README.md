# HJS canonical-byte fixtures

`hjs-behavior-record-jcs-v1.json` pins the RFC 8785 UTF-8 bytes and SHA-256
outputs for three HJS-Core-1 behavior records.

For every vector:

- canonicalize the entire `input` member as one top-level JSON object;
- do not omit fields or remove explicit null values;
- compare the resulting bytes with `canonical_bytes_hex`;
- compute SHA-256 over those bytes and compare its lowercase hexadecimal form
  with `canonical_sha256`;
- add the `sha256:` prefix only when constructing the HJS/JEP textual digest.

The draft example vector is copied from Appendix A.1 of
`draft-wang-hjs-accountability-05`. The digest values in this fixture are test
values, unlike the illustrative placeholders in the Internet-Draft.
