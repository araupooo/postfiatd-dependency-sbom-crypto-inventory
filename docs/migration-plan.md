# Staged Upgrade + Post-Quantum Migration Plan

Pinned target: `postfiatorg/postfiatd`
`0085a1ff885d6a446369cf73a4430f75af22be55` (postfiatd 1.0.9).
Basis: `findings/findings-register.md` (13 affected/support findings),
`inventory/crypto-inventory.json` (14 entries), `docs/decision-memo.md`.

Principles: patch-level bumps first; no consensus change in stages 1-2;
every stage ends with a re-run of this pack's harness (`scripts/run_all.sh`)
and a fresh findings register before the next stage starts. Do not skip
the re-run — it is the only way to prove a stage closed what it claims to.

## Stage 1 — Close the network-reachable Highs (grpc + abseil + protobuf)

Goal: remove CVE-2023-44487, CVE-2023-33953 (grpc) and CVE-2025-0838 (abseil).

1. Bump `conanfile.py`: `grpc/1.50.1` → `1.59.2` (minimum; 1.59.2 is the
   SUSE-confirmed fix version for CVE-2023-44487; 1.53.2 already fixes
   CVE-2023-33953, so any version >= 1.59.2 closes both). Prefer the
   newest 1.6x patch release that the xrplf Conan remote offers, and
   record the chosen version in the commit message.
2. Let the grpc bump pull its abseil: verify the resolved abseil in the
   Conan graph is >= 20230802.3 (closes CVE-2025-0838). If the grpc recipe
   still resolves abseil 20230802.1, pin abseil explicitly in
   `requirements()` to 20230802.3.
3. Bump `protobuf/3.21.12` together with grpc (grpc 1.59.x pairs with a
   newer protobuf; check the grpc recipe's requirements and take the
   matching protobuf — do not leave a stale protobuf behind the grpc bump).
   protobuf 3.21.12 itself has no open finding in this pack, so this step
   is compatibility, not security.
4. Re-run the full test suite, then re-run this pack's harness and confirm
   the findings register drops CVE-2023-44487, CVE-2023-33953 and
   CVE-2025-0838 to zero. Also confirm the gRPC service still binds and
   serves on the configured endpoint (port 50051, 127.0.0.1 in shipped
   configs) — the upgrade must not silently change the bind behaviour.
5. Operator note (no code change): the gRPC service is unauthenticated by
   design (`InsecureServerCredentials`, GRPCServer.cpp:572). Keep the
   shipped `127.0.0.1` bind; if an operator binds it publicly, document
   that the endpoint is unauthenticated and should sit behind a gateway
   (`secure_gateway` config) or a firewall.

Exit criteria: findings register shows 0 network-reachable Highs; Conan
graph shows grpc >= 1.59.2 and abseil >= 20230802.3.

## Stage 2 — Archive + TLS libraries (libarchive + OpenSSL)

Goal: remove the 8 libarchive findings and the OpenSSL 1.1.1 EOL status.

### 2a. libarchive 3.8.1 → >= 3.8.9

1. Bump `conanfile.py`: `libarchive/3.8.1` → `3.8.9` (closes all 8
   libarchive CVEs in this pack: 3.8.6 fixes 4111; 3.8.7 fixes 4424, 4426,
   5121; 3.8.8 fixes 14164, 5745; 3.8.9 fixes 15028, 16517; 3.8.2 fixed
   64031). Minimum acceptable is 3.8.9 — do not stop at 3.8.6 or 3.8.7.
2. Keep the `conanfile.py` feature flags as they are
   (`with_bzip2/zlib/lzma/lzo/openssl/libxml2/expat/iconv/acl/xattr/cng/
   nettle/pcreposix: False`, `with_lz4: True`): the flags are what make
   six of the nine CVEs unreachable, and widening the enabled formats
   would widen the attack surface.
3. Add a standing guard: a test that asserts `extractTarLz4`'s enabled
   format/filter set (tar + lz4 only) so a future change cannot silently
   enable RAR/zip/ISO readers. While there, add a path-traversal guard on
   the `dst / archive_entry_pathname(entry)` join (Archive.cpp:99-101).
4. Re-run the harness; confirm the libarchive findings drop to zero.

### 2b. OpenSSL 1.1.1w → 3.5 LTS

This is code work, not a version bump — sequence it after 2a.

1. Inventory the blocking call sites: `src/libxrpl/crypto/digest.cpp`
   uses RIPEMD160 low-level APIs removed from the OpenSSL 3.x default
   provider. The ledger's hash160 (RIPEMD160(SHA-256),
   `include/xrpl/protocol/digest.h:155-157`) must keep producing
   byte-identical outputs — this is a consensus-critical hash.
2. Options, in order of preference: (a) move the RIPEMD-160 call sites to
   the EVP API with the legacy provider loaded explicitly for that one
   algorithm; (b) vendor a small, audited RIPEMD-160 implementation and
   drop the OpenSSL dependency for that hash; (c) load the legacy provider
   globally (least preferred — it re-enables deprecated algorithms
   process-wide).
3. Audit the rest of the OpenSSL surface while migrating: TLS cipher list
   (`src/libxrpl/basics/make_SSLContext.cpp:104`,
   `TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL`), the ephemeral RSA-2048
   self-signed certificate (`defaultRSAKeyBits = 2048`, `:66`; `X509_sign`
   with `EVP_sha256()`, `:233`), and the CSPRNG (`RAND_bytes` seeded via
   `RAND_poll` + `std::random_device`, `src/libxrpl/crypto/csprng.cpp:37-92`).
   Set an explicit TLS minimum version in the same change (no min/max
   protocol-version config exists in the tree today — CRYPTO-06).
4. Re-run the full test suite with consensus tests; any hash-output change
   is a hard failure, not a warning. Re-run the harness; confirm the
   OpenSSL EOL finding is closed and no new OpenSSL 3.x finding appears.

Exit criteria: libarchive >= 3.8.9 with flags unchanged; OpenSSL 3.5 LTS
linked; findings register shows 0 libarchive findings and 0 EOL status.

## Stage 3 — Post-quantum migration (roadmap, not a patch)

Goal: a ledger that survives a cryptographically relevant quantum computer.
This is a consensus change and cannot be done as a dependency bump.

[FACT] The tree has zero post-quantum primitives (no ML-DSA, ML-KEM,
SLH-DSA, Dilithium, Kyber terms in `src/`/`include/`). Signatures are
Ed25519 (ed25519-donna, CRYPTO-01) and secp256k1 ECDSA (CRYPTO-02); the
TLS certificate is ephemeral RSA-2048 (CRYPTO-07). All three are
quantum-vulnerable (Shor). Hashes (SHA-512, SHA-256, RIPEMD-160) are
quantum-reduced (Grover) — doubling hash output length restores the
margin, and SHA-512-Half already provides 256-bit pre-quantum strength.

Sequencing:

1. **Tooling first (no consensus change).** Add ML-DSA (FIPS 204) and
   ML-KEM (FIPS 203) support to offline tooling and the release-signing
   flow (hybrid classical + PQ signatures on release artefacts). This
   exercises the libraries and the key-management story without touching
   the ledger. Candidate: liboqs / the OpenSSL 3.5 provider ecosystem —
   evaluate, do not vendor blindly.
2. **Hybrid transaction signatures (amendment).** Design a hybrid
   signature scheme (e.g. Ed25519 + ML-DSA-65, or secp256k1 + ML-DSA-65)
   as a new key type and transaction signature format, gated by a ledger
   amendment. The design must cover: key/address derivation (hash160 is
   RIPEMD-160(SHA-256) of the public key — a PQ public key is ~2 KB, so
   address derivation and key storage need a scheme decision), serialised
   transaction size limits, validator manifest signing (CRYPTO-11), and
   migration of existing accounts (old keys cannot be upgraded by their
   owners if the owner is offline — the amendment must state the policy
   for un-migrated accounts).
3. **TLS (operator config, no amendment).** Once OpenSSL 3.5 is in place
   (stage 2b), enable a PQ-hybrid key exchange (ML-KEM-768 + X25519) for
   peer and RPC TLS where both sides support it. This is the cheapest PQ
   win: TLS is negotiated per connection, so it needs no ledger change.
4. **Do not** ship a vendored PQ implementation copied into `external/`
   without an upstream to track (the ed25519-donna precedent shows the
   cost: an unversioned snapshot that cannot be version-matched against
   advisories). Prefer a versioned Conan dependency with a real release
   cadence.

Exit criteria: hybrid signatures specified and amendment-drafted;
tooling signs releases with hybrid signatures; TLS negotiates a PQ-hybrid
KEX on testnet.

## Stage 4 — Standing hygiene (after every future dependency bump)

1. Re-run this pack's harness (`scripts/run_all.sh`) on every dependency
   bump and on every release branch cut; publish the refreshed findings
   register with the release notes.
2. Re-run the two-pass advisory triage — never rely on OSV version
   queries alone (decision D8).
3. Re-check the Boost component list on every `conanfile.py` change
   (CVE-2026-11460 control, decision D5).
4. Re-check `Archive.cpp`'s enabled formats on every libarchive bump
   (stage 2a guard).
5. Track the vendored copies (secp256k1, ed25519-donna, antithesis-sdk-cpp)
   against upstream releases; ed25519-donna needs a version marker or a
   recorded upstream commit before it can be advisory-checked at all.
