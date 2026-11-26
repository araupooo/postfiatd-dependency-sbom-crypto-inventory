# Claim-to-Evidence Index

Every substantive claim in this pack, mapped to the evidence that backs
it. Labels: [FACT] verified fact with source and date, [ESTIMATE]
modelled/reported number, [ANALYSIS] interpretation. A claim with no
evidence row is not made in this pack.

## A. Pin and scope

| # | Claim | Evidence |
| --- | --- | --- |
| A1 | [FACT] Pinned target is `postfiatorg/postfiatd` at commit `0085a1ff885d6a446369cf73a4430f75af22be55` (merge PR #50, 2026-10-10), tree `78944f75f2156312289ee341e5d23a2fb34fba28`. | `outputs/00-pin.json`; GitHub API `GET /repos/postfiatorg/postfiatd/commits/main` at build start 2026-11-26; confirmed by `git rev-parse HEAD` / `HEAD^{tree}` in `work/postfiatd-pinned/`. |
| A2 | [FACT] postfiatd version is 1.0.9. | `src/libxrpl/protocol/BuildInfo.cpp:39` (pinned tree); merge subject "1.0.9: backport the upstream 3.4.1 payment engine overflow fix" (`outputs/00-pin.json`). |
| A3 | [FACT] A PGP signature is present on the pinned commit (RSA key B5690EEEBB952194) but its validity was NOT verified on the build VM (no public key in keyring). | `git verify-commit HEAD` output, recorded in `outputs/00-pin.json`. |
| A4 | [FACT] No full postfiatd build was performed; all analysis is from manifests + source. | `docs/methodology.md` §1, §8; no build artefacts exist in this pack. |
| A5 | [FACT] The Conan graph was resolved against conancenter only; the xrplf remote `https://conan.ripplex.io` was unreachable from the build VM. | `outputs/02-conan-graph.log`; `outputs/conan-graph-info.stderr.txt`; `docs/methodology.md` §3. |

## B. Dependency inventory (25 manifest records, 22 graph packages)

| # | Claim | Evidence |
| --- | --- | --- |
| B1 | [FACT] 25 manifest records: 13 direct, 1 optional (jemalloc 5.3.0, default off), 1 test (doctest 2.4.11), 1 tool (protobuf 3.21.12), 3 vendored, 5 toolchain, 1 self. | `outputs/dependencies.json` (dependency_count 25); `outputs/01-extract-deps.log`; `scripts/extract_deps.py`. |
| B2 | [FACT] Direct pins: grpc/1.50.1, libarchive/3.8.1, nudb/2.0.9, openssl/1.1.1w, soci/4.0.3, zlib/1.3.1; via `requirements()`: boost/1.83.0 (forced), date/3.0.4, lz4/1.10.0, protobuf/3.21.12, sqlite3/3.49.1, rocksdb/10.0.1 (default on), xxhash/0.8.3. | `conanfile.py` in the pinned tree; `outputs/dependencies.json`. |
| B3 | [FACT] Conan graph resolved: 28 nodes, 22 unique packages, 0 errors. Transitive: abseil/20230802.1, c-ares/1.34.9, re2/20230301, bzip2/1.0.8, libbacktrace/cci.20210118, snappy/1.2.1; tools b2/5.6.1, cmake/3.31.12 + 4.5.1. | `outputs/conan-graph-info-raw.json`; `outputs/conan-graph-deps.json`; `outputs/02-conan-graph.log`; `scripts/conan_graph.py`. |
| B4 | [FACT] Vendored secp256k1 is 0.6.0 (MIT); ed25519-donna is an unversioned snapshot (consolidated 2024-04-19, commit e2384885f; public domain); antithesis-sdk-cpp is 0.4.4 (MIT). | `external/secp256k1/configure.ac:6-9`, `CHANGELOG` (0.6.0, 2024-11-04); `external/ed25519-donna/ed25519.c:2`; `external/antithesis-sdk/CMakeLists.txt:4`. |
| B5 | [FACT] Vendored ed25519.c is byte-identical to upstream master HEAD. | SHA-256 `491efa60521d6ef3cc8b42c722adbb07c5a8da3e355bd9ed8947a5ca02cec594` for both files (3,687 bytes each): pinned `external/ed25519-donna/ed25519.c` @ 0085a1ff and upstream `floodyberry/ed25519-donna` master `ed25519.c`, both fetched via the GitHub API and hashed 2026-11-26. |
| B6 | [FACT] No `.gitmodules` in the tree; no `conan.lock` in the tree. | GitHub API contents lookup at the pinned ref 0085a1ff returns "does not exist" for both `.gitmodules` and `conan.lock` (checked 2026-11-26). |
| B7 | [FACT] Toolchain minimums: Python 3.11+, Conan 2.17+, CMake 3.22+, GCC 12 / Clang 16 (BUILD.md); Dockerfile: ubuntu:24.04, gcc-13, CMake 3.25.1 built from source, pipx conan. | `BUILD.md`; `Dockerfile:39` (pinned tree); `outputs/dependencies.json` (toolchain records). |

## C. SBOMs

| # | Claim | Evidence |
| --- | --- | --- |
| C1 | [FACT] SPDX JSON: 32 packages incl. root. SHA-256 `c5d69012ffb6de0000f7cb62c9a2e46ca5325b5fb38d34175cd9d4509da9b1ea`. | `sbom/postfiatd-0085a1ff.spdx.json`; `outputs/03-generate-sbom.log`; `SHA256SUMS`. |
| C2 | [FACT] CycloneDX JSON: 31 components. SHA-256 `a25a19032e90e11ce900bbd383b212409ccd05e0b9ca6bb260a32ff87eb422ca`. | `sbom/postfiatd-0085a1ff.cyclonedx.json`; `outputs/03-generate-sbom.log`; `SHA256SUMS`. |
| C3 | [FACT] Licenses/homepages in the SBOMs come from Conan recipe metadata in the raw graph. | `outputs/conan-graph-info-raw.json`; `scripts/generate_sbom.py`. |

## D. Cryptographic inventory (14 entries)

| # | Claim | Evidence |
| --- | --- | --- |
| D1 | [FACT] CRYPTO-01 Ed25519 signatures via vendored ed25519-donna; quantum-vulnerable; 21 hits. | `inventory/crypto-inventory.json` (CRYPTO-01, evidence `external/ed25519-donna/ed25519.h:18` etc.); `outputs/04-crypto-inventory.log`. |
| D2 | [FACT] CRYPTO-02 secp256k1 ECDSA signatures; quantum-vulnerable; 127 hits. | `inventory/crypto-inventory.json` (CRYPTO-02). |
| D3 | [FACT] CRYPTO-03 SHA-512 / SHA-512-Half is the core ledger hash; quantum-reduced; 66 hits. | `inventory/crypto-inventory.json` (CRYPTO-03, `include/xrpl/protocol/digest.h:70-77`). |
| D4 | [FACT] CRYPTO-04 SHA-256; quantum-reduced; 21 hits. | `inventory/crypto-inventory.json` (CRYPTO-04, `digest.h:93-100`). |
| D5 | [FACT] CRYPTO-05 hash160 = RIPEMD160(SHA-256) for account IDs; quantum-reduced; 16 hits. | `inventory/crypto-inventory.json` (CRYPTO-05, `digest.h:155-157`). |
| D6 | [FACT] CRYPTO-06 TLS cipher list `TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL`; renegotiation disabled; no explicit ECDH/curve config; no TLS 1.3 or min/max protocol-version config in the tree (TLS 1.3 availability UNVERIFIED). | `inventory/crypto-inventory.json` (CRYPTO-06, `src/libxrpl/basics/make_SSLContext.cpp:104,375`). |
| D7 | [FACT] CRYPTO-07 ephemeral self-signed RSA-2048 certificate; quantum-vulnerable; 10 hits. | `inventory/crypto-inventory.json` (CRYPTO-07, `make_SSLContext.cpp:66,233`). |
| D8 | [FACT] CRYPTO-08 peer handshake channel binding = SHA-512 of TLS Finished messages, self-described non-standard; cites openssl#5509, rippled#2413. | `inventory/crypto-inventory.json` (CRYPTO-08, `src/xrpld/overlay/detail/Handshake.cpp:128-160`). |
| D9 | [FACT] CRYPTO-09 CSPRNG = `RAND_bytes` seeded via `RAND_poll` + `std::random_device`; not-quantum-relevant; 6 hits. | `inventory/crypto-inventory.json` (CRYPTO-09, `src/libxrpl/crypto/csprng.cpp:37-92`). |
| D10 | [FACT] CRYPTO-10 deterministic key derivation from 128-bit seeds (Ed25519: SHA-512-Half(seed); secp256k1: SHA-512 root-key derivation); quantum-reduced; 31 hits. | `inventory/crypto-inventory.json` (CRYPTO-10, `src/libxrpl/protocol/SecretKey.cpp:86-124,309-327`). |
| D11 | [FACT] CRYPTO-11 validator manifests signed with master + ephemeral keys; quantum-vulnerable; 140 hits. | `inventory/crypto-inventory.json` (CRYPTO-11, `src/xrpld/app/misc/detail/Manifest.cpp:46-145`). |
| D12 | [FACT] CRYPTO-12 gRPC API transport binds `grpc::InsecureServerCredentials()`; not-quantum-relevant; 2 hits. | `inventory/crypto-inventory.json` (CRYPTO-12, `src/xrpld/app/main/GRPCServer.cpp:571-572`). |
| D13 | [FACT] CRYPTO-13 zero PQC terms (ML-DSA/ML-KEM/SLH-DSA/Dilithium/Kyber/post-quantum) in `src/`/`include/` — measured absence. | `inventory/crypto-inventory.json` (CRYPTO-13, hit_count 0, verification_status measured-absence). |
| D14 | [FACT] CRYPTO-14 no HMAC/AES at-rest encryption calls in `src/` — measured absence. | `inventory/crypto-inventory.json` (CRYPTO-14, hit_count 0, verification_status measured-absence). |
| D15 | [FACT] `secp256k1_context_randomize` is never called from `src/`/`include/`; context created VERIFY\|SIGN only. | `include/xrpl/protocol/detail/secp256k1.h:35-36`; grep in `outputs/04-crypto-inventory.log`. |

## E. Advisory findings (13 affected / support-status)

| # | Claim | Evidence |
| --- | --- | --- |
| E1 | [FACT] 13 affected/support findings: Critical 1, High 6, support-status 1, Medium 2, Low 3. | `findings/findings-register.json` (finding_count 13); `outputs/05-advisory-check.log`. |
| E2 | [FACT] CVE-2025-0838 (abseil 20230802.1): NVD CVSS 3.1 9.8 Critical, fixed 20230802.3 / 20250127.0; no direct `absl::flat_hash*` use in postfiatd src/include. | `findings/findings-register.json`; OSV record `outputs/osv-records/CVE-2025-0838.json`; NVD API; SUSE-SU-2026:20268-1; grep (0 hits). |
| E3 | [FACT] CVE-2023-44487 (grpc 1.50.1): CVSS 3.1 7.5 High, CISA KEV, fixed 1.59.2; reachable via the gRPC service (port 50051, shipped bind 127.0.0.1). | `findings/findings-register.json`; OSV record `outputs/osv-records/CVE-2023-44487.json`; `GRPCServer.cpp:571-572`; `cfg/postfiatd-example.cfg:1466-1468`. |
| E4 | [FACT] CVE-2023-33953 (grpc 1.50.1): CVSS 3.1 7.5 High, fixed 1.53.2; reachable via the gRPC service. | `findings/findings-register.json`; OSV records `CVE-2023-33953.json` + `GHSA-496j-2rq6-j6cc.json`. |
| E5 | [FACT] libarchive 3.8.1 affected by 9 CVEs (4111, 4424, 5121, 14164 @ 7.5; 4426 @ 6.5; 5745 @ 5.5; 15028 @ 3.9; 16517 @ 2.9; 64031 @ 2.5); fixed in 3.8.6 / 3.8.7 / 3.8.8 / 3.8.9 / 3.8.2 respectively. | `findings/findings-register.json`; OSV records in `outputs/osv-records/`; Debian changelog `https://metadata.ftp-master.debian.org/changelogs/main/liba/libarchive/unstable_changelog`; NVD API records. |
| E6 | [FACT] 6 of the 9 libarchive CVEs are not reachable via postfiatd's use (RAR/RAR5/ISO9660/zisofs/ZIP-writer/gzip-writer never enabled); 2 are latent tar-path flaws (15028, 5745). | `src/libxrpl/basics/Archive.cpp:36-116` (tar + lz4 only); `findings/findings-register.md`. |
| E7 | [FACT] `extractTarLz4` has NO caller in `src/` or `include/` in the pinned tree. | `grep -rln extractTarLz4` over pinned `src/` + `include/` (2026-11-26): only `Archive.cpp` and `Archive.h`. |
| E8 | [FACT] OpenSSL 1.1.1 EOL 2023-09-11; 1.1.1w is the final release; no public security fixes after that date. | OpenSSL EOL reminder 2023-06-15: `https://www.openssl.org/blog/blog/2023/06/15/1.1.1-EOL/`; `findings/findings-register.json` (OPENSSL-1.1.1-EOL). |
| E9 | [FACT] All 12 vector-carrying CVSS 3.1 scores were recomputed from their vectors in-script and match the published scores. | `outputs/05-advisory-check.log` (match=True on all 12); `scripts/advisory_check.py` (`cvss31_base`). |
| E10 | [FACT] 35 CVE records were determined NOT affected; 1 (CVE-2026-11460, Boost.Serialization) not applicable (component not linked — zero `boost::serialization`/`boost/archive` hits in src/include; linked components: chrono, container, coroutine, date_time, filesystem, json, program_options, regex, system, thread). | `findings/findings-register.json` (not_affected 35, not_applicable 1); `conanfile.py` / CMakeLists (component list); grep. |
| E11 | [FACT] OSV version queries return 0 for all 31 pinned package versions, including controls c-ares 1.26.0 (CVE-2024-25629) and sqlite 3.48.0 (CVE-2025-3277) — proven method limitation, not cleanliness. | `outputs/advisory-check-raw.json`; `outputs/osv-controls.json`; `outputs/05-advisory-check.log`. |
| E12 | [FACT] 13 packages have no advisory found in this triage (soci, nudb, date, xxhash, bzip2, doctest, jemalloc, rocksdb, libbacktrace, secp256k1, ed25519-donna, antithesis-sdk-cpp, cmake) — recorded as "no advisory found", not "clean". | `findings/findings-register.json` (no_advisory_found 13). |

## F. Unverified items (labelled as such; do not cite as fact)

| # | Item | Status |
| --- | --- | --- |
| F1 | TLS 1.3 availability with the linked OpenSSL. | UNVERIFIED — no TLS 1.3 / protocol-version config in the tree; no build was run. |
| F2 | Which curves / ECDH parameters the TLS stack negotiates. | UNVERIFIED — no explicit ECDH/curve config in the tree (library defaults). |
| F3 | Whether the vendored `src/libxrpl/beast/` fork shares the Shielder Boost.Beast CRLF flaw. | UNVERIFIED — the Shielder finding is against conan Boost.Beast, not the fork; different lineage. |
| F4 | Whether the xrplf Conan remote (`conan.ripplex.io`) would resolve different transitive versions than conancenter. | UNVERIFIED — remote unreachable from the build VM. |
| F5 | PGP signature validity on the pinned commit. | UNVERIFIED on this VM — signature present, no public key in keyring. |
