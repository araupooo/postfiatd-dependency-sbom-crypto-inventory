# Methodology

Pinned target: `postfiatorg/postfiatd` at commit
`0085a1ff885d6a446369cf73a4430f75af22be55` (merge of PR #50, 2026-10-10,
tree `78944f75f2156312289ee341e5d23a2fb34fba28`, merge of PR #50
("1.0.9: backport the upstream 3.4.1 payment engine overflow fix", author
Domagoj Ravlić, 2026-10-10). A PGP signature is present (RSA key
B5690EEEBB952194) but its validity could NOT be verified on the build VM
(`gpg: Can't check signature: No public key`) — recorded as such in
`outputs/00-pin.json`, not claimed as verified. postfiatd version `1.0.9`
(`src/libxrpl/protocol/BuildInfo.cpp:39`). All analysis is
against this pinned tree; nothing in this pack was built (no full postfiatd
build was performed — dependency analysis from manifests + source only).

## 1. Pinning

The LIVE `main` HEAD was resolved at build start via the GitHub API
(`GET /repos/postfiatorg/postfiatd/commits/main`) and recorded in
`outputs/00-pin.json` (commit, tree, author date, PGP verification status).
The repo owner is `postfiatorg`, not `PostFiat` (that namespace 404s for
this repository). A local checkout of the pinned commit lives at
`work/postfiatd-pinned/` (1,783 tracked files, 312 MB); every file+line
citation in this pack was verified against that checkout with `grep -n`,
never against a browser-fetched copy (browser fetches of pinned raw files
have been observed to serve different content than the pinned commit).

## 2. Dependency extraction

`scripts/extract_deps.py` parses the pinned tree's manifests:

- `conanfile.py` — direct `requires`, `test_requires`, `tool_requires`,
  `requirements()` overrides, `default_options` (feature flags such as
  `libarchive/*:with_bzip2 False`), and the optional jemalloc requirement.
- `Dockerfile` — base image (`ubuntu:24.04`), compiler (`gcc-13`), CMake
  built from source (`3.25.1`), `pipx conan`.
- `BUILD.md` — documented toolchain minimums (Python 3.11+, Conan 2.17+,
  CMake 3.22+, GCC 12 / Clang 16) and the Conan remote
  (`https://conan.ripplex.io`, the xrplf fork).
- `external/` — vendored code: secp256k1 (version from `configure.ac` +
  `CHANGELOG`), ed25519-donna (no version marker; provenance established by
  SHA-256 of `ed25519.c` against upstream master HEAD), antithesis-sdk-cpp
  (version from `CMakeLists.txt`).

Output: `outputs/dependencies.json` — 25 manifest records (13 direct,
1 optional, 1 test, 1 tool, 3 vendored, 5 toolchain, 1 self). Log:
`outputs/01-extract-deps.log`.

## 3. Transitive resolution (Conan graph)

`conan graph info` was run with Conan 2.34.0 (installed on the build VM
via `pip --user`; needs
`PYTHONPATH=/home/hatch/.local/lib/python3.12/site-packages`).
`scripts/conan_graph.py` normalises the raw graph into
`outputs/conan-graph-deps.json`. Log: `outputs/02-conan-graph.log`.

**xrplf remote caveat (open verification item).** The documented Conan
remote `https://conan.ripplex.io` (xrplf fork, BUILD.md:121-130) was
UNREACHABLE from the build VM (curl exit 000, proxy disconnect). The graph
was therefore resolved against conancenter only and SUCCEEDED: 28 nodes,
22 unique packages, 0 errors (raw graph in
`outputs/conan-graph-info-raw.json`). The xrplf fork holds patched recipes;
its resolutions could differ from conancenter's. Any consumer that can
reach `conan.ripplex.io` should re-run `scripts/conan_graph.py` with the
xrplf remote enabled and compare.

## 4. SBOM generation

`scripts/generate_sbom.py` emits SPDX 2.3 JSON and CycloneDX 1.5 JSON from
`dependencies.json` + `conan-graph-deps.json` (31 components + the
postfiatd root package in SPDX; 31 components in CycloneDX). Licenses and
homepages come from Conan recipe metadata in the raw graph. Log:
`outputs/03-generate-sbom.log`. SHA-256 (full 64-char values):

- SPDX: `c5d69012ffb6de0000f7cb62c9a2e46ca5325b5fb38d34175cd9d4509da9b1ea`
- CycloneDX: `a25a19032e90e11ce900bbd383b212409ccd05e0b9ca6bb260a32ff87eb422ca`

Note: Dockerfile CMake 3.25.1 (build tool) and the graph tool-requires
cmake 3.31.12 / 4.5.1 (recipe tools) are kept as separate records — they
are different roles, not a contradiction.

## 5. Cryptographic inventory

`scripts/crypto_inventory.py` greps the pinned tree (`src/`, `include/`)
for cryptographic primitives (algorithm names, OpenSSL API calls, key and
certificate handling) and records file+line evidence per entry, with a
quantum-exposure label per primitive. 14 entries (CRYPTO-01..14). Logs:
`outputs/04-crypto-inventory.log`. Inventory: `inventory/crypto-inventory.json`
+ `.md`.

Label rules:

- `quantum-vulnerable` — broken by a cryptographically relevant quantum
  computer (Shor): Ed25519, secp256k1 ECDSA, RSA-2048, TLS with ECDHE/ECDSA.
- `quantum-reduced` — security halved by Grover-style search: SHA-512,
  SHA-256, RIPEMD-160, SHA-512-Half, seed-derived keys.
- `not-quantum-relevant` — RNG / transport configuration, no quantum
  attack surface of its own.
- `unverified` — a measured absence (zero hits) or a capability whose
  availability could not be confirmed in the tree. Absence of a grep hit is
  recorded as a measured absence, never as proof of absence from the binary.

No TLS 1.3 or min/max protocol-version configuration exists in the tree;
whether the linked OpenSSL negotiates TLS 1.3 is UNVERIFIED (no build was
run). No HMAC/AES at-rest encryption calls were found in `src/` (measured
absence).

## 6. Advisory triage (two-pass)

`scripts/advisory_check.py` (see its header docstring for the full method).

**Pass 1 — OSV version queries.** `curl` POSTs to
`https://api.osv.dev/v1/query` (no auth) for every pinned package version
(Conan ecosystem, 31 queries) plus vendored upstreams by `pkg:github`
purl. Raw responses: `outputs/advisory-check-raw.json`. Transport: curl
with retries — Python `urllib` was abandoned after the first pass failed
with "Remote end closed connection without response" on this VM's flaky
egress proxy.

**Pass 1 measured limitation.** OSV version queries return 0 results for
these C/C++ packages because their advisories are recorded as GIT commit
ranges with no version/ecosystem data. This was proven with controls
(`outputs/osv-controls.json`): OSV purl queries for c-ares 1.26.0 (known
CVE-2024-25629) and sqlite 3.48.0 (known CVE-2025-3277) both return 0,
while npm/PyPI controls (lodash 4.17.20 → 4 vulns, requests 2.28.0 → 8
vulns) work. A pass-1 zero is therefore NOT evidence that a version is
clean. The GitHub Advisory Database has the same shape of data for these
packages (GHSA records with GIT ranges), so it does not fix the gap either.

**Pass 2 — targeted record fetch + curated triage (authoritative).** For
every CVE/GHSA the manual triage found relevant, the OSV record was
fetched by ID (`api.osv.dev/v1/vulns/<id>`, saved in
`outputs/osv-records/`) and applicability was determined from GHSA
ECOSYSTEM version ranges, NVD API records (CVSS 3.1 vectors + CPE ranges),
and distro changelogs (Debian, Ubuntu, SUSE, Yocto). CVSS 3.1 numeric
scores were recomputed from the vectors in-script (FIRST reference
Roundup) and checked against the published scores — all 12 vector-carrying
findings match. Reachability was determined per CVE against the pinned
tree's actual use of the library (see `findings/findings-register.md`):
which formats/filters `Archive.cpp` enables, which Boost components are
linked, which gRPC endpoint is exposed, and whether a function has any
in-tree caller.

Result: 13 affected/support-status findings (Critical 1, High 6,
support-status 1, Medium 2, Low 3), 35 determined-not-affected CVE
records, 1 not-applicable, 13 packages with no advisory found in this
triage. Full register: `findings/findings-register.json` + `.md`. Log:
`outputs/05-advisory-check.log`.

## 7. Reproduction

`scripts/run_all.sh` re-runs the whole harness end to end (extract →
graph → SBOM → inventory → advisory → digests). `clean_reproduce.sh`
clones `postfiatorg/postfiatd` fresh at the pinned commit into a clean
directory and re-runs the harness there; `verify_digests.sh` + `SHA256SUMS`
verify every pack file by full 64-char SHA-256. The fresh-clone comparison
was NOT performed (see README, Known limitations): the reproduction run was
stopped before completion and needs explicit approval to clone/check out the
tree and run Conan. The script and instructions are included at
`scripts/clean_reproduce.sh` so the comparison can be run.

## 8. Scope and exclusions

- No full postfiatd build (dependency analysis from manifests + source only).
- No dynamic analysis, no fuzzing, no runtime measurement.
- The Conan graph is conancenter-only (xrplf remote unreachable — see §3).
- OS-level patch state of the `ubuntu:24.04` base image is out of scope.
- Toolchain CVEs (gcc, cmake, python) are out of scope except as recorded
  versions.
- "No advisory found" means no public advisory surfaced in this triage,
  not that the version is vulnerability-free.
- Anything this pack could not verify is labelled `unverified` where it
  appears; the full list of limitations is in this section and in the
  README ("Known limitations").
