# Decision Memo

Pinned target: `postfiatorg/postfiatd`
`0085a1ff885d6a446369cf73a4430f75af22be55` (postfiatd 1.0.9). Every decision
below cites its primary source. Labels: [FACT] verified fact with source
and date, [ESTIMATE] modelled/reported number, [ANALYSIS] interpretation.
Labels are never mixed within one claim.

## D1. Upgrade grpc 1.50.1 to >= 1.59.2 — priority: highest

[FACT] grpc 1.50.1 is affected by CVE-2023-44487 (HTTP/2 Rapid Reset,
CVSS 3.1 7.5 High, CISA KEV, exploited in the wild Aug-Oct 2023) and
CVE-2023-33953 (HPACK table accounting DoS, CVSS 3.1 7.5 High).
Fixed in 1.59.2 and 1.53.2 respectively (SUSE-SU-2024:0573-1;
GHSA-496j-2rq6-j6cc). Both scores were recomputed from their CVSS vectors
in-script and match the published scores (see `findings/findings-register.md`).

[FACT] Both flaws are reachable via postfiatd's gRPC service: the server
binds `grpc::InsecureServerCredentials()` at
`src/xrpld/app/main/GRPCServer.cpp:571-572`. Shipped configs bind
`[port_grpc]` port 50051 on 127.0.0.1 (`cfg/postfiatd-example.cfg:1466-1468`),
so in the shipped configuration the attacker must be local or the
operator must have bound the port publicly — but the bind address is
operator-configurable and the service is unauthenticated by design (the
code comment at GRPCServer.cpp says "without any authentication mechanism").

[ANALYSIS] The grpc upgrade is the single highest-value change in this
pack: it closes the only two network-reachable High findings, and 1.59.2
also closes CVE-2023-44487's fix commit 06021d91. Upgrading grpc pulls a
newer abseil (see D3) and a newer protobuf (see D4); plan them together
(migration plan stage 1).

## D2. Migrate OpenSSL 1.1.1w to 3.x — priority: high, but code work first

[FACT] OpenSSL 1.1.1 reached end of life on 2023-09-11; 1.1.1w (2023-09-11)
was the final 1.1.1 release and receives no further public security fixes
(OpenSSL project EOL reminder, 2023-06-15:
https://www.openssl.org/blog/blog/2023/06/15/1.1.1-EOL/). The pinned tree
therefore runs an unsupported TLS/crypto library more than three years
past EOL at the time of this pack (2026-11-26).

[FACT] Migration is not a version bump: `src/libxrpl/crypto/digest.cpp`
uses RIPEMD160 low-level OpenSSL APIs that were removed from the OpenSSL
3.x default provider. The tree's account-ID derivation depends on
RIPEMD-160 (hash160 = RIPEMD160(SHA-256),
`include/xrpl/protocol/digest.h:155-157`). Either the code must move to
the EVP API / legacy provider, or RIPEMD-160 must be reimplemented or
vendored.

[ANALYSIS] Do the grpc upgrade first (D1) and the OpenSSL migration
second, because the OpenSSL move touches the ledger's core hash paths and
needs the test suite to prove no consensus change. Target OpenSSL 3.5 LTS.
Keep 1.1.1w only behind a documented risk acceptance until the migration
lands; do not treat "no CVE filed against 1.1.1w this month" as safety —
no public fix would be issued for a new 1.1.1 flaw anyway.

## D3. Upgrade abseil 20230802.1 to >= 20230802.3 — priority: high

[FACT] abseil 20230802.1 is affected by CVE-2025-0838 (heap buffer
overflow in `absl::{flat,node}hash{set,map}` sized constructors /
`reserve()` / `rehash()`; NVD CVSS 3.1 9.8 Critical, recomputed from the
vector in-script and matching). Fixed upstream in 20230802.3 (SUSE
backport of commit 5a0e2cb5) / 20250127.0. Note the CNA's CVSS 4.0 score
is 5.9 Medium; this pack ranks on NVD CVSS 3.1 (9.8) for consistency.

[FACT] No direct use of the vulnerable APIs exists in postfiatd's own
code: zero hits for `absl::flat_hash*` in `src/` and `include/` (grep,
pinned tree). abseil is consumed transitively by grpc.

[ANALYSIS] The 9.8 score overstates the risk to postfiatd as pinned —
exploitation needs a caller to pass an attacker-controlled huge size to
the vulnerable APIs, and no such call site was identified — but the fix
is a patch-level bump (20230802.1 → 20230802.3) with no API change, so
there is no reason not to take it. It arrives automatically with the
grpc upgrade (D1); verify the resolved abseil version in the Conan graph
after the upgrade.

## D4. Upgrade libarchive 3.8.1 to >= 3.8.9 — priority: medium

[FACT] libarchive 3.8.1 is affected by 8 CVEs found in this triage
(CVE-2026-4111, 4424, 5121, 14164 at 7.5 High; CVE-2026-4426 at 6.5
Medium; CVE-2026-5745 at 5.5 Medium; CVE-2026-15028 at 3.9 Low;
CVE-2026-16517 at 2.9 Low; CVE-2025-64031 at 2.5 Low). Fixed versions
per the Debian changelog: 3.8.6 (4111), 3.8.7 (4424, 4426, 5121), 3.8.8
(14164, 5745), 3.8.9 (15028, 16517), 3.8.2 (64031). All scores were
recomputed from their NVD CVSS vectors in-script and match.

[FACT] Six of the nine are NOT reachable via postfiatd's use: the only
libarchive consumer is `extractTarLz4`
(`src/libxrpl/basics/Archive.cpp:36-116`), which enables ONLY
`archive_read_support_format_tar` + the lz4 filter and writes with
`archive_write_disk`. RAR/RAR5 (4111, 4424, 14164), ISO9660/zisofs (4426,
5121), the ZIP writer (16517) and the gzip writer (64031) are never
enabled.

[FACT] The remaining two are LATENT, not live: CVE-2026-15028 (tar PAX
`SUN.holesdata` heap overflow) and CVE-2026-5745 (tar ACL parsing NULL
dereference) sit in the tar reader path that `Archive.cpp` does enable —
but `extractTarLz4` is the only function in `Archive.cpp` and has NO
caller in `src/` or `include/` in the pinned tree (grep, 2026-11-26). The
vulnerable code is present in the libxrpl source with no in-tree
execution path in xrpld as pinned.

[ANALYSIS] Upgrade to 3.8.9 anyway: it is a patch-level bump, it closes
the two latent tar-path flaws before any future caller can reach them,
and the alternative (leaving a known-affected archive parser in the
library) relies on `extractTarLz4` staying uncalled forever. If the
utility is ever called, restrict its input to operator-supplied local
files and validate the destination path (the current code joins
`dst / archive_entry_pathname(entry)` without traversal checks —
`Archive.cpp:99-101`).

## D5. Boost.Serialization CVE-2026-11460 — no action (component not linked)

[FACT] CVE-2026-11460 (Boost.Serialization type-confusion RCE, 7.3 High,
published 2026-06-07, PoC public since Oct 2025, no patch as of
2026-11-26) affects Boost 1.0-1.91. postfiatd links these Boost
components only: chrono, container, coroutine, date_time, filesystem,
json, program_options, regex, system, thread (`conanfile.py` /
`CMakeLists`). Zero hits for `boost::serialization` / `boost/archive` in
`src/` and `include/` (grep, pinned tree).

[ANALYSIS] No action required. Do NOT add Boost.Serialization to the
build. Record the component check as a standing control: any future
`conanfile.py` change that adds a Boost component must re-run this check.

## D6. secp256k1 0.6.0 — upgrade available, not security-driven

[FACT] No public advisory was found for bitcoin-core/secp256k1 (C
library) 0.6.0 in this triage. Newer upstream releases exist (0.7.0,
0.7.1, 0.8.0 per `git ls-remote` tags, 2026-11-26). The vendored copy is
`external/secp256k1` at 0.6.0 (`configure.ac:6-9`, CHANGELOG 0.6.0
2024-11-04, MIT).

[ANALYSIS] A vendored-library bump is cheap and keeps the tree current,
but there is no security driver. Bundle it with a scheduled dependency
refresh, not with the security upgrades. Note the vendored beast fork
(`src/libxrpl/beast/`, rippled's fork, no version macro found) separately:
the Shielder May 2024 Boost audit (scope = Boost 1.83.0) found a
Boost.Beast CRLF injection (Medium, Open) — that finding is against
conan Boost.Beast, NOT the vendored fork, and whether the fork shares the
flaw is UNVERIFIED. Do not cite the Shielder finding as a postfiatd
finding.

## D7. No post-quantum primitives exist in the tree — roadmap, not emergency

[FACT] Zero hits for ML-DSA / ML-KEM / SLH-DSA / Dilithium / Kyber /
"post-quantum" in `src/` and `include/` (grep, pinned tree). The ledger's
signatures are Ed25519 (ed25519-donna, CRYPTO-01) and secp256k1 ECDSA
(CRYPTO-02); the TLS certificate is ephemeral RSA-2048 (CRYPTO-07).
All are quantum-vulnerable (Shor). Hashes (SHA-512, SHA-256, RIPEMD-160)
are quantum-reduced (Grover), not broken.

[ANALYSIS] There is no drop-in PQ replacement for the ledger's signature
schemes: changing the signature algorithm is a consensus change (key
formats, address derivation, transaction serialisation, validator
manifests). The migration plan (stage 3) therefore sequences: hybrid
signatures in tooling first, then a ledger amendment. Do not bolt a PQ
library onto the tree as a vendored copy without a design that the
validator set can adopt.

## D8. OSV version queries are not a sufficient triage method for C/C++ — process

[FACT] OSV version queries (Conan ecosystem and `pkg:github` purls)
returned 0 results for all 31 pinned package versions, including
c-ares 1.26.0 and sqlite 3.48.0, which have known CVEs. The cause is
structural: these advisories are recorded as GIT commit ranges with no
version/ecosystem data (proven by controls in
`outputs/osv-controls.json`).

[ANALYSIS] Any future triage that relies only on OSV version queries
will silently miss real vulnerabilities. The two-pass method in
`docs/methodology.md` §6 (version queries + targeted record fetch +
NVD/distro cross-check) is the minimum credible method for this
codebase, and it should be re-run on every dependency bump, not just on
this pin.
