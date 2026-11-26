# Postfiatd Dependency SBOM and Cryptographic Inventory Pack

Pinned target: [`postfiatorg/postfiatd`](https://github.com/postfiatorg/postfiatd)
at commit `0085a1ff885d6a446369cf73a4430f75af22be55` (merge of PR #50,
2026-10-10; postfiatd 1.0.9). Pin record: `outputs/00-pin.json`.

This pack inventories every dependency of the pinned tree, publishes SPDX
and CycloneDX SBOMs, catalogues the cryptographic primitives in the tree
with per-primitive quantum-exposure labels, matches the pinned versions
against public advisories, and lays out a staged upgrade + post-quantum
migration plan. Every claim is backed by a runnable script and unedited
output, or by a primary-source file+line citation. See
`docs/claim-evidence-index.md` for the full claim-to-evidence map.

## Headline numbers

- **25** manifest dependency records; **22** unique packages in the Conan
  graph (28 nodes, conancenter-only resolution — see the xrplf caveat below).
- **14** cryptographic inventory entries (CRYPTO-01..14); **zero**
  post-quantum primitives in the tree.
- **13** affected / support-status advisory findings: **1 Critical**
  (abseil CVE-2025-0838, 9.8), **6 High** (grpc CVE-2023-44487 and
  CVE-2023-33953 — network-reachable; libarchive CVE-2026-4111, 4424,
  5121, 14164 — not reachable via postfiatd's use), **1 support-status**
  (OpenSSL 1.1.1 EOL), **2 Medium**, **3 Low**. Plus 35 CVE records
  determined not affected and 1 not applicable (Boost.Serialization,
  component not linked).
- All 12 vector-carrying CVSS 3.1 scores were recomputed from their
  vectors in-script and match the published scores.

## Contents

| Path | What it is |
| --- | --- |
| `README.md` | This file. |
| `SHA256SUMS` | Full 64-char SHA-256 digests for every pack file (see `scripts/verify_digests.sh`). |
| `docs/methodology.md` | How the pack was built: pinning, extraction, graph, SBOM, inventory, two-pass advisory triage, scope. |
| `docs/decision-memo.md` | Source-cited decisions (grpc upgrade, OpenSSL migration, abseil, libarchive reachability, no-PQC finding). |
| `docs/migration-plan.md` | Staged upgrade + post-quantum migration plan. |
| `docs/claim-evidence-index.md` | Every claim → script output or primary source. |
| `sbom/postfiatd-0085a1ff.spdx.json` | SPDX 2.3 SBOM (32 packages incl. root). |
| `sbom/postfiatd-0085a1ff.cyclonedx.json` | CycloneDX 1.5 SBOM (31 components). |
| `inventory/crypto-inventory.json` / `.md` | 14-entry cryptographic inventory with quantum labels. |
| `findings/findings-register.json` / `.md` | Severity-ranked advisory findings with evidence links. |
| `outputs/` | Unedited logs (`00-pin.json`, `01-` to `05-` step logs), raw Conan graph, OSV query responses, OSV records, controls. |
| `scripts/` | The runnable harness: `extract_deps.py`, `conan_graph.py`, `generate_sbom.py`, `crypto_inventory.py`, `advisory_check.py`, plus `run_all.sh`, `clean_reproduce.sh`, `verify_digests.sh`. |

## Reproduce

```bash
# Full re-run against the pinned checkout (no postfiatd build is performed):
./scripts/run_all.sh

# Fresh clone at the pinned commit + full re-run + byte comparison:
./scripts/clean_reproduce.sh

# Verify digests:
./scripts/verify_digests.sh --verify
```

`run_all.sh` takes optional `[TREE] [PACK_DIR] [CONAN_HOME]` arguments.
Conan 2.x is required (2.34.0 on the build VM). The harness needs network
access to conancenter and to the OSV/NVD APIs.

## Known limitations (honest)

- **xrplf remote unreachable.** The documented Conan remote
  `https://conan.ripplex.io` could not be reached from the build VM, so
  the graph was resolved against conancenter only. The xrplf fork holds
  patched recipes; its resolutions could differ. Re-run with the remote
  reachable to close this item.
- **OSV version queries do not work for these C/C++ packages.** Their
  advisories are recorded as GIT commit ranges with no version data, so
  OSV version/purl queries return 0 even for known-vulnerable versions
  (proven by controls in `outputs/osv-controls.json`). The pack therefore
  uses a two-pass triage (version queries + targeted record fetch +
  NVD/distro cross-check); see `docs/methodology.md` §6.
- **TLS 1.3 availability is unverified** (no protocol-version config in
  the tree, no build was run). **PGP signature validity is unverified**
  on the build VM (signature present, no public key in keyring).
- **"No advisory found" is not "clean".** 13 packages had no advisory
  surface in this triage; that is a statement about the triage, not about
  the packages.
- **libarchive reachability is code-path analysis, not a runtime test.**
  `extractTarLz4` has no in-tree caller, so the two latent tar-path flaws
  (CVE-2026-15028, CVE-2026-5745) have no in-tree execution path as pinned.
- **Fresh-clone comparison not performed.** `scripts/clean_reproduce.sh`
  was stopped before completion and needs explicit approval to clone/check
  out the pinned tree and run Conan; the script and instructions are
  included so the comparison can be run. Determinism is instead
  demonstrated by the advisory script's two identical end-to-end runs and
  by SBOM determinism by construction (fixed timestamp, uuid5 serials).
  Digest verification passes for all 46 covered files.

## Scope

Dependency analysis from manifests + source only. No full postfiatd build,
no dynamic analysis, no fuzzing. OS-level patch state of the
`ubuntu:24.04` base image is out of scope.
