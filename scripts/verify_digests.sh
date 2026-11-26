#!/usr/bin/env bash
# Verifies (or generates) SHA-256 digests for every pack file.
#
# Usage: verify_digests.sh [--generate|--verify] [PACK_DIR]
#   --generate  (re)write SHA256SUMS from the current pack files
#   --verify    (default) check every file listed in SHA256SUMS
#
# Covered: README.md, docs/, findings/, inventory/, outputs/, sbom/,
# scripts/. Excluded (local run metadata, not shipped in the repository):
# SHA256SUMS itself and the two local handoff files. All hashes are full
# 64-character SHA-256 values.
set -euo pipefail

MODE="${1:---verify}"
PACK_DIR="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$PACK_DIR"

COVERED=(README.md docs findings inventory outputs sbom scripts)

if [ "$MODE" = "--generate" ]; then
    find "${COVERED[@]}" -type f | LC_ALL=C sort | xargs sha256sum > SHA256SUMS
    echo "wrote SHA256SUMS ($(wc -l < SHA256SUMS) files)"
elif [ "$MODE" = "--verify" ]; then
    if [ ! -f SHA256SUMS ]; then
        echo "FATAL: SHA256SUMS not found in $PACK_DIR" >&2
        exit 1
    fi
    sha256sum -c SHA256SUMS
else
    echo "usage: verify_digests.sh [--generate|--verify] [PACK_DIR]" >&2
    exit 2
fi
