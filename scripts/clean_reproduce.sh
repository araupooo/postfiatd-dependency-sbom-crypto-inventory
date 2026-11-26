#!/usr/bin/env bash
# Fresh-clone reproduction: clone postfiatd at the pinned commit into a clean
# directory, set up a fresh Conan home, re-run the whole harness there, and
# compare the deterministic outputs against the original pack.
#
# Usage: clean_reproduce.sh
# Writes: <task>/work/clean-repro/ (fresh tree + fresh pack copy + comparison)
set -euo pipefail

TASK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PACK_DIR="$TASK_DIR/pack"
PIN="0085a1ff885d6a446369cf73a4430f75af22be55"
REPRO="$TASK_DIR/work/clean-repro"
TREE="$REPRO/postfiatd-pinned"
REPRO_PACK="$REPRO/pack"
CONAN_HOME_DIR="$REPRO/conan-home"

echo "=== clean reproduction ==="
echo "pin: $PIN"
rm -rf "$REPRO"
mkdir -p "$REPRO"

# --- 1. fresh clone at the pinned commit --------------------------------------
echo "--- [1] fresh clone ---"
git clone --quiet https://github.com/postfiatorg/postfiatd.git "$TREE"
cd "$TREE"
git checkout --quiet "$PIN"
HEAD="$(git rev-parse HEAD)"
[ "$HEAD" = "$PIN" ] || { echo "FATAL: cloned HEAD $HEAD != $PIN" >&2; exit 1; }
echo "cloned HEAD OK: $HEAD (tracked files: $(git ls-files | wc -l))"

# --- 2. fresh pack copy (scripts + docs; outputs are regenerated) ------------
echo "--- [2] fresh pack copy ---"
mkdir -p "$REPRO_PACK"
cp -r "$PACK_DIR/scripts" "$REPRO_PACK/"
cp -r "$PACK_DIR/docs" "$REPRO_PACK/"
cp "$PACK_DIR/README.md" "$REPRO_PACK/" 2>/dev/null || true

# --- 3. fresh conan home -------------------------------------------------------
echo "--- [3] fresh conan home ---"
if [ -d "$HOME/.local/lib/python3.12/site-packages" ]; then
    export PYTHONPATH="$HOME/.local/lib/python3.12/site-packages${PYTHONPATH:+:$PYTHONPATH}"
fi
CONAN_BIN="$(command -v conan || echo "$HOME/.local/bin/conan")"
export CONAN_HOME="$CONAN_HOME_DIR"
"$CONAN_BIN" --version
"$CONAN_BIN" remote add conancenter https://center2.conan.io || true
"$CONAN_BIN" remote add xrplf https://conan.ripplex.io || true
"$CONAN_BIN" remote disable xrplf || true
"$CONAN_BIN" profile detect --force 2>&1 | tail -2
echo "remotes:"; "$CONAN_BIN" remote list

# --- 4. run the harness against the fresh tree ---------------------------------
echo "--- [4] run harness ---"
"$REPRO_PACK/scripts/run_all.sh" "$TREE" "$REPRO_PACK" "$CONAN_HOME_DIR" \
    2>&1 | tee "$REPRO/repro-run.log"

# --- 5. compare deterministic outputs -------------------------------------------
echo "--- [5] compare ---"
{
    echo "# Fresh-clone reproduction comparison"
    echo ""
    echo "Pinned commit: \`$PIN\`"
    echo "Reproduction run: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ""
    echo "Compared files (byte-identical = reproduced):"
    echo ""
    for f in outputs/dependencies.json outputs/conan-graph-deps.json \
             sbom/postfiatd-0085a1ff.spdx.json sbom/postfiatd-0085a1ff.cyclonedx.json \
             inventory/crypto-inventory.json inventory/crypto-inventory.md \
             findings/findings-register.json findings/findings-register.md; do
        if cmp -s "$PACK_DIR/$f" "$REPRO_PACK/$f"; then
            echo "- IDENTICAL: $f"
        else
            echo "- DIFFERS: $f"
            diff "$PACK_DIR/$f" "$REPRO_PACK/$f" | head -30 || true
        fi
    done
    echo ""
    echo "Notes:"
    echo "- outputs/conan-graph-info-raw.json is NOT byte-compared: it carries"
    echo "  remote recipe timestamps that can differ between runs. The normalised"
    echo "  conan-graph-deps.json above is the comparison target for the graph."
    echo "- outputs/05-advisory-check.log and the OSV records are live fetches;"
    echo "  a diff there after the query date means OSV/NVD data moved, not that"
    echo "  the harness is broken. The findings register above is the comparison"
    echo "  target for the triage."
    echo "- Log files (01-05) carry run paths; they are not byte-compared."
} | tee "$REPRO/COMPARISON.md"

echo "=== clean reproduction complete: $REPRO/COMPARISON.md ==="
