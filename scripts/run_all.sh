#!/usr/bin/env bash
# Re-runs the whole pack harness end to end against a pinned postfiatd tree.
#
# Usage: run_all.sh [TREE] [PACK_DIR] [CONAN_HOME]
#   TREE       path to the postfiatd checkout at the pinned commit
#              (default: <task>/work/postfiatd-pinned)
#   PACK_DIR   pack directory to (re)generate into
#              (default: the pack directory containing this script)
#   CONAN_HOME conan home to use (default: <task>/work/conan-home)
#
# Steps: 01 extract deps -> 02 conan graph -> 03 SBOMs -> 04 crypto
# inventory -> 05 advisory triage -> 06 digests. Logs land in
# <PACK_DIR>/outputs/0N-*.log, unedited.
#
# Notes:
#   * Conan 2.x is required (2.34.0 on the build VM, pip --user install at
#     ~/.local/bin/conan; the wrapper needs PYTHONPATH pointing at the
#     user site-packages — set automatically below when it exists).
#   * The xrplf remote (https://conan.ripplex.io) is unreachable from the
#     build VM, so the graph is resolved against conancenter only. If the
#     remote is enabled in CONAN_HOME, this script disables it for the run
#     and logs the fact (open verification item, see docs/methodology.md).
#   * No postfiatd build is performed by any step.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACK_DIR="${2:-$(cd "$SCRIPT_DIR/.." && pwd)}"
TASK_DIR="$(cd "$PACK_DIR/.." && pwd)"
TREE="${1:-$TASK_DIR/work/postfiatd-pinned}"
CONAN_HOME_DIR="${3:-$TASK_DIR/work/conan-home}"
PIN="0085a1ff885d6a446369cf73a4430f75af22be55"

mkdir -p "$PACK_DIR/outputs" "$PACK_DIR/sbom" "$PACK_DIR/inventory" \
         "$PACK_DIR/findings" "$PACK_DIR/docs" "$PACK_DIR/outputs/osv-records"

echo "=== pack harness ==="
echo "tree:       $TREE"
echo "pack:       $PACK_DIR"
echo "conan home: $CONAN_HOME_DIR"
echo "pin:        $PIN"

# --- 0. pin check -----------------------------------------------------------
HEAD="$(cd "$TREE" && git rev-parse HEAD)"
if [ "$HEAD" != "$PIN" ]; then
    echo "FATAL: tree HEAD is $HEAD, expected pinned $PIN" >&2
    exit 1
fi
echo "pin OK: $HEAD"

# --- conan setup ------------------------------------------------------------
if [ -d "$HOME/.local/lib/python3.12/site-packages" ]; then
    export PYTHONPATH="$HOME/.local/lib/python3.12/site-packages${PYTHONPATH:+:$PYTHONPATH}"
fi
CONAN_BIN="$(command -v conan || echo "$HOME/.local/bin/conan")"
export CONAN_HOME="$CONAN_HOME_DIR"
"$CONAN_BIN" --version

# --- 01. dependency extraction ----------------------------------------------
echo "--- [01] extract_deps ---"
python3 "$PACK_DIR/scripts/extract_deps.py" \
    --tree "$TREE" --out "$PACK_DIR/outputs/dependencies.json" \
    2>&1 | tee "$PACK_DIR/outputs/01-extract-deps.log"

# --- 02. conan graph ---------------------------------------------------------
echo "--- [02] conan graph info ---"
# Resolve against conancenter only: disable xrplf if present/enabled.
if "$CONAN_BIN" remote list 2>/dev/null | grep -q "^xrplf"; then
    echo "NOTE: disabling xrplf remote for this run (unreachable from this VM; see docs/methodology.md §3)"
    "$CONAN_BIN" remote disable xrplf || true
fi
(
    cd "$TREE"
    "$CONAN_BIN" graph info . --format=json \
        > "$PACK_DIR/outputs/conan-graph-info-raw.json" \
        2> "$PACK_DIR/outputs/conan-graph-info.stderr.txt"
)
python3 "$PACK_DIR/scripts/conan_graph.py" \
    --graph "$PACK_DIR/outputs/conan-graph-info-raw.json" \
    --out "$PACK_DIR/outputs/conan-graph-deps.json" \
    2>&1 | tee "$PACK_DIR/outputs/02-conan-graph.log"

# --- 03. SBOMs ---------------------------------------------------------------
echo "--- [03] generate_sbom ---"
python3 "$PACK_DIR/scripts/generate_sbom.py" \
    --deps "$PACK_DIR/outputs/dependencies.json" \
    --graph "$PACK_DIR/outputs/conan-graph-deps.json" \
    --raw-graph "$PACK_DIR/outputs/conan-graph-info-raw.json" \
    --outdir "$PACK_DIR/sbom" \
    2>&1 | tee "$PACK_DIR/outputs/03-generate-sbom.log"

# --- 04. crypto inventory -----------------------------------------------------
echo "--- [04] crypto_inventory ---"
python3 "$PACK_DIR/scripts/crypto_inventory.py" \
    --tree "$TREE" --deps "$PACK_DIR/outputs/dependencies.json" \
    --out-json "$PACK_DIR/inventory/crypto-inventory.json" \
    --out-md "$PACK_DIR/inventory/crypto-inventory.md" \
    2>&1 | tee "$PACK_DIR/outputs/04-crypto-inventory.log"

# --- 05. advisory triage -------------------------------------------------------
echo "--- [05] advisory_check ---"
python3 "$PACK_DIR/scripts/advisory_check.py" \
    --deps "$PACK_DIR/outputs/dependencies.json" \
    --graph "$PACK_DIR/outputs/conan-graph-deps.json" \
    --raw-out "$PACK_DIR/outputs/advisory-check-raw.json" \
    --findings-json "$PACK_DIR/findings/findings-register.json" \
    --findings-md "$PACK_DIR/findings/findings-register.md" \
    --records-dir "$PACK_DIR/outputs/osv-records" \
    --controls-out "$PACK_DIR/outputs/osv-controls.json" \
    2>&1 | tee "$PACK_DIR/outputs/05-advisory-check.log"

# --- 06. digests ----------------------------------------------------------------
echo "--- [06] digests ---"
"$PACK_DIR/scripts/verify_digests.sh" --generate "$PACK_DIR"
"$PACK_DIR/scripts/verify_digests.sh" --verify "$PACK_DIR"

echo "=== harness complete ==="
