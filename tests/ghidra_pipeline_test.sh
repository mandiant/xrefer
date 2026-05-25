#!/usr/bin/env bash
# Ghidra pipeline test — runs all 30 samples, stores results in _ghidra_ref/ subdirs
# Usage: bash tests/ghidra_pipeline_test.sh

export GHIDRA_INSTALL_DIR="/home/vboxuser/Downloads/ghidra_12.1_PUBLIC_20260513/ghidra_12.1_PUBLIC"
SAMPLES_DIR="tests/e2e/xrefer-test/samples"
PASS=0; FAIL=0; SKIP=0
declare -a FAILED_LIST

echo "======================================================"
echo " Ghidra Pipeline Test — $(date)"
echo "======================================================"
echo ""

for sample_dir in "$SAMPLES_DIR"/*/; do
    sample_hash=$(basename "$sample_dir")
    binary="${sample_dir}binary"
    [ -f "$binary" ] || { echo "[SKIP] $sample_hash — no binary"; SKIP=$((SKIP+1)); continue; }

    size=$(stat -c%s "$binary")
    size_mb=$(echo "scale=1; $size/1048576" | bc)

    # Store Ghidra output alongside the binary but with ghidra-tagged name
    out_xrefer="${sample_dir}binary_ghidra.xrefer"
    out_html="${sample_dir}binary_ghidra_report.html"
    rm -f "$out_xrefer"

    echo -n "[ RUN ] ${sample_hash:0:16}...  (${size_mb} MB)  "

    start=$(date +%s)
    output=$(timeout 600 uv run xrefer --backend ghidra "$binary" --mode full --report-data-mode html 2>&1)
    code=$?
    elapsed=$(( $(date +%s) - start ))

    if [ $code -eq 124 ]; then
        echo "TIMEOUT (${elapsed}s)"
        FAIL=$((FAIL+1))
        FAILED_LIST+=("$sample_hash TIMEOUT(${elapsed}s)")
    elif echo "$output" | grep -q "Analysis completed successfully"; then
        # Rename the output files to ghidra-tagged names so they don't overwrite SMDA outputs
        mv "${sample_dir}binary.xrefer"      "$out_xrefer"      2>/dev/null
        mv "${sample_dir}binary_report.html" "$out_html"        2>/dev/null
        echo "PASS (${elapsed}s)"
        PASS=$((PASS+1))
    else
        err=$(echo "$output" | grep -iE "aborted|error|failed|exception" | tail -1)
        echo "FAIL — $err"
        FAIL=$((FAIL+1))
        FAILED_LIST+=("$sample_hash — $err")
    fi
done

echo ""
echo "======================================================"
echo " RESULTS: PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
echo "======================================================"
for f in "${FAILED_LIST[@]}"; do echo "  $f"; done
