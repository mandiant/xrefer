#!/usr/bin/env bash
# SMDA end-to-end pipeline test — runs all samples, reports pass/fail
# Usage: bash tests/smda_pipeline_test.sh

SAMPLES_DIR="tests/e2e/xrefer-test/samples"
PASS=0
FAIL=0
SKIP=0
declare -a FAILED_LIST
declare -a SKIPPED_LIST

echo "======================================================"
echo " SMDA Pipeline Test — $(date)"
echo " Samples: $SAMPLES_DIR"
echo "======================================================"
echo ""

for sample_dir in "$SAMPLES_DIR"/*/; do
    sample_hash=$(basename "$sample_dir")
    binary="${sample_dir}binary"

    if [ ! -f "$binary" ]; then
        echo "[SKIP] $sample_hash — no binary file"
        SKIP=$((SKIP + 1))
        SKIPPED_LIST+=("$sample_hash")
        continue
    fi

    binary_size=$(stat -c%s "$binary" 2>/dev/null || echo 0)
    size_mb=$(echo "scale=1; $binary_size / 1048576" | bc)

    # Skip samples > 2 MB — SMDA's disassembly phase itself OOMs 8 GB VM on larger PEs
    # (1.8 MB passes, 4.4 MB hangs the VM — safe threshold is ~2 MB)
    if [ "$binary_size" -gt 2097152 ]; then
        echo "[ RUN ] ${sample_hash:0:16}...  (${size_mb} MB)  SKIP (>2 MB, deferred to tomorrow)"
        SKIP=$((SKIP + 1))
        SKIPPED_LIST+=("$sample_hash (${size_mb} MB — too large for 8 GB VM)")
        continue
    fi

    # Remove old .xrefer cache to force fresh run
    rm -f "${binary}.xrefer"

    echo -n "[ RUN ] ${sample_hash:0:16}...  (${size_mb} MB)  "

    start_ts=$(date +%s)

    # Run with timeout — 10 min per sample (LLM categorization can be slow on cold cache)
    output=$(timeout 600 uv run xrefer --backend smda "$binary" --mode full --report-data-mode html 2>&1)
    exit_code=$?

    end_ts=$(date +%s)
    elapsed=$((end_ts - start_ts))

    if [ $exit_code -eq 124 ]; then
        echo "TIMEOUT (${elapsed}s — LLM too slow, increase timeout or warm cache)"
        FAIL=$((FAIL + 1))
        FAILED_LIST+=("$sample_hash (TIMEOUT ${elapsed}s)")
    elif echo "$output" | grep -q "\[+\] Analysis completed successfully"; then
        # Verify .xrefer and HTML were actually written
        if [ -f "${binary}.xrefer" ] && [ -f "${binary}_report.html" ]; then
            echo "PASS (${elapsed}s)"
            PASS=$((PASS + 1))
        else
            echo "FAIL — output files missing (${elapsed}s)"
            FAIL=$((FAIL + 1))
            FAILED_LIST+=("$sample_hash (missing output files)")
        fi
    else
        # Extract last error line for context
        last_err=$(echo "$output" | grep -i "error\|traceback\|exception\|failed" | tail -1)
        echo "FAIL (${elapsed}s) — $last_err"
        FAIL=$((FAIL + 1))
        FAILED_LIST+=("$sample_hash — $last_err")
    fi
done

echo ""
echo "======================================================"
echo " RESULTS"
echo "======================================================"
echo " PASS:  $PASS"
echo " FAIL:  $FAIL"
echo " SKIP:  $SKIP"
echo " TOTAL: $((PASS + FAIL + SKIP))"
echo ""

if [ ${#FAILED_LIST[@]} -gt 0 ]; then
    echo "--- Failed samples ---"
    for f in "${FAILED_LIST[@]}"; do
        echo "  $f"
    done
    echo ""
fi

if [ ${#SKIPPED_LIST[@]} -gt 0 ]; then
    echo "--- Skipped ---"
    for s in "${SKIPPED_LIST[@]}"; do
        echo "  $s"
    done
fi
