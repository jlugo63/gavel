#!/usr/bin/env bash
#
# run-validation.sh — wave-gated runner for tests/validation/
#
# The validation suite is organized into four waves:
#
#   Wave 1 (fast, local, deterministic)
#     V3  tamper detection
#     V4  Article 5 prohibited practice blocking
#     V5  Annex IV documentation validation
#     V10 compliance export offline acceptance (Ollama optional)
#
#   Wave 2 (fast, local, red-team scenarios)
#     V2  separation of powers
#     V6  multi-tenant isolation
#     V8  drift and oversight evasion
#
#   Wave 3 (slow, requires Ollama live) — gated on Wave 1+2 clean
#     V1  live Ollama adversarial enrollment
#
#   Wave 4 (slow, requires fleet + load infra) — gated on Wave 1+2 clean
#     V7  EDR fleet behavioral envelope
#     V9  sustained load
#
# Waves 3 and 4 only run when Wave 1+2 pass. Failure inside a wave halts
# the script immediately so the first signal is always the lowest-wave
# failure.
#
# Usage:
#   ./scripts/run-validation.sh              # waves 1+2 only (default)
#   ./scripts/run-validation.sh --all        # waves 1+2+3+4
#   ./scripts/run-validation.sh --wave 1     # single wave
#   ./scripts/run-validation.sh --wave 2
#
# Exit codes:
#   0  all requested waves passed
#   1  a wave failed (first-failure signal)
#   2  usage error

set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

WAVE_FILTER=""
RUN_ALL=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --all) RUN_ALL=1; shift ;;
        --wave) WAVE_FILTER="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,40p' "$0"
            exit 0
            ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

PY=${PY:-python}

FAILED_WAVES=()

run_wave() {
    local wave_name="$1"
    local halt_on_fail="$2"
    shift 2
    local paths=("$@")
    echo
    echo "=================================================================="
    echo " $wave_name"
    echo "=================================================================="
    "$PY" -m pytest "${paths[@]}" -q --tb=short
    local rc=$?
    if [[ $rc -ne 0 ]]; then
        FAILED_WAVES+=("$wave_name")
        echo
        if [[ "$halt_on_fail" == "halt" ]]; then
            echo "!! $wave_name FAILED (pytest exit $rc) — halting (blocks downstream waves)."
            exit 1
        else
            echo "!! $wave_name FAILED (pytest exit $rc) — continuing (wave is independent)."
        fi
    else
        echo "-- $wave_name passed."
    fi
}

want_wave() {
    # Returns 0 if this wave should run under the current filter.
    local n="$1"
    if [[ -n "$WAVE_FILTER" ]]; then
        [[ "$WAVE_FILTER" == "$n" ]]
        return
    fi
    return 0
}

if want_wave 1; then
    # Wave 1 halts — it gates everything downstream.
    run_wave "WAVE 1 — Compliance + Tamper (V3/V4/V5/V10)" halt \
        tests/validation/red_team/test_v3_tamper_detection.py \
        tests/validation/red_team/test_v4_article5_blocking.py \
        tests/validation/compliance/test_v5_annex_iv.py \
        tests/validation/compliance/test_v10_offline_acceptance.py
fi

if want_wave 2; then
    # Wave 2 halts — it also gates Wave 3+4.
    run_wave "WAVE 2 — Red Team (V2/V6/V8)" halt \
        tests/validation/red_team/test_v2_separation_of_powers.py \
        tests/validation/red_team/test_v6_tenant_isolation.py \
        tests/validation/red_team/test_v8_drift_evasion.py
fi

if [[ $RUN_ALL -eq 1 ]] || [[ "$WAVE_FILTER" == "3" ]]; then
    # Wave 3 does NOT halt — it is independent of Wave 4.
    if [[ -d tests/validation/e2e ]]; then
        run_wave "WAVE 3 — Live Ollama Adversarial (V1)" continue \
            tests/validation/e2e/
    else
        echo "(Wave 3 skipped: tests/validation/e2e/ not yet populated)"
    fi
fi

if [[ $RUN_ALL -eq 1 ]] || [[ "$WAVE_FILTER" == "4" ]]; then
    if [[ -d tests/validation/load ]]; then
        run_wave "WAVE 4 — Load + Fleet (V7/V9)" continue \
            tests/validation/load/
    else
        echo "(Wave 4 skipped: tests/validation/load/ not yet populated)"
    fi
fi

echo
echo "=================================================================="
if [[ ${#FAILED_WAVES[@]} -eq 0 ]]; then
    echo " ALL REQUESTED WAVES PASSED"
    exit 0
else
    echo " SUMMARY: ${#FAILED_WAVES[@]} wave(s) failed"
    for w in "${FAILED_WAVES[@]}"; do
        echo "   - $w"
    done
    echo "=================================================================="
    exit 1
fi
