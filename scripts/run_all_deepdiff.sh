#!/usr/bin/env bash
#
# run_all_deepdiff.sh — Batch-run the DeepDiff write-trace pipeline over many tasks.
#
# For every subset_cyberGym task it discovers (or the ones you pass explicitly),
# it invokes scripts/deepdiff_pipeline.sh with a dedicated container, then FORCE-
# REMOVES that container afterwards — even if the pipeline crashes or is
# interrupted — so no containers are left alive between tasks.
#
# Usage:
#   scripts/run_all_deepdiff.sh [options] [task_dir ...]
#
#   task_dir   One or more task dirs, e.g. subset_cyberGym/projects/opensc/arvo_18798.
#              If none are given, tasks are auto-discovered under --root/--project.
#
# Options:
#   --root DIR       Root to scan for tasks (default: subset_cyberGym/projects)
#   --project NAME   Only run tasks under this project subdir (e.g. opensc)
#   --log-dir DIR    Directory for per-task logs (default: deepdiff_batch_logs)
#   --validation-dir DIR
#                    only_validation.py results dir (e.g. validation_output for
#                    subset_cyberGym). When set, each candidate patch is checked
#                    against <DIR>/<task_id>/<patch_id>/validation_summary.json and
#                    DeepDiff runs ONLY on patches whose validation succeeded (both
#                    TT/stage3 and RT/stage4). Patches that failed or were never
#                    validated are dropped; tasks with no passing patch are skipped.
#   --benign-count N Benign inputs to auto-generate per task (default: 1; 0=off).
#                    Also applies with `-- --generate-patch-inputs-only`: set it
#                    >0 there to additionally emit patch-blind benign_poc{N}.bin,
#                    or 0 to generate only patch-reaching/boundary inputs.
#   --use-existing-pocs
#                    Do NOT generate any inputs. Instead, for each task, use EVERY
#                    *.bin already in that task's data folder (the /projects/ ->
#                    /data/projects/ mapping) as matrix columns, via
#                    deepdiff_pipeline.sh --benign-dir. Skips gen_benign entirely
#                    (ignores --benign-count/--gen-patch-poc/--boundary/--min-iters).
#                    Alias: --benign-dir-auto. Ignored in --unit-test-only mode.
#   --input GLOB     Only meaningful with --use-existing-pocs: restrict the inputs
#                    to file(s) in the task's data folder matching GLOB (e.g.
#                    'agent_decoded.bin' or 'agent_*.bin') instead of every *.bin.
#                    Passed to the pipeline via --benign. Tasks with no match are
#                    skipped. Combine with --merge-new-input to append just those
#                    input(s) as new column(s) without touching existing ones.
#   --merge-new-input
#                    Forward --merge-new-input to deepdiff_pipeline.sh: rather than
#                    overwriting each task's matrix_result.txt, MERGE this run's
#                    input(s) into the existing matrix (new input -> new column,
#                    prior columns/rows preserved). Keyed by column label, so
#                    re-running an existing input is a no-op. Ignored in
#                    --unit-test-only mode.
#   --merge-new-input-auto
#                    Forward --merge-new-input-auto: like --merge-new-input but
#                    each task FIRST skips inputs already present as columns in
#                    its matrix_result.txt, so only not-yet-tested inputs are
#                    built/traced and appended as new columns (tasks whose inputs
#                    are all already columns are left unchanged). Best combined
#                    with --use-existing-pocs. Ignored in --unit-test-only mode.
#   --gen-patch-poc N benign_patch_poc inputs to auto-generate per task
#                    (forwarded to deepdiff_pipeline.sh --gen-patch-poc; default: 0=off)
#   --boundary       ADDITIONALLY generate patch-blind BOUNDARY inputs per task
#                    (forwarded to deepdiff_pipeline.sh --boundary): finds the
#                    decision boundary of a length-like field and samples inputs
#                    at/near it, exposing off-by-one / under-restrictive patches.
#                    Ignored in --unit-test-only mode.
#   --boundary-discover-max-scan N   Max byte offsets to probe during auto-discovery
#                    per task (forwarded to deepdiff_pipeline.sh; default: 512).
#   --boundary-discover-timeout S    Wall-clock seconds for auto-discovery sweep
#                    per task (forwarded to deepdiff_pipeline.sh; default: 600).
#   --min-iters N    Require benign/patch inputs to iterate the target loop >=N
#                    times (forwarded to deepdiff_pipeline.sh --min-iters). N=auto
#                    uses the PoC's own iteration count. Only takes effect when a
#                    loop is actually detected on the PoC path; skipped otherwise.
#                    Exposes patches whose effect only appears on the 2nd+ loop
#                    iteration. Ignored in --unit-test-only mode.
#   --unit-test-only COVERAGE PROBE across all tasks: run only the unit-test
#                    reachability check per task (no PoC / candidates / benign /
#                    matrix). The summary gains a 'coverage' column recording
#                    whether each task's unit tests cover the patched code.
#   --python          Use the Python pipeline (deepdiff_pipeline.py) instead of
#                    the shell one (deepdiff_pipeline.sh). The interpreter is
#                    ./.venv/bin/python if it exists, else python3.
#   --continue       Keep going after a task fails (default: on)
#   --stop-on-fail   Abort the whole batch on the first failing task
#   --skip-existing  Skip any task that already has a log in --log-dir, without
#                    starting a container. Lets an interrupted batch resume where
#                    it left off. Skips regardless of the earlier run's outcome,
#                    so delete a task's log to force it to re-run. Skipped tasks
#                    are recorded in batch_summary.tsv as SKIP-EXISTING.
#   -h|--help        Show this help
#   --               Everything after this is passed through to the pipeline
#                    e.g. ... -- --no-benign --engine libfuzzer
#
set -uo pipefail

usage() { sed -n '2,79p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PIPELINE="$SCRIPT_DIR/deepdiff_pipeline.sh"
USE_PYTHON=0
PYTHON_BIN=""

ROOT="subset_cyberGym/projects"
PROJECT=""
LOG_DIR="deepdiff_batch_logs"
VALIDATION_DIR=""
BENIGN_COUNT=1
USE_EXISTING=0
INPUT_GLOB=""
GEN_PATCH_POC=0
BOUNDARY=0
BOUNDARY_DISCOVER_MAX_SCAN=""
BOUNDARY_DISCOVER_TIMEOUT=""
MIN_ITERS=""
STOP_ON_FAIL=0
SKIP_EXISTING=0
UNIT_TEST_ONLY=0
MERGE_NEW_INPUT=0
MERGE_NEW_INPUT_AUTO=0
declare -a TASKS=()
declare -a PASS_THROUGH=()

while [ $# -gt 0 ]; do
    case "$1" in
        --root)        ROOT="$2"; shift 2;;
        --project)     PROJECT="$2"; shift 2;;
        --log-dir)     LOG_DIR="$2"; shift 2;;
        --validation-dir) VALIDATION_DIR="$2"; shift 2;;
        --benign-count) BENIGN_COUNT="$2"; shift 2;;
        --use-existing-pocs|--benign-dir-auto) USE_EXISTING=1; shift;;
        --input)       INPUT_GLOB="$2"; shift 2;;
        --merge-new-input) MERGE_NEW_INPUT=1; shift;;
        --merge-new-input-auto) MERGE_NEW_INPUT=1; MERGE_NEW_INPUT_AUTO=1; shift;;
        --gen-patch-poc) GEN_PATCH_POC="$2"; shift 2;;
        --boundary)    BOUNDARY=1; shift;;
        --boundary-discover-max-scan) BOUNDARY_DISCOVER_MAX_SCAN="$2"; shift 2;;
        --boundary-discover-timeout)  BOUNDARY_DISCOVER_TIMEOUT="$2"; shift 2;;
        --min-iters)   MIN_ITERS="$2"; shift 2;;
        --unit-test-only) UNIT_TEST_ONLY=1; shift;;
        --python)      USE_PYTHON=1; shift;;
        --continue)    STOP_ON_FAIL=0; shift;;
        --stop-on-fail) STOP_ON_FAIL=1; shift;;
        --skip-existing) SKIP_EXISTING=1; shift;;
        -h|--help)     usage 0;;
        --)            shift; PASS_THROUGH=("$@"); break;;
        -*)            echo "unknown option: $1" >&2; usage 1;;
        *)             TASKS+=("$1"); shift;;
    esac
done

[ -x "$PIPELINE" ] || { echo "ERROR: pipeline not found/executable: $PIPELINE" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found in PATH" >&2; exit 1; }

# Select the pipeline command: shell (default) or Python (--python). PIPELINE_CMD
# is an array so the Python variant runs as "<python> <pipeline.py>".
declare -a PIPELINE_CMD=()
if [ "$USE_PYTHON" -eq 1 ]; then
    PY_PIPELINE="$SCRIPT_DIR/deepdiff_pipeline.py"
    [ -f "$PY_PIPELINE" ] || { echo "ERROR: python pipeline not found: $PY_PIPELINE" >&2; exit 1; }
    if [ -z "$PYTHON_BIN" ]; then
        if [ -x "$REPO_ROOT/.venv/bin/python" ]; then PYTHON_BIN="$REPO_ROOT/.venv/bin/python"
        else PYTHON_BIN="python3"; fi
    fi
    PIPELINE_CMD=("$PYTHON_BIN" "-u" "$PY_PIPELINE")
else
    PIPELINE_CMD=("$PIPELINE")
fi

cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Discover tasks if none were passed explicitly: EVERY dir that contains a
# config.toml under $ROOT (optionally restricted to $ROOT/$PROJECT), at ANY
# nesting depth. This covers all subprojects and their tasks regardless of the
# exact directory layout. A project-level file such as project.toml is ignored
# because we only key off config.toml.
# ---------------------------------------------------------------------------
if [ "${#TASKS[@]}" -eq 0 ]; then
    scan_root="$ROOT"
    [ -n "$PROJECT" ] && scan_root="$ROOT/$PROJECT"
    [ -d "$scan_root" ] || { echo "ERROR: scan root not found: $scan_root" >&2; exit 1; }
    while IFS= read -r cfg; do
        TASKS+=("$(dirname "$cfg")")
    done < <(find "$scan_root" -type f -name config.toml | sort -V)
fi

[ "${#TASKS[@]}" -gt 0 ] || { echo "ERROR: no tasks found to run" >&2; exit 1; }

mkdir -p "$LOG_DIR"
SUMMARY="$LOG_DIR/batch_summary.tsv"
: > "$SUMMARY"
printf "task\tstatus\trc\tseconds\tcoverage\tlog\n" >> "$SUMMARY"

echo "=================================================================="
echo "DeepDiff batch run"
echo "  tasks        : ${#TASKS[@]}"
echo "  log dir      : $LOG_DIR"
echo "  pipeline     : ${PIPELINE_CMD[*]}"
if [ "$UNIT_TEST_ONLY" -eq 1 ]; then
    echo "  mode         : UNIT-TEST-ONLY coverage probe (no PoC/candidates/matrix)"
else
    if [ "$USE_EXISTING" -eq 1 ]; then
        if [ -n "$INPUT_GLOB" ]; then
            echo "  mode         : USE-EXISTING-POCS (per-task --benign '$INPUT_GLOB'; no gen_benign)"
        else
            echo "  mode         : USE-EXISTING-POCS (per-task --benign-dir; no gen_benign)"
        fi
    else
        echo "  benign-count : $BENIGN_COUNT"
        echo "  gen-patch-poc: $GEN_PATCH_POC"
        echo "  boundary     : $([ "$BOUNDARY" -eq 1 ] && echo ON || echo off)"
        echo "  min-iters    : ${MIN_ITERS:-off}"
    fi
fi
[ "$UNIT_TEST_ONLY" -ne 1 ] && echo "  merge-input  : $([ "$MERGE_NEW_INPUT_AUTO" -eq 1 ] && echo 'ON (auto: only new inputs)' || { [ "$MERGE_NEW_INPUT" -eq 1 ] && echo ON || echo off; })"
echo "  pass-through : ${PASS_THROUGH[*]:-<none>}"
echo "  stop-on-fail : $STOP_ON_FAIL"
echo "  skip-existing: $([ "$SKIP_EXISTING" -eq 1 ] && echo 'ON (tasks with a log in '"$LOG_DIR"' are skipped)' || echo off)"
echo "=================================================================="

# Force-remove a container by name, ignoring errors.
kill_container() { docker rm -f "$1" >/dev/null 2>&1 || true; }

# True if a validation_summary.json exists and reports overall success (i.e. every
# requested stage — TT/stage3 and RT/stage4 — passed).
validation_passed() {
    local f="$1"
    [ -f "$f" ] || return 1
    grep -Eq '"success"[[:space:]]*:[[:space:]]*true' "$f"
}

# Echo a comma-separated list of the task's candidate patches (patch.diff first,
# then patch_*.diff in natural order) that PASSED validation under
# $VALIDATION_DIR/<task_id>/<patch_id>/validation_summary.json.
passing_patches_csv() {
    local task_dir="$1"
    local task_id patch_id vs pf
    task_id="$(echo "$task_dir" | sed -E 's#.*/projects/##; s#/#_#g')"
    local -a cands=() keep=()
    [ -f "$task_dir/patch.diff" ] && cands+=("patch.diff")
    while IFS= read -r pf; do [ -n "$pf" ] && cands+=("$pf"); done \
        < <(cd "$task_dir" && ls patch_*.diff 2>/dev/null | sort -V)
    for pf in "${cands[@]}"; do
        patch_id="${pf%.diff}"
        vs="$VALIDATION_DIR/$task_id/$patch_id/validation_summary.json"
        if validation_passed "$vs"; then
            keep+=("$pf")
        else
            echo "   skip patch $pf (validation not passed: $vs)" >&2
        fi
    done
    local IFS=,
    echo "${keep[*]}"
}

declare -i n_ok=0 n_fail=0 n_covers=0 n_nocover=0
CURRENT_CONTAINER=""

# Guarantee cleanup of the in-flight container if the batch is interrupted.
on_exit() { [ -n "$CURRENT_CONTAINER" ] && kill_container "$CURRENT_CONTAINER"; }
trap on_exit EXIT INT TERM

for task_dir in "${TASKS[@]}"; do
    if [ ! -f "$task_dir/config.toml" ]; then
        echo ">> SKIP $task_dir (no config.toml)"
        printf "%s\tSKIP\t-\t0\t-\t-\n" "$task_dir" >> "$SUMMARY"
        continue
    fi

    # Unique, filesystem-safe container name derived from the task path.
    tag="$(echo "$task_dir" | sed -E 's#.*/projects/##; s#[/ ]#-#g')"
    cname="deepdiff-batch-$tag"
    log="$LOG_DIR/${tag}.log"

    # --skip-existing: treat a pre-existing per-task log as "already done" and move
    # on, without starting a container or touching the task's outputs. Checked
    # before any container work so a skip has no side effects. Note this skips
    # regardless of how the earlier run ended — delete the log (or drop the flag)
    # to force a re-run.
    if [ "$SKIP_EXISTING" -eq 1 ] && [ -f "$log" ]; then
        echo ">> SKIP $task_dir (log exists: $log)"
        printf "%s\tSKIP-EXISTING\t-\t0\t-\t%s\n" "$task_dir" "$log" >> "$SUMMARY"
        continue
    fi

    # Validation gating: only run DeepDiff on patches that passed only_validation.py.
    # Not applied in unit-test-only mode (that probe does not consult candidate patches).
    declare -a PATCH_ARGS=()
    if [ -n "$VALIDATION_DIR" ] && [ "$UNIT_TEST_ONLY" -ne 1 ]; then
        keep_csv="$(passing_patches_csv "$task_dir")"
        if [ -z "$keep_csv" ]; then
            echo ">> SKIP $task_dir (no patches passed validation in $VALIDATION_DIR)"
            printf "%s\tSKIP\t-\t0\t-\t-\n" "$task_dir" >> "$SUMMARY"
            continue
        fi
        echo ">> validated patches for $task_dir: $keep_csv"
        PATCH_ARGS=(--patches "$keep_csv")
    fi

    echo ""
    echo ">> RUN  $task_dir  (container=$cname)"
    CURRENT_CONTAINER="$cname"
    kill_container "$cname"   # clear any stale container with this name

    start=$(date +%s)
    if [ "$UNIT_TEST_ONLY" -eq 1 ]; then
        "${PIPELINE_CMD[@]}" "$task_dir" --container "$cname" --unit-test-only \
            "${PASS_THROUGH[@]}" \
            >"$log" 2>&1
    else
        declare -a PATCH_INVOKE=()
        if [ "$USE_EXISTING" -eq 1 ]; then
            # Per-task data dir (same /projects/ -> /data/projects/ mapping the
            # pipeline uses).
            bdir="${task_dir/\/projects\//\/data\/projects\/}"
            if [ -n "$INPUT_GLOB" ]; then
                # Restrict to specific input file(s) matching --input GLOB (e.g.
                # agent_decoded.bin) rather than every *.bin in the data dir.
                declare -a _sel=()
                while IFS= read -r f; do [ -n "$f" ] && _sel+=("$f"); done \
                    < <(ls "$bdir"/$INPUT_GLOB 2>/dev/null | sort -V)
                if [ "${#_sel[@]}" -eq 0 ]; then
                    echo "  SKIP (no input matching '$INPUT_GLOB' in $bdir)"
                    kill_container "$cname"; CURRENT_CONTAINER=""
                    continue
                fi
                _csv=$(IFS=,; echo "${_sel[*]}")
                PATCH_INVOKE=(--benign "$_csv")
            else
                # Use every *.bin there as columns; no generation.
                PATCH_INVOKE=(--benign-dir "$bdir")
            fi
        else
            declare -a BOUNDARY_ARGS=()
            [ "$BOUNDARY" -eq 1 ] && BOUNDARY_ARGS=(--boundary)
            [ -n "$BOUNDARY_DISCOVER_MAX_SCAN" ] && BOUNDARY_ARGS+=(--boundary-discover-max-scan "$BOUNDARY_DISCOVER_MAX_SCAN")
            [ -n "$BOUNDARY_DISCOVER_TIMEOUT" ]  && BOUNDARY_ARGS+=(--boundary-discover-timeout  "$BOUNDARY_DISCOVER_TIMEOUT")
            declare -a MIN_ITERS_ARGS=()
            [ -n "$MIN_ITERS" ] && MIN_ITERS_ARGS=(--min-iters "$MIN_ITERS")
            PATCH_INVOKE=(--gen-benign "$BENIGN_COUNT" --gen-patch-poc "$GEN_PATCH_POC"
                          "${BOUNDARY_ARGS[@]}" "${MIN_ITERS_ARGS[@]}")
        fi
        declare -a MERGE_ARGS=()
        [ "$MERGE_NEW_INPUT" -eq 1 ] && MERGE_ARGS=(--merge-new-input)
        [ "$MERGE_NEW_INPUT_AUTO" -eq 1 ] && MERGE_ARGS=(--merge-new-input-auto)
        "${PIPELINE_CMD[@]}" "$task_dir" --container "$cname" \
            "${PATCH_INVOKE[@]}" "${MERGE_ARGS[@]}" "${PATCH_ARGS[@]}" "${PASS_THROUGH[@]}" \
            >"$log" 2>&1
    fi
    rc=$?
    end=$(date +%s)
    secs=$(( end - start ))

    # Always force-remove the container for this task, regardless of pipeline rc.
    kill_container "$cname"
    CURRENT_CONTAINER=""

    # In probe mode, extract the coverage verdict from the task log.
    cov="-"
    if [ "$UNIT_TEST_ONLY" -eq 1 ]; then
        if grep -q "VERDICT: unit tests DO cover" "$log"; then cov="COVERS"; n_covers+=1
        elif grep -q "VERDICT: unit tests do NOT cover" "$log"; then cov="NO-COVER"; n_nocover+=1
        else cov="?"; fi
    fi

    if [ "$rc" -eq 0 ]; then
        echo "   OK   $task_dir (${secs}s)$([ "$UNIT_TEST_ONLY" -eq 1 ] && echo " coverage=$cov") -> $log"
        printf "%s\tOK\t%d\t%d\t%s\t%s\n" "$task_dir" "$rc" "$secs" "$cov" "$log" >> "$SUMMARY"
        n_ok+=1
    else
        echo "   FAIL $task_dir (rc=$rc, ${secs}s) -> $log"
        printf "%s\tFAIL\t%d\t%d\t%s\t%s\n" "$task_dir" "$rc" "$secs" "$cov" "$log" >> "$SUMMARY"
        n_fail+=1
        if [ "$STOP_ON_FAIL" -eq 1 ]; then
            echo ">> stop-on-fail set; aborting batch."
            break
        fi
    fi
done

echo ""
echo "=================================================================="
echo "BATCH COMPLETE"
echo "  ok=$n_ok  fail=$n_fail  total=$(( n_ok + n_fail ))"
if [ "$UNIT_TEST_ONLY" -eq 1 ]; then
    echo "  coverage: COVERS=$n_covers  NO-COVER=$n_nocover  (unit-test-only probe)"
    echo "  tasks whose unit tests cover the patched code:"
    awk -F'\t' '$5=="COVERS"{print "    "$1}' "$SUMMARY"
fi
echo "  summary: $SUMMARY"
echo "=================================================================="

[ "$n_fail" -eq 0 ]
