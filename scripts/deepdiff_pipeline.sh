#!/usr/bin/env bash
#
# deepdiff_pipeline.sh — Generic DeepDiff write-trace differential pipeline.
#
# NO "correct patch" assumption. Every candidate patch is treated equally and
# compared ONLY against the vulnerable baseline, per input — mirroring the logic
# of repro_matrix.sh but generalized to any subset_cyberGym task.
#
# Given a task dir (config.toml, patch.diff, patch_*.diff), it sets up an
# OSS-Fuzz container, builds the vulnerable baseline plus every candidate patch
# with source-level write instrumentation, runs the PoC and N validated benign
# inputs under each build, and diffs the (address-normalized) traces to produce
# a patch x input matrix of EQUIVALENT / DIVERGENT / NO-DATA.
#
# Candidates:
#   p0 = patch.diff        (the shipped fix — but treated as just another candidate)
#   p1..pN = patch_*.diff   (mutants), sorted naturally
#
# Reading the matrix (each cell = patched-vs-vulnerable for that input):
#   * PoC column DIVERGENT   -> patch changes crash-path behaviour (candidate fix)
#   * benign column EQUIVALENT-> patch preserves valid-input behaviour (no regression)
#   * A GOOD patch: DIVERGENT on PoC, EQUIVALENT on every benign
#   * A BAD  patch: DIVERGENT on a benign input (breaks legitimate inputs)
#
# It auto-derives the file(s) and function(s) to instrument from patch.diff and
# records them, so it is NOT tied to the coolkey example.
#
# Usage:
#   scripts/deepdiff_pipeline.sh <task_dir> [options]
#
#   <task_dir>   e.g. subset_cyberGym/projects/opensc/arvo_18798
#
# Options:
#   --gen-benign N    Auto-generate N benign RT inputs (default 1; 0=off).
#                     PATCH-BLIND: validated only on the vulnerable build
#                     (not-trigger + reach-target); patches are never consulted.
#                     Written as benign_poc{N}.bin (+ per-input instrument_targets).
#   --gen-patch-poc N Auto-generate N benign_patch_poc inputs (default 0; 0=off).
#                     Validated as non-crashing on the vulnerable ASan build and
#                     must REACH the patched code (non-empty trace on the
#                     instrumented p0 build). Written as
#                     benign_patch_poc{N}.bin (+ per-input instrument_targets).
#   --benign FILE     Use provided benign input(s) (comma-separated host paths);
#                     skips auto-generation. Each becomes its own matrix column.
#   --benign-dir DIR  Use EVERY *.bin already in DIR as inputs (skips gen_benign
#                     entirely). Each file becomes its own matrix column labelled
#                     by its filename. The task's own poc.bin is EXCLUDED here
#                     (it is always traced as the dedicated PoC column, so keeping
#                     it would run it twice). Duplicate paths are de-duplicated.
#                     Combine with --benign to add extra explicit files. This is
#                     the "run DeepDiff on all the PoCs in a folder, no new
#                     generation" mode.
#   --no-benign       Skip benign inputs entirely (PoC-only differential)
#   --unit-test       ADDITIONALLY run the project's unit tests (test.sh / make
#                     check) under each instrumented build with DEEPDIFF_TRACE.
#                     If the tests reach the patched code (non-empty trace, or the
#                     tighten marker), a 'unit_test' column is added to the matrix
#                     comparing vuln-vs-patched unit-test traces (a real developer
#                     regression). If they never reach it, the column is skipped.
#   --unit-test-only  COVERAGE PROBE: build ONLY the instrumented vulnerable
#                     baseline, run the unit tests, report whether they reach the
#                     target function(s)/patch region, then exit. Skips PoC,
#                     candidate patches, benign generation and the matrix. Fast
#                     way to scan which tasks have unit-test coverage of the fix.
#   --tighten         Require generated benign/patch inputs to reach the PATCHED
#                     REGION, not merely the target function. Derives a marker
#                     variable from patch.diff (the LHS of an added assignment,
#                     e.g. `p` from `+ p = rbuf;`) and requires that write to
#                     appear in the coverage trace. Rejects "shallow" inputs that
#                     enter the function but early-return before the fix's code
#                     (which otherwise produce misleading DIVERGENT verdicts).
#   --tighten-marker REGEX
#                     Force the deep-reach marker (implies --tighten) instead of
#                     auto-deriving it. Use when the auto marker is too deep /
#                     near the crash path so no benign input can be generated
#                     (e.g. arvo_19222). REGEX is matched against trace lines,
#                     e.g. 'coolkey_v0_get_attribute_data:attr_out->attribute_length'.
#   --min-iters N     Require generated benign/patch inputs to iterate the target
#                     LOOP at least N times: the loop-carried coverage marker must
#                     appear >=N times in the trace (passed to gen_benign.py as
#                     --cover-min-count N). N=auto uses the PoC's own iteration
#                     count (>=2 when loop-carried). This rejects "shallow"
#                     single-iteration inputs that never exercise the multi-
#                     iteration path a patch changes (e.g. an injected
#                     `if(1) return;` at a loop-body end shows EQUIVALENT on
#                     1-iteration inputs but breaks legitimate multi-iteration
#                     ones). Default 1 (off).
#   --gen-attempts N  Max mutation attempts for input generation (default 2000).
#   --no-structured   Skip gen_benign.py's deterministic length-field sweep and
#                     use random mutation only.
#   --no-ccwrap       Do not install the /usr/local/ccwrap compiler wrappers, so
#                     compile.sh sees exactly the toolchain validate.py gives it.
#                     Use when a task builds under only_validation.py but not here
#                     and you want byte-for-byte build parity. Note the wrappers
#                     are already probed against the active compiler, so this is
#                     rarely needed.
#   --build-check     Preflight: build ONLY the instrumented sources (vuln plus
#                     each selected patch) to verify they still compile, print a
#                     per-variant PASS/FAIL summary, then exit. No crash-oracle
#                     is built and no inputs are generated, so this is a fast way
#                     to find tasks whose instrumentation is broken before
#                     committing to a full generation run. Exit code is 0 only if
#                     every instrumented variant compiled.
#   --generate-patch-inputs-only
#                     Build every patch selected by --patches, generate a separate
#                     patch-reaching input set for each build, then exit without
#                     producing the differential matrix. Outputs are named
#                     benign_patch_p0_pocN.bin, benign_patch_p1_pocN.bin, etc.
#                     Plain benign_poc{N}.bin are OFF by default in this mode, but
#                     an explicit --gen-benign N re-enables them (generated
#                     patch-blind against the vulnerable build, still no matrix).
#                     --boundary likewise adds benign_poc_agent_p{N}.bin.
#   --boundary        ADDITIONALLY generate patch-blind BOUNDARY inputs
#                     benign_poc_agent_p{N}.bin, each becoming its own matrix
#                     column. Binary-searches the largest length-field value that
#                     still does NOT crash the vulnerable build (and reaches the
#                     target), then samples inputs at/near that decision boundary
#                     (last-valid, last-valid-1, midpoint, ...). These expose
#                     off-by-one / under-restrictive patches that plain benign
#                     inputs (which sit deep in the safe region) miss. No patch is
#                     consulted. The field is AUTO-DISCOVERED (sweep offsets x
#                     widths {2,4,1} x endianness) unless --boundary-offset given.
#   --boundary-offset CSV  Byte offset(s) of the length field (skips auto-discovery).
#   --boundary-width  CSV  Field width(s) in bytes (default: 2, or {2,4,1} auto).
#   --boundary-endian E    'be' | 'le' | 'both' (default: be known / both auto).
#   --boundary-count  N    Max boundary inputs to emit (default: 4).
#   --boundary-discover-max-scan N   Max byte offsets to probe during auto-discovery
#                                    (default: 512; 0 = no limit).
#   --boundary-discover-timeout S    Wall-clock seconds for auto-discovery sweep
#                                    (default: 600; 0 = no limit).
#   --instrument_all_func_file
#                     Instrument ALL functions (and all their compile-safe
#                     scalar/pointer writes) in the patch-changed file(s), instead
#                     of only the patch-derived target function(s). Uses
#                     scripts/instrument_writes_all.py. The target FILE set is
#                     still auto-derived from patch.diff (or --files); only the
#                     per-function restriction is lifted. Aliases:
#                     --instrument_all_func, --instrument_all_write.
#                     (Write selection stays compile-safe: struct-field/string/
#                     memcpy writes are still skipped since they can't be cast to
#                     long without breaking the build.)
#   --instrument_all_exec
#                     WHOLE-PROGRAM: instrument ALL functions (and all compile-safe
#                     writes) in EVERY .c file under the source repo, so writes are
#                     captured everywhere along the execution path, not just the
#                     patch-changed file(s). Implies --instrument_all_func_file.
#                     Uses instrument_writes_all.py over the whole source tree
#                     (best-effort per file). WARNING: much slower to build and
#                     produces very large traces. Aliases: --capture-all-writes,
#                     --instrument_all_write_exec.
#   --funcs  CSV      Override auto-derived target functions (comma-separated)
#   --files  CSV      Override auto-derived target files (repo-relative, comma-sep)
#   --patches CSV     Explicit candidate patch list (comma-separated, relative to
#                     the task dir). Overrides the auto-discovered p0=patch.diff +
#                     p1..pN=patch_*.diff list; names are assigned p0..pN in the
#                     order given. Used to run DeepDiff only on patches that
#                     passed validation.
#   --data-dir DIR    Override data dir (default: task_dir /projects/ -> /data/projects/)
#   --container NAME  Container name (default: deepdiff-<task_id>)
#   --engine ENG      Fuzzing engine (default: honggfuzz)
#   --no-mirror       LEGACY: use the hardcoded gcr.io/oss-fuzz-base/base-builder
#                     image instead of the project-specific one declared in
#                     project.toml / config.toml. Default is to mirror
#                     only_validation.py and pick the image from the tomls.
#   --build-image IMG Explicit build image, overrides both --no-mirror and the
#                     project.toml lookup.
#   --no-setup        Reuse an existing container, skip source/backup setup
#   --keep            Do not remove the container on exit
#   --merge-new-input MERGE mode: instead of overwriting matrix_result.txt, fold
#                     this run's input(s) into any existing matrix — the new
#                     input becomes an extra COLUMN (and coverage row) while all
#                     prior columns/rows keep their verdicts. Merge is keyed by
#                     column label, so re-running an existing input is a no-op.
#   --merge-new-input-auto
#                     Like --merge-new-input, but FIRST drops any provided input
#                     whose column already exists in the saved matrix_result.txt,
#                     so only inputs NOT tested before are built/traced and then
#                     added as new columns. If every input is already a column,
#                     the run exits early leaving the matrix unchanged. Intended
#                     with --benign/--benign-dir (e.g. run_all --use-existing-pocs).
#   -h|--help         Show this help
#
set -uo pipefail

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
usage() {
    sed -n '2,/^set -uo pipefail$/p' "$0" | sed '$d; s/^# \{0,1\}//'
    exit "${1:-0}"
}
[ $# -ge 1 ] || usage 1

TASK_DIR="" BENIGN="" BENIGN_DIR="" FUNCS="" FILES_OVERRIDE="" DATA_DIR="" CONTAINER="" ENGINE="honggfuzz"
PATCHES_OVERRIDE=""
NO_SETUP=0 KEEP=0 GEN_BENIGN=1 GEN_BENIGN_SET=0 GEN_PATCH=0 NO_BENIGN=0 TIGHTEN=0 TIGHTEN_MARKER_OVERRIDE="" GEN_ATTEMPTS="" UNIT_TEST=0 ONLY_UT=0 INSTRUMENT_ALL=0 INSTRUMENT_ALL_EXEC=0
GENERATE_PATCH_INPUTS_ONLY=0
NO_STRUCTURED=0
NO_CCWRAP=0
BUILD_CHECK=0
MERGE_NEW_INPUT=0
MERGE_NEW_INPUT_AUTO=0
BOUNDARY=0 BOUNDARY_OFFSET="" BOUNDARY_WIDTH="" BOUNDARY_ENDIAN="" BOUNDARY_COUNT="" BOUNDARY_DISCOVER_MAX_SCAN="" BOUNDARY_DISCOVER_TIMEOUT=""
MIN_ITERS="1"
# Default: mirror only_validation.py — read build_image from project.toml/config.toml.
# Set MIRROR=0 with --no-mirror to fall back to the legacy hardcoded base-builder.
MIRROR=1
BUILD_IMAGE_OVERRIDE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --gen-benign) GEN_BENIGN="$2"; GEN_BENIGN_SET=1; shift 2;;
        --gen-patch-poc) GEN_PATCH="$2"; shift 2;;
        --benign)     BENIGN="$2"; shift 2;;
        --benign-dir) BENIGN_DIR="$2"; shift 2;;
        --no-benign)  NO_BENIGN=1; shift;;
        --min-iters)  MIN_ITERS="$2"; shift 2;;
        --instrument_all_func_file|--instrument_all_func|--instrument_all_write) INSTRUMENT_ALL=1; shift;;
        --instrument_all_exec|--capture-all-writes|--instrument_all_write_exec) INSTRUMENT_ALL=1; INSTRUMENT_ALL_EXEC=1; shift;;
        --unit-test)  UNIT_TEST=1; shift;;
        --unit-test-only) UNIT_TEST=1; ONLY_UT=1; shift;;
        --tighten)    TIGHTEN=1; shift;;
        --tighten-marker) TIGHTEN=1; TIGHTEN_MARKER_OVERRIDE="$2"; shift 2;;
        --boundary)   BOUNDARY=1; shift;;
        --boundary-offset) BOUNDARY=1; BOUNDARY_OFFSET="$2"; shift 2;;
        --boundary-width)  BOUNDARY=1; BOUNDARY_WIDTH="$2"; shift 2;;
        --boundary-endian) BOUNDARY=1; BOUNDARY_ENDIAN="$2"; shift 2;;
        --boundary-count)  BOUNDARY=1; BOUNDARY_COUNT="$2"; shift 2;;
        --boundary-discover-max-scan) BOUNDARY_DISCOVER_MAX_SCAN="$2"; shift 2;;
        --boundary-discover-timeout)  BOUNDARY_DISCOVER_TIMEOUT="$2"; shift 2;;
        --gen-attempts) GEN_ATTEMPTS="$2"; shift 2;;
        --no-structured) NO_STRUCTURED=1; shift;;
        --no-ccwrap) NO_CCWRAP=1; shift;;
        --build-check) BUILD_CHECK=1; shift;;
        --generate-patch-inputs-only) GENERATE_PATCH_INPUTS_ONLY=1; shift;;
        --funcs)      FUNCS="$2"; shift 2;;
        --files)      FILES_OVERRIDE="$2"; shift 2;;
        --patches)    PATCHES_OVERRIDE="$2"; shift 2;;
        --data-dir)   DATA_DIR="$2"; shift 2;;
        --container)  CONTAINER="$2"; shift 2;;
        --engine)     ENGINE="$2"; shift 2;;
        --no-setup)   NO_SETUP=1; shift;;
        --merge-new-input) MERGE_NEW_INPUT=1; shift;;
        --merge-new-input-auto) MERGE_NEW_INPUT=1; MERGE_NEW_INPUT_AUTO=1; shift;;
        --no-mirror)  MIRROR=0; shift;;
        --build-image) BUILD_IMAGE_OVERRIDE="$2"; shift 2;;
        --keep)       KEEP=1; shift;;
        -h|--help)    usage 0;;
        -*)           echo "unknown option: $1" >&2; usage 1;;
        *)            TASK_DIR="$1"; shift;;
    esac
done
[ -n "$TASK_DIR" ] || usage 1
TASK_DIR="$(cd "$TASK_DIR" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# In generate-only mode plain benign_poc inputs are off by default (the mode is
# about patch-reaching inputs), but an EXPLICIT --gen-benign N is honoured so the
# same run can also produce patch-blind benign_poc{N}.bin without a matrix.
[ "$GENERATE_PATCH_INPUTS_ONLY" -eq 0 ] || [ "$GEN_BENIGN_SET" -eq 1 ] || GEN_BENIGN=0

# ---------------------------------------------------------------------------
# Locate inputs
# ---------------------------------------------------------------------------
[ -f "$TASK_DIR/config.toml" ] || { echo "ERROR: $TASK_DIR/config.toml not found"; exit 1; }
[ -f "$TASK_DIR/patch.diff" ]  || { echo "ERROR: $TASK_DIR/patch.diff not found"; exit 1; }

cfg() { grep -E "^\s*$1\s*=" "$TASK_DIR/config.toml" | head -1 | tr -d '\r' | sed -E 's/[^=]*=\s*"?([^"]*)"?\s*$/\1/'; }
TASK_ID="$(cfg task_id)"
TARGET_PROG="$(cfg target_prog)"
VUL_COMMIT="$(cfg vul_commit)"
[ -n "$TARGET_PROG" ] || { echo "ERROR: target_prog missing in config.toml"; exit 1; }

if [ -z "$DATA_DIR" ]; then
    DATA_DIR="${TASK_DIR/\/projects\//\/data\/projects\/}"
fi
POC="$DATA_DIR/poc.bin"
SRC_TGZ="$DATA_DIR/src.tgz"
[ -f "$POC" ]     || { echo "ERROR: poc.bin not found at $POC"; exit 1; }
[ -f "$SRC_TGZ" ] || { echo "ERROR: src.tgz not found at $SRC_TGZ"; exit 1; }

# ---------------------------------------------------------------------------
# Candidate patches (NO reference/correct assumption):
#   p0 = patch.diff ; p1..pN = patch_*.diff (natural sort)
# ---------------------------------------------------------------------------
declare -a CAND_NAMES=() CAND_FILES=()
if [ -n "$PATCHES_OVERRIDE" ]; then
    # Explicit candidate list (e.g. only patches that passed validation).
    IFS=',' read -r -a _PLIST <<< "$PATCHES_OVERRIDE"
    ci=0
    for pf in "${_PLIST[@]}"; do
        [ -n "$pf" ] || continue
        [ -f "$TASK_DIR/$pf" ] || { echo "ERROR: --patches entry not found: $TASK_DIR/$pf"; exit 1; }
        CAND_NAMES+=("p$ci"); CAND_FILES+=("$pf"); ci=$((ci+1))
    done
    [ "${#CAND_FILES[@]}" -gt 0 ] || { echo "ERROR: --patches produced no candidate patches"; exit 1; }
else
    CAND_NAMES+=("p0"); CAND_FILES+=("patch.diff")
    mapfile -t MUTANTS < <(cd "$TASK_DIR" && ls patch_*.diff 2>/dev/null | sort -V)
    mi=1
    for m in "${MUTANTS[@]}"; do
        CAND_NAMES+=("p$mi"); CAND_FILES+=("$m"); mi=$((mi+1))
    done
fi

# ---------------------------------------------------------------------------
# Auto-derive instrumentation targets from patch.diff
# ---------------------------------------------------------------------------
if [ -z "$FILES_OVERRIDE" ]; then
    mapfile -t TFILES < <(grep -E '^\+\+\+ b/' "$TASK_DIR/patch.diff" | tr -d '\r' | sed -E 's#^\+\+\+ b/##' | sort -u)
else
    IFS=',' read -r -a TFILES <<< "$FILES_OVERRIDE"
fi
if [ -z "$FUNCS" ]; then
    # Function name sits right after the second @@ in each hunk header:
    #   @@ -787,9 +787,9 @@ static void parse_sec_attr_44(...)
    FUNCS="$(grep -E '^@@ .* @@ ' "$TASK_DIR/patch.diff" | tr -d '\r' \
             | sed -E 's/^@@ .* @@ //' \
             | grep -oE '[A-Za-z_][A-Za-z0-9_]*\s*\(' \
             | sed -E 's/\s*\($//' | awk 'NF' | sort -u | paste -sd, -)"
fi
if [ -z "$FUNCS" ]; then
    if [ "$INSTRUMENT_ALL" -eq 1 ]; then
        # All-function instrumentation doesn't need a specific target function;
        # record a placeholder. (--tighten / unit-test reachability that rely on
        # a real target function may be limited in this mode.)
        FUNCS="(all functions in changed file)"
    else
        echo "ERROR: could not derive target function; pass --funcs"; exit 1
    fi
fi
[ "${#TFILES[@]}" -gt 0 ] || { echo "ERROR: could not derive target file; pass --files"; exit 1; }

# Select the instrumenter: patch-scoped (default), all-functions-in-file, or
# whole-program (all functions in every .c file).
if [ "$INSTRUMENT_ALL" -eq 1 ]; then
    INSTR_SCRIPT="instrument_writes_all.py"
    [ -f "$SCRIPT_DIR/$INSTR_SCRIPT" ] || { echo "ERROR: $SCRIPT_DIR/$INSTR_SCRIPT not found"; exit 1; }
    if [ "$INSTRUMENT_ALL_EXEC" -eq 1 ]; then
        INSTR_DESC="WHOLE-PROGRAM: ALL functions in EVERY .c under the source repo (instrument_writes_all.py)"
    else
        INSTR_DESC="ALL functions in changed file(s) (instrument_writes_all.py)"
    fi
else
    INSTR_SCRIPT="instrument_writes.py"
    INSTR_DESC="patch-derived funcs: $FUNCS (instrument_writes.py)"
fi

# ---------------------------------------------------------------------------
# --tighten: derive a "deep reach" marker variable from patch.diff. We take the
# LHS identifier of an ADDED assignment line (e.g. `+  p = rbuf;` -> `p`), which
# is written only when execution reaches the patched region. Combined with the
# first target function it forms marker "<func>:<var>", passed to gen_benign as a
# required coverage marker so shallow early-return inputs are rejected.
# ---------------------------------------------------------------------------
TIGHTEN_MARKER=""
if [ "$TIGHTEN" -eq 1 ]; then
    if [ -n "$TIGHTEN_MARKER_OVERRIDE" ]; then
        # User-supplied marker wins (used verbatim for BOTH benign and patch).
        TIGHTEN_MARKER="$TIGHTEN_MARKER_OVERRIDE"
    else
        _first_func="${FUNCS%%,*}"
        # First simple identifier that is the LHS of an added assignment (skip '==',
        # struct-field targets 'a->b'/'a.b', and array subscripts).
        _tvar="$(grep -E '^\+[^+]' "$TASK_DIR/patch.diff" | tr -d '\r' | sed -E 's/^\+//' \
            | grep -oE '(^|[^A-Za-z0-9_>.])[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[^=]' \
            | grep -oE '[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[^=]' \
            | sed -E 's/[[:space:]]*=.*//' | awk 'NF' | head -1)"
        if [ -n "$_tvar" ] && [ -n "$_first_func" ]; then
            # \b keeps it space-free (shell-safe) yet exact (won't match e.g. 'ptr').
            TIGHTEN_MARKER="${_first_func}:${_tvar}\\b"
        fi
    fi
fi

[ -z "$CONTAINER" ] && CONTAINER="deepdiff-$(echo "$TASK_ID" | tr ':/ ' '---')"

echo "=================================================================="
echo "DeepDiff pipeline (no-correct-patch matrix mode)"
echo "  task_id     : $TASK_ID"
echo "  target_prog : $TARGET_PROG"
echo "  vul_commit  : $VUL_COMMIT"
echo "  data dir    : $DATA_DIR"
echo "  target files: ${TFILES[*]}"
echo "  target funcs: $FUNCS"
echo "  instrument  : $INSTR_DESC"
if [ "$TIGHTEN" -eq 1 ]; then
    echo "  tighten     : ON (deep-reach marker: ${TIGHTEN_MARKER:-<none derived; will fall back>})"
fi
[ "$MIN_ITERS" != "1" ] && echo "  min-iters   : $MIN_ITERS (require benign/patch inputs to iterate the target loop >= this many times)"
[ "$UNIT_TEST" -eq 1 ] && echo "  unit-test   : ON (run make check/test.sh under instrumentation; add column if it reaches the fix)"
echo "  candidates  : ${#CAND_NAMES[@]} ->"
for i in "${!CAND_NAMES[@]}"; do echo "                  ${CAND_NAMES[$i]} = ${CAND_FILES[$i]}"; done
if [ -n "$BENIGN" ] || [ -n "$BENIGN_DIR" ]; then BEN_DESC="provided${BENIGN:+ files=$BENIGN}${BENIGN_DIR:+ dir=$BENIGN_DIR} (no gen_benign)"; elif [ "$NO_BENIGN" -eq 1 ] || { [ "$GEN_BENIGN" -le 0 ] && [ "$GEN_PATCH" -le 0 ] && [ "$BOUNDARY" -eq 0 ]; }; then BEN_DESC="<none>"; else BEN_DESC="auto-generate benign=$GEN_BENIGN patch_poc=$GEN_PATCH boundary=$BOUNDARY (validated)"; fi
echo "  benign      : $BEN_DESC"
echo "  container   : $CONTAINER (engine=$ENGINE)"
echo "=================================================================="

container_running() { [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" = "true" ]; }
# Guard every in-container command: if the container has died (e.g. OOM-killed,
# or force-removed by a concurrent run reusing the same --container name), emit a
# single clear error instead of letting docker's raw "container is not running"
# message repeat into the results matrix.
__dex_dead_warned=0
dex() {
    if ! container_running; then
        if [ "$__dex_dead_warned" -eq 0 ]; then
            echo "ERROR: container '$CONTAINER' is not running — it was killed mid-run (OOM, or removed by another process/pipeline using the same --container name). Aborting further in-container steps." >&2
            __dex_dead_warned=1
        fi
        return 125
    fi
    docker exec "$CONTAINER" bash -c "$1"
}

# ---------------------------------------------------------------------------
# Container setup
# ---------------------------------------------------------------------------
# Resolve the build image, mirroring only_validation.py by default:
#   project.toml (parent dir) provides build_image; config.toml (task dir) may
#   override it. --no-mirror or --build-image bypass this.
DEFAULT_BUILD_IMAGE="gcr.io/oss-fuzz-base/base-builder"
if [ -n "$BUILD_IMAGE_OVERRIDE" ]; then
    BUILD_IMAGE="$BUILD_IMAGE_OVERRIDE"
elif [ "$MIRROR" -eq 1 ]; then
    BUILD_IMAGE="$(python3 - "$TASK_DIR" "$DEFAULT_BUILD_IMAGE" <<'PY'
import sys, os
try:
    import tomllib as t
except ImportError:
    import tomli as t
task_dir, default_img = sys.argv[1], sys.argv[2]
cfg = {}
for f in (os.path.join(task_dir, "..", "project.toml"),
          os.path.join(task_dir, "config.toml")):
    try:
        with open(f, "rb") as fh:
            cfg.update(t.loads(fh.read().decode("utf-8", "replace")))
    except FileNotFoundError:
        pass
print(cfg.get("build_image", default_img))
PY
)"
else
    BUILD_IMAGE="$DEFAULT_BUILD_IMAGE"
fi
echo ">> build image : $BUILD_IMAGE $([ "$MIRROR" -eq 0 ] && echo '(legacy: --no-mirror)' || echo '(mirror project.toml)')"

if [ "$NO_SETUP" -eq 0 ]; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    echo ">> starting container"
    docker run -dit --name "$CONTAINER" \
        -v "$DATA_DIR":/output \
        -v "$TASK_DIR":/proj \
        "$BUILD_IMAGE" bash >/dev/null

    echo ">> extracting source + installing deps (this can take a few minutes)"
    # Marker consumed by the setup block below (dex cannot pass env vars through).
    if [ "$NO_CCWRAP" -eq 1 ]; then
        dex 'touch /tmp/dd_no_ccwrap' >/dev/null 2>&1
    else
        dex 'rm -f /tmp/dd_no_ccwrap' >/dev/null 2>&1
    fi
    dex '
        set -e
        # Remove any prior extraction of THIS tarball (its own top-level entries)
        # WITHOUT touching the base image prebuilt fuzzing engines (/src/honggfuzz,
        # /src/aflplusplus, /src/libfuzzer, ...), which "compile" needs to link.
        # Strip a leading "./" (some tarballs are packed as ./repo/...) and drop the
        # bare "." entry so we never try to `rm -rf /src/.`.
        for _e in $(tar tzf /output/src.tgz | sed -e "s#^\./##" -e "s#/.*##" | grep -vE "^\.?$" | sort -u); do
            rm -rf "/src/$_e"
        done
        tar xzf /output/src.tgz -C /src
        # OpenSC autotools bootstrap needs configure --disable-strict; the sed is a
        # no-op for projects whose build.sh does not call ./configure, so it is safe.
        [ -f /src/build.sh ] && sed -i "s|./configure|./configure --disable-strict|" /src/build.sh || true
        # Best-effort build-tool + common -dev deps covering the ecosystems these
        # tasks use: autotools (opensc-style bootstraps), ninja-build (CMake/Ninja,
        # e.g. assimp), bison/flex/texinfo (GNU parser-generator projects, e.g.
        # binutils, whose make step generates arparse.c via yacc) and the common
        # system libraries some configure scripts require after deleting their
        # bundled copies (e.g. the ghostscript build.sh does `rm -rf zlib libpng`
        # then ./configure, so it needs system zlib + libpng headers). Never fatal:
        # a project needs only its own subset, so a failed install must not abort
        # setup. NOTE: deliberately NOT installing libfontconfig1-dev — its presence
        # makes ghostscript configure ENABLE fontconfig, but the task hardcoded
        # fuzzer link line does not add -lfontconfig, so the final link then fails
        # with undefined FcFontSetDestroy/FcConfigDestroy. Leaving fontconfig absent
        # lets configure disable it cleanly (the feature is not needed to fuzz).
        if ! command -v autoreconf >/dev/null 2>&1 || ! command -v ninja >/dev/null 2>&1 \
           || ! command -v bison >/dev/null 2>&1 || ! command -v flex >/dev/null 2>&1 \
           || ! command -v makeinfo >/dev/null 2>&1 \
           || ! (echo "#include <zlib.h>" | cc -E - >/dev/null 2>&1); then
            apt-get update -qq && apt-get install -y -qq \
                autoconf automake libtool m4 pkg-config perl \
                ninja-build bison flex texinfo \
                zlib1g-dev libpng-dev >/dev/null 2>&1 || true
        fi
        # afl-cc (bundled clang-22) emits LLVM bitcode instead of native ELF objects
        # when it sees -fcf-protection (which binutils libiberty adds via CET
        # detection). GNU ld/ar then cannot index/link the resulting archives
        # (archive has no index / file format not recognized). Wrap the afl compiler
        # front-ends so they strip -fcf-protection* and always produce native
        # objects; argv[0] is preserved (via exec -a) so afl-cc keeps its per
        # front-end instrumentation mode. Only affects tasks whose compile.sh uses
        # the afl engine; harmless otherwise.
        if [ -d /src/aflplusplus ]; then
            for NAME in afl-clang-fast afl-clang-fast++ afl-clang-lto afl-clang-lto++; do
                P=/src/aflplusplus/$NAME
                [ -e "$P" ] || continue
                grep -q DEEPDIFF-AFL-WRAP "$P" 2>/dev/null && continue
                rm -f "$P"
                cat > "$P" <<WEOF
#!/bin/bash
# DEEPDIFF-AFL-WRAP
args=()
for a in "\$@"; do case "\$a" in -fcf-protection*) ;; *) args+=("\$a");; esac; done
exec -a "$NAME" /src/aflplusplus/afl-cc "\${args[@]}"
WEOF
                chmod +x "$P"
            done
        fi
        [ -f /proj/prepare.sh ] && (tr -d "\r" < /proj/prepare.sh > /src/prepare.sh && chmod +x /src/prepare.sh && bash /src/prepare.sh) || true
        # Compiler wrappers that always append warning-downgrade flags LAST, so a
        # project that adds its own per-target -Werror (e.g. assimp) cannot promote
        # warnings to hard errors, AND so modern clang default-error diagnostics
        # (-Wint-conversion, -Wimplicit-*, -Wincompatible-*-types, ...) which a
        # bare -Wno-error does NOT downgrade are turned back into warnings. Needed
        # because these tasks were built with older clang; harmless for projects
        # that already compile clean.
        #
        # Built AFTER prepare.sh on purpose: prepare.sh may replace the toolchain
        # (binutils/arvo_19702 pins clang-10 so the PoC still traps), so both the
        # compiler path and the flag set must be resolved against the compiler that
        # actually ends up being used.
        #
        # Every candidate flag is PROBED against that compiler and dropped if
        # unsupported. Feeding clang a flag it does not know makes it print
        # "unknown warning option" on every single compile, and old autoconf
        # scripts (libiberty) treat any stderr output as a failed feature test —
        # that silently misdetects <limits.h>, so LONG_MIN goes undeclared and the
        # build dies in a way validate.py never reproduces. Probing keeps this
        # wrapper a strict no-op wherever it would otherwise diverge from
        # validate.py, which runs compile.sh with no wrapper at all.
        if [ -f /tmp/dd_no_ccwrap ]; then
            rm -rf /usr/local/ccwrap
            echo "ccwrap: disabled (--no-ccwrap) -> compiler used exactly as validate.py does"
        else
            DD_CAND_FLAGS="-Wno-error -Wno-error=int-conversion -Wno-error=implicit-int -Wno-error=implicit-function-declaration -Wno-error=incompatible-function-pointer-types -Wno-error=incompatible-pointer-types -Wno-error=return-type -Wno-error=deprecated-non-prototype -Wno-declaration-after-statement"
            dd_probe_flags() {
                _cc="$1"; _ext="$2"; _ok=""
                printf "int main(void){return 0;}\n" > /tmp/dd_probe.$_ext
                for _f in $DD_CAND_FLAGS; do
                    # -Werror=unknown-warning-option turns "flag not recognised"
                    # into a non-zero exit, which a bare compile would not do.
                    if "$_cc" -Werror=unknown-warning-option "$_f" -c /tmp/dd_probe.$_ext \
                            -o /tmp/dd_probe.o >/dev/null 2>&1; then
                        _ok="$_ok $_f"
                    fi
                done
                rm -f /tmp/dd_probe.$_ext /tmp/dd_probe.o
                printf "%s" "$_ok"
            }
            REAL_CC="$(command -v clang)"; REAL_CXX="$(command -v clang++)"
            WRAP_CC_FLAGS="$(dd_probe_flags "$REAL_CC" c)"
            WRAP_CXX_FLAGS="$(dd_probe_flags "$REAL_CXX" cpp)"
            mkdir -p /usr/local/ccwrap
            printf "#!/bin/bash\nexec %s \"\$@\"%s\n" "$REAL_CC"  "$WRAP_CC_FLAGS"  > /usr/local/ccwrap/clang
            printf "#!/bin/bash\nexec %s \"\$@\"%s\n" "$REAL_CXX" "$WRAP_CXX_FLAGS" > /usr/local/ccwrap/clang++
            chmod +x /usr/local/ccwrap/clang /usr/local/ccwrap/clang++
            echo "ccwrap: cc=$REAL_CC flags=[${WRAP_CC_FLAGS# }] cxx_flags=[${WRAP_CXX_FLAGS# }]"
        fi
        rm -rf /src_backup && cp -a /src /src_backup
        echo "setup done: top-level=$(ls /src | tr "\n" " "), build.sh present=$( [ -f /src/build.sh ] && echo yes || echo no )"
    ' || { echo "SETUP FAILED"; exit 1; }
fi
docker cp "$SCRIPT_DIR/$INSTR_SCRIPT" "$CONTAINER":/tmp/instrument.py >/dev/null
docker cp "$SCRIPT_DIR/gen_benign.py" "$CONTAINER":/tmp/gen_benign.py >/dev/null
dex 'mkdir -p /output/traces'

# ---------------------------------------------------------------------------
# Derive the extracted source root generically. The tarball's top-level layout
# is project-specific (opensc -> /src/opensc, assimp -> /src/assimp,
# binutils -> /src/binutils-gdb, and sometimes multiple sibling dirs), so we
# locate the directory that actually contains the first patch-target file.
# Falls back to a maxdepth search, then to the sole top-level dir.
# ---------------------------------------------------------------------------
REPO_DIR="$(dex "
    f='${TFILES[0]}'
    for base in /src /src/*/; do
        base=\${base%/}
        [ -f \"\$base/\$f\" ] && { echo \"\$base\"; exit 0; }
    done
    hit=\$(find /src -maxdepth 5 -type f -path \"*/\$f\" -print -quit 2>/dev/null)
    [ -n \"\$hit\" ] && { echo \"\${hit%/\$f}\"; exit 0; }
    # last resort: a single top-level directory under /src
    only=\$(ls -d /src/*/ 2>/dev/null); n=\$(echo \"\$only\" | grep -c .)
    [ \"\$n\" = 1 ] && echo \"\${only%/}\"
" | tr -d '\r' | head -1)"
[ -n "$REPO_DIR" ] || { echo "ERROR: could not locate source repo dir for target file '${TFILES[0]}' under /src (pass --files with a correct repo-relative path)"; exit 1; }
echo ">> source repo dir: $REPO_DIR"

# ---------------------------------------------------------------------------
# Derive the build working directory (the OSS-Fuzz WORKDIR). build.sh may assume
# cwd is either $SRC or $SRC/<repo> depending on the project's Dockerfile WORKDIR
# (e.g. assimp's build.sh runs `cmake CMakeLists.txt` from $SRC/assimp, while
# binutils' build.sh does `cd binutils-gdb` from $SRC). The task's compile.sh
# encodes this exactly as its `cd <dir>` line, so we extract and reuse it.
# Falls back to REPO_DIR.
# ---------------------------------------------------------------------------
BUILD_WORKDIR="$REPO_DIR"
if dex 'test -f /proj/compile.sh' 2>/dev/null; then
    _wd="$(dex "export SRC=/src; t=\$(grep -oE '^[[:space:]]*cd[[:space:]]+[^[:space:]]+' /proj/compile.sh | tail -1 | awk '{print \$2}'); [ -n \"\$t\" ] && eval echo \"\$t\"" | tr -d '\r' | head -1)"
    [ -n "$_wd" ] && dex "test -d '$_wd'" 2>/dev/null && BUILD_WORKDIR="$_wd"
fi
echo ">> build workdir  : $BUILD_WORKDIR"

# Clear stale benign inputs from previous runs so they don't pollute this matrix
# (old benign_poc*.bin would be miscounted as this run's benign columns).
# Traces in /output/traces are intentionally KEPT for future inspection: each is
# overwritten in place (rm -f + rewrite) by build_and_trace when regenerated, and
# the matrix only reads logs for candidates that actually built this run, so
# lingering logs from prior runs cannot produce stale verdicts here.
#
# IMPORTANT: /output is bind-mounted to the host DATA_DIR (see docker run -v
# above), so this rm deletes HOST files. In provided-inputs mode (--benign /
# --benign-dir) the user's inputs (which may be named benign_poc*.bin and may
# live in DATA_DIR itself) MUST NOT be deleted, and gen_benign never runs so
# there is nothing stale to clear. Skip the destructive cleanup in that mode.
if [ -z "$BENIGN" ] && [ -z "$BENIGN_DIR" ]; then
    if [ "$GENERATE_PATCH_INPUTS_ONLY" -eq 1 ]; then
        # Independent per-patch generation is scoped to THIS run's --patches
        # selection (and --boundary), so only clear the outputs this run is
        # about to (re)generate — NOT the whole benign_patch_p*_poc* family —
        # so a prior run's inputs for a DIFFERENT --patches selection (e.g.
        # patch_1.diff generated yesterday, patch.diff being generated today)
        # are preserved instead of silently wiped.
        for _cn in "${CAND_NAMES[@]}"; do
            dex "rm -f /output/benign_patch_${_cn}_poc*.bin /output/benign_patch_${_cn}_poc*.instrument_targets.txt"
        done
        [ "$BOUNDARY" -eq 1 ] && dex 'rm -f /output/benign_poc_agent_p*.bin /output/benign_poc_agent_p*.instrument_targets.txt'
        # Numeric-suffix glob only, so boundary inputs (benign_poc_agent_p*.bin)
        # generated by a previous run are never caught by the benign cleanup.
        [ "$GEN_BENIGN" -gt 0 ] && dex 'rm -f /output/benign_poc[0-9]*.bin /output/benign_poc[0-9]*.instrument_targets.txt'
    else
        dex 'rm -f /output/benign_poc*.bin /output/benign_patch_poc*.bin /output/benign_patch_p*_poc*.bin /output/benign_provided_*.bin /output/*.instrument_targets.txt'
    fi
else
    echo ">> provided-inputs mode: skipping benign cleanup (preserving host inputs in /output)"
    dex 'rm -f /output/*.instrument_targets.txt'
fi

# Persist the per-task instrumentation targets (written in-container because the
# host-mounted traces/ dir is root-owned). This is the "instrument file" record.
dex "printf '%s\n' '# DeepDiff instrumentation targets for $TASK_ID' '# auto-derived from patch.diff (override with --files/--funcs)' '# mode: $INSTR_DESC' 'files=${TFILES[*]}' 'funcs=$FUNCS' > /output/traces/instrument_targets.txt"

# ---------------------------------------------------------------------------
# Build one instrumented variant into /tmp/bin_<name> (reuse if already built).
# name "vuln" builds the unpatched baseline; else applies the candidate patch.
# ---------------------------------------------------------------------------
CFILES_ABS=""
for f in "${TFILES[@]}"; do CFILES_ABS="$CFILES_ABS $REPO_DIR/$f"; done

# Instrumentation step run inside the container for each build variant.
#  * whole-program: instrument every .c under the source tree (best-effort per
#    file; xargs batches keep the arg list bounded).
#  * otherwise: instrument only the patch-changed file(s).
INSTR_SRC_ROOT="$REPO_DIR"
if [ "$INSTRUMENT_ALL_EXEC" -eq 1 ]; then
    INSTR_STEP="find $INSTR_SRC_ROOT -name '*.c' -print0 | xargs -0 -r -n 40 python3 /tmp/instrument.py >/dev/null 2>&1"
else
    INSTR_STEP="DEEPDIFF_FUNCS='$FUNCS' python3 /tmp/instrument.py $CFILES_ABS >/dev/null"
fi

build_variant_stash() {
    local name="$1" patch="$2"
    local build_log="/tmp/dd_build_${CONTAINER}_${name}_$$.log"
    if dex "test -x /tmp/bin_$name" 2>/dev/null; then
        return 0
    fi
    dex "
        set -e
        rm -rf /src && cp -a /src_backup /src
        if [ -n '$patch' ]; then
            tr -d '\r' < '/proj/$patch' > /tmp/cur_patch.diff
            cd $REPO_DIR && (git apply --ignore-whitespace /tmp/cur_patch.diff 2>/dev/null \
                || patch -p1 --binary < /tmp/cur_patch.diff) \
                || { echo 'PATCH_APPLY_FAILED'; exit 3; }
        fi
        $INSTR_STEP
        mkdir -p /output/traces/instrumented_src
        for _f in $CFILES_ABS; do cp \"\$_f\" /output/traces/instrumented_src/${name}_\$(basename \"\$_f\") 2>/dev/null || true; done
        cd $BUILD_WORKDIR
        export PATH=/usr/local/ccwrap:\$PATH
        export SRC=/src SANITIZER=none FUZZING_ENGINE=$ENGINE ARCHITECTURE=x86_64 \
               FUZZING_LANGUAGE=c++ CFLAGS='-g -O1 -Wno-error' CXXFLAGS='-g -O1 -Wno-error'
        compile
        cp /out/$TARGET_PROG /tmp/bin_$name
    " >"$build_log" 2>&1
    local rc=$?
    if [ $rc -ne 0 ]; then
        echo "   BUILD FAILED for $name (rc=$rc). Tail:"; tail -20 "$build_log" | sed 's/^/     /'
        if [ $rc -eq 137 ] || ! container_running; then
            echo "   NOTE: rc=137 (SIGKILL) usually means the process/container was killed —"
            echo "         out-of-memory from concurrent heavy builds, or the container was"
            echo "         force-removed by another run using the same --container name."
            container_running || { echo "   container is gone; aborting."; exit 1; }
        fi
        return 1
    fi
    # --unit-test: run the project's unit tests under THIS freshly-built
    # instrumented tree (still in /src) with DEEPDIFF_TRACE, so we capture what
    # the developer test-suite writes in the target functions. Best-effort: test
    # failures/timeouts never fail the build (the binary is already stashed). The
    # test console is kept (/tmp/ut_console_<name>.log) to report pass/skip counts.
    if [ "$UNIT_TEST" -eq 1 ]; then
        dex "
            [ -f /proj/test.sh ] && (tr -d "\r" < /proj/test.sh > /src/test.sh && chmod +x /src/test.sh) 2>/dev/null || true
            rm -f /output/traces/${name}_unittest.log
            export PATH=/usr/local/ccwrap:\$PATH
            cd $REPO_DIR
            if [ -f /src/test.sh ]; then
                SRC=/src DEEPDIFF_TRACE=/output/traces/${name}_unittest.log timeout 900 bash /src/test.sh >/tmp/ut_console_${name}.log 2>&1 || true
            else
                DEEPDIFF_TRACE=/output/traces/${name}_unittest.log timeout 900 make check >/tmp/ut_console_${name}.log 2>&1 || true
            fi
        " >/dev/null 2>&1 || true
        local un; un=$(dex "[ -s /output/traces/${name}_unittest.log ] && wc -l < /output/traces/${name}_unittest.log || echo 0")
        if [ "${un:-0}" -gt 0 ] 2>/dev/null; then
            echo "   $name unittest: REACHED target funcs ($un trace lines)"
        else
            echo "   $name unittest: did NOT reach target funcs (0 trace lines)"
        fi
    fi
    return 0
}

cleanup() { [ "$KEEP" -eq 0 ] && [ "$NO_SETUP" -eq 0 ] && docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Report whether the unit tests reached the target function(s)/patch region on
# the vulnerable build. Sets global UT_COL=1 when the tests reach it (so the
# matrix path can add a 'unit_test' column). Prints the test PASS/SKIP summary
# and, when not reached, the likely reason.
# ---------------------------------------------------------------------------
UT_COL=0
unit_test_report() {
    echo ""
    echo ">> Unit-test reachability analysis (target funcs: $FUNCS)"
    local utn utsum
    utn=$(dex "[ -s /output/traces/vuln_unittest.log ] && wc -l < /output/traces/vuln_unittest.log || echo 0")
    utsum=$(dex "grep -hE '^# (TOTAL|PASS|SKIP|FAIL|XFAIL|ERROR):' /tmp/ut_console_vuln.log 2>/dev/null | tr '\n' ' '" 2>/dev/null)
    echo "   test suite summary (vuln): ${utsum:-<no automake test summary found>}"
    if [ "${utn:-0}" -gt 0 ] 2>/dev/null; then
        echo "   reaches target function(s): YES ($utn trace lines in $FUNCS)"
        if [ -n "$TIGHTEN_MARKER" ]; then
            if dex "grep -qE '$TIGHTEN_MARKER' /output/traces/vuln_unittest.log" 2>/dev/null; then
                echo "   reaches patch region (marker '$TIGHTEN_MARKER'): YES"
                UT_COL=1
            else
                echo "   reaches patch region (marker '$TIGHTEN_MARKER'): NO"
            fi
        else
            echo "   (no patch-region marker; using function-level reachability)"
            UT_COL=1
        fi
    else
        echo "   reaches target function(s): NO (0 trace lines)"
        echo "   likely cause: the tests that run do not call $FUNCS, or the tests that would"
        echo "                 are SKIPPED (e.g. they need a real card / PCSC reader)."
    fi
}

# ---------------------------------------------------------------------------
# --unit-test-only: coverage probe. Build only the instrumented vulnerable
# baseline, run the unit tests, report reachability, and exit — no PoC, no
# candidate patches, no benign generation, no matrix.
# ---------------------------------------------------------------------------
if [ "$ONLY_UT" -eq 1 ]; then
    echo ">> --unit-test-only: building instrumented vulnerable baseline + running unit tests"
    build_variant_stash vuln "" || { echo "vuln build failed, aborting"; exit 1; }
    unit_test_report
    if [ "$UT_COL" -eq 1 ]; then
        echo ">> VERDICT: unit tests DO cover the target/patch region for $TASK_ID"
    else
        echo ">> VERDICT: unit tests do NOT cover the target/patch region for $TASK_ID"
    fi
    echo "Trace: $DATA_DIR/traces/vuln_unittest.log"
    exit 0
fi

# ---------------------------------------------------------------------------
# --build-check: preflight that ONLY verifies the instrumented sources compile.
# Builds the instrumented vulnerable baseline and each selected patch variant,
# then reports per-variant status and exits. Nothing is generated and no ASan
# crash-oracle is built, so this is a fast way to find tasks whose instrumented
# build is broken before committing to a full input-generation run.
# ---------------------------------------------------------------------------
if [ "$BUILD_CHECK" -eq 1 ]; then
    echo ">> --build-check: compiling instrumented sources only (no input generation)"
    declare -a BC_NAMES=() BC_STATUS=()
    BC_FAILED=0

    bc_run() {   # bc_run <name> <patch-file-or-empty>
        local name="$1" patch="$2"
        dex "rm -f /tmp/bin_$name" >/dev/null 2>&1 || true
        if build_variant_stash "$name" "$patch"; then
            BC_NAMES+=("$name"); BC_STATUS+=("ok")
        else
            BC_NAMES+=("$name"); BC_STATUS+=("FAIL")
            BC_FAILED=$((BC_FAILED+1))
        fi
    }

    echo "   building instrumented vulnerable baseline (vuln)"
    bc_run vuln ""

    # Check every candidate patch the run would have used, so the preflight
    # covers exactly the same set of instrumented builds as the real run.
    if [ "${#CAND_NAMES[@]}" -gt 0 ]; then
        for i in "${!CAND_NAMES[@]}"; do
            echo "   building instrumented ${CAND_NAMES[$i]} (${CAND_FILES[$i]})"
            bc_run "${CAND_NAMES[$i]}" "${CAND_FILES[$i]}"
        done
    fi

    echo "-------------------------------------------------------------"
    echo "BUILD-CHECK $TASK_ID"
    for i in "${!BC_NAMES[@]}"; do
        printf '  %-6s %s\n' "${BC_NAMES[$i]}" "${BC_STATUS[$i]}"
    done
    _bc_line=""
    for i in "${!BC_NAMES[@]}"; do
        _bc_line="$_bc_line${_bc_line:+ }${BC_NAMES[$i]}=${BC_STATUS[$i]}"
    done
    if [ "$BC_FAILED" -eq 0 ]; then
        echo "BUILD-CHECK RESULT: PASS ($_bc_line)"
        exit 0
    fi
    echo "BUILD-CHECK RESULT: FAIL ($BC_FAILED of ${#BC_NAMES[@]} failed: $_bc_line)"
    exit 1
fi

# ---------------------------------------------------------------------------
# RT inputs: explicit --benign wins; otherwise auto-generate inputs of two kinds
# via gen_benign.py, each becoming one matrix column:
#   * benign_poc{N}   — non-crashing on the VULNERABLE build + reaches the vuln
#                       function (PATCH-BLIND; patches never consulted).
#   * benign_patch_poc{N} — non-crashing on the vulnerable ASan build + reaches
#                       the PATCHED code (non-empty trace on instrumented p0).
# Every accepted input also gets a per-input <input>.instrument_targets.txt.
# BENIGN_PATHS holds container paths; BENIGN_LABELS holds column labels.
# ---------------------------------------------------------------------------
declare -a BENIGN_PATHS=() BENIGN_LABELS=()

# Column labels already present in an existing matrix_result.txt (PoC + each
# benign column). Used by --merge-new-input-auto to skip already-tested inputs.
existing_matrix_cols() {
    local mf="$1"
    [ -f "$mf" ] || return 0
    awk -F'|' '/^patch[[:space:]]*\|/ && /PoC/ {
        for (i = 2; i <= NF; i++) { gsub(/^[ \t]+|[ \t]+$/, "", $i); if ($i != "") print $i }
        exit
    }' "$mf"
}

if [ -n "$BENIGN" ] || [ -n "$BENIGN_DIR" ]; then
    # Provided-inputs mode: use existing *.bin files as-is; gen_benign is never
    # invoked. --benign gives explicit comma-separated files; --benign-dir adds
    # every *.bin in a folder. Columns are labelled by the input's filename stem
    # so the matrix stays readable (poc.bin included when present in the dir).
    declare -a _provided=()
    if [ -n "$BENIGN" ]; then
        IFS=',' read -r -a _b <<< "$BENIGN"
        for p in "${_b[@]}"; do [ -n "$p" ] && _provided+=("$p"); done
    fi
    if [ -n "$BENIGN_DIR" ]; then
        [ -d "$BENIGN_DIR" ] || { echo "ERROR: --benign-dir not found: $BENIGN_DIR"; exit 1; }
        # Pick up EVERY *.bin in the directory (agentic_*, benign_*, and any other
        # naming), natural-sorted, so no benign inputs are silently missed.
        while IFS= read -r f; do [ -n "$f" ] && _provided+=("$f"); done \
            < <(ls "$BENIGN_DIR"/*.bin 2>/dev/null | sort -V)
    fi
    # Drop the task's own poc.bin from the provided set: it is ALWAYS traced as
    # the dedicated PoC column below, so including it here would run it twice
    # (once as PoC, once as a redundant benign column). De-duplicate by resolved
    # path so the same file passed twice is not run twice either.
    declare -a _clean=()
    declare -A _seen=()
    _dropped_poc=0
    for p in "${_provided[@]}"; do
        if [ "$(basename "$p")" = "poc.bin" ]; then _dropped_poc=1; continue; fi
        rp="$(readlink -f "$p" 2>/dev/null || echo "$p")"
        [ -n "${_seen[$rp]:-}" ] && continue
        _seen[$rp]=1
        _clean+=("$p")
    done
    _provided=("${_clean[@]}")
    # --merge-new-input-auto: drop inputs whose column already exists in the saved
    # matrix so ONLY genuinely-new inputs are built/traced; then merge as new
    # columns. Labels are computed identically to the column labels below.
    if [ "$MERGE_NEW_INPUT_AUTO" -eq 1 ] && [ "${#_provided[@]}" -gt 0 ]; then
        _mf="$DATA_DIR/matrix_result.txt"
        if [ -f "$_mf" ]; then
            declare -a _existing_cols=()
            while IFS= read -r e; do [ -n "$e" ] && _existing_cols+=("$e"); done \
                < <(existing_matrix_cols "$_mf")
            declare -a _new_inputs=()
            for p in "${_provided[@]}"; do
                _l="$(basename "$p")"; _l="${_l%.bin}"
                _l="$(printf '%s' "$_l" | tr -c 'A-Za-z0-9_.-' '_')"
                _dup=0
                for e in "${_existing_cols[@]}"; do [ "$e" = "$_l" ] && { _dup=1; break; }; done
                if [ "$_dup" -eq 1 ]; then
                    echo ">> skip already-tested input (column '$_l' present): $p"
                else
                    _new_inputs+=("$p")
                fi
            done
            _provided=("${_new_inputs[@]}")
            if [ "${#_provided[@]}" -eq 0 ]; then
                echo ">> --merge-new-input-auto: no new inputs to test (all already columns in $_mf); leaving matrix unchanged."
                exit 0
            fi
            echo ">> --merge-new-input-auto: ${#_provided[@]} new input(s) not yet in $_mf; testing only those."
        fi
    fi
    [ "$_dropped_poc" -eq 1 ] && echo ">> excluded poc.bin from benign inputs (already the dedicated PoC column)"
    [ "${#_provided[@]}" -gt 0 ] || { echo "ERROR: no input .bin files found for --benign/--benign-dir"; exit 1; }
    echo ">> using ${#_provided[@]} provided input(s) as matrix columns (no gen_benign):"
    printf '     %s\n' "${_provided[@]}"
    # Copy provided inputs to a CONTAINER-LOCAL dir (NOT /output, which is bind-
    # mounted to the host DATA_DIR) so we never overwrite the user's files in the
    # data directory (e.g. clobbering benign_poc1.bin with a different input).
    dex 'mkdir -p /tmp/dd_provided'
    k=1
    for p in "${_provided[@]}"; do
        [ -f "$p" ] || { echo "   WARNING: input not found, skipping: $p"; continue; }
        docker cp "$p" "$CONTAINER":/tmp/dd_provided/benign_poc${k}.bin >/dev/null
        # Column label = filename stem, sanitised to column-safe chars.
        _lbl="$(basename "$p")"; _lbl="${_lbl%.bin}"
        _lbl="$(printf '%s' "$_lbl" | tr -c 'A-Za-z0-9_.-' '_')"
        BENIGN_PATHS+=("/tmp/dd_provided/benign_poc${k}.bin"); BENIGN_LABELS+=("$_lbl")
        echo "   col $k: $_lbl  ($p)"
        k=$((k+1))
    done
elif [ "$NO_BENIGN" -eq 0 ] && { [ "$GEN_BENIGN" -gt 0 ] || [ "$GEN_PATCH" -gt 0 ] || [ "$BOUNDARY" -eq 1 ]; }; then
    echo ">> generating RT inputs: benign=$GEN_BENIGN patch_poc=$GEN_PATCH boundary=$BOUNDARY"
    echo "   building instrumented vulnerable reference (benign reach-target coverage)"
    build_variant_stash vuln "" || echo "   (vuln cover build failed)"
    if [ "$GEN_PATCH" -gt 0 ]; then
        if [ "$GENERATE_PATCH_INPUTS_ONLY" -eq 1 ]; then
            echo "   building selected instrumented patches for independent generation"
            for i in "${!CAND_NAMES[@]}"; do
                # p0/p1 names depend on the current --patches ordering. Rebuild
                # them even with --no-setup so a prior run cannot supply a stale
                # binary associated with a different patch file.
                dex "rm -f /tmp/bin_${CAND_NAMES[$i]}"
                build_variant_stash "${CAND_NAMES[$i]}" "${CAND_FILES[$i]}" \
                    || echo "   (${CAND_NAMES[$i]} cover build failed)"
            done
        else
            echo "   building instrumented patched reference p0 (patch reach-target coverage)"
            build_variant_stash p0 "patch.diff" || echo "   (patch cover build failed)"
        fi
    fi
    echo "   building crash-oracle (vulnerable, task compile.sh / ASan)"
    dex '
        set -e
        rm -rf /src && cp -a /src_backup /src
        [ -f /proj/compile.sh ] && (tr -d "\r" < /proj/compile.sh > /src/compile.sh && chmod +x /src/compile.sh)
        [ -f /proj/run_poc.sh ] && (tr -d "\r" < /proj/run_poc.sh > /src/run_poc.sh && chmod +x /src/run_poc.sh)
        export PATH=/usr/local/ccwrap:$PATH
        export SRC=/src
        bash /src/compile.sh
    ' >/tmp/dd_oracle.log 2>&1 || { echo "   ORACLE BUILD FAILED"; tail -6 /tmp/dd_oracle.log | sed 's/^/     /'; }
    if dex 'test -x /out/'"$TARGET_PROG" 2>/dev/null; then
        # Default (and benign-only path): use the task harness directly against the
        # vulnerable ASan build currently in /out. This is the original, proven
        # oracle path — no snapshot/sed step, so no extra failure surface.
        RUN_HARNESS="bash /src/run_poc.sh"
        PATCH_ARGS=""

        # Patch inputs need BOTH a vulnerable and a patched ASan oracle. Building
        # the patched oracle overwrites /out, so we first preserve the vulnerable
        # binary, then emit two dedicated harnesses (the task harness pointed at a
        # fixed binary path) so neither oracle depends on the current /out.
        if [ "$GEN_PATCH" -gt 0 ] && [ "$GENERATE_PATCH_INPUTS_ONLY" -eq 0 ]; then
            echo "   preserving vulnerable ASan oracle + building patched (p0) ASan oracle"
            dex "mkdir -p /tmp/asan_vuln && cp /out/$TARGET_PROG /tmp/asan_vuln/"
            dex "
                set -e
                rm -rf /src && cp -a /src_backup /src
                tr -d '\r' < /proj/patch.diff > /tmp/oracle_patch.diff
                cd $REPO_DIR && (git apply --ignore-whitespace /tmp/oracle_patch.diff 2>/dev/null \
                    || patch -p1 --binary < /tmp/oracle_patch.diff) || { echo PATCH_APPLY_FAILED; exit 3; }
                [ -f /proj/compile.sh ] && (tr -d '\r' < /proj/compile.sh > /src/compile.sh && chmod +x /src/compile.sh)
                [ -f /proj/run_poc.sh ] && (tr -d '\r' < /proj/run_poc.sh > /src/run_poc.sh && chmod +x /src/run_poc.sh)
                export PATH=/usr/local/ccwrap:\$PATH
                export SRC=/src
                bash /src/compile.sh
                mkdir -p /tmp/asan_patch && cp /out/$TARGET_PROG /tmp/asan_patch/
                sed 's#/out/$TARGET_PROG#/tmp/asan_vuln/$TARGET_PROG#g'  /src/run_poc.sh > /src/run_poc_vuln.sh
                sed 's#/out/$TARGET_PROG#/tmp/asan_patch/$TARGET_PROG#g' /src/run_poc.sh > /src/run_poc_patch.sh
            " >/tmp/dd_oracle_patch.log 2>&1 || { echo "   PATCH ORACLE BUILD FAILED"; tail -6 /tmp/dd_oracle_patch.log | sed 's/^/     /'; }
            if dex 'test -s /src/run_poc_vuln.sh && test -s /src/run_poc_patch.sh && test -x /tmp/asan_patch/'"$TARGET_PROG" 2>/dev/null && dex 'test -x /tmp/bin_p0' 2>/dev/null; then
                RUN_HARNESS="bash /src/run_poc_vuln.sh"
                PATCH_ARGS="--patch-run 'bash /src/run_poc_patch.sh' --patch-cover-run /tmp/bin_p0"
            else
                echo "   WARNING: patched oracle/harness or /tmp/bin_p0 missing; disabling patch_poc generation"
                GEN_PATCH=0
                # The patched build overwrote /out; restore the vulnerable binary so
                # the default run_poc.sh harness stays a correct vulnerable oracle.
                dex 'test -x /tmp/asan_vuln/'"$TARGET_PROG" 2>/dev/null && dex "cp /tmp/asan_vuln/$TARGET_PROG /out/$TARGET_PROG" || true
            fi
        fi

        COVER_ARG=""
        dex 'test -x /tmp/bin_vuln' 2>/dev/null && COVER_ARG="--cover-run /tmp/bin_vuln"
        # Derive a loop-depth marker: run the PoC on the instrumented vuln build
        # and pick the most-frequently-written traced variable. A variable written
        # many times is necessarily inside a loop, so requiring the benign trace to
        # contain it forces RT inputs to reach the vulnerable loop, not just the
        # function entry. Only used when it is clearly loop-carried (count > 1).
        MARKER_ARG=""
        MARKER_REGEX=""   # the bare marker regex chosen (for loop-recurrence check)
        if [ -n "$COVER_ARG" ]; then
            # Always capture the PoC trace on the instrumented vuln build.
            dex "rm -f /tmp/marker_poc.log; DEEPDIFF_TRACE=/tmp/marker_poc.log timeout 25 /tmp/bin_vuln /output/poc.bin >/dev/null 2>&1 || true"
            if [ "$TIGHTEN" -eq 1 ] && [ -n "$TIGHTEN_MARKER_OVERRIDE" ]; then
                # User forced the marker: use it verbatim for the benign gate too.
                MARKER_ARG="--cover-marker '$TIGHTEN_MARKER_OVERRIDE'"
                MARKER_REGEX="$TIGHTEN_MARKER_OVERRIDE"
                echo "   reach-target marker (benign): '$TIGHTEN_MARKER_OVERRIDE' (--tighten-marker override)"
            elif [ "$TIGHTEN" -eq 1 ]; then
                # --tighten (benign/vuln kind): require the DEEPEST-reaching write on
                # the vulnerable build — the traced write whose FIRST occurrence in
                # the PoC trace is latest. This is past any early-return gate, so
                # shallow inputs that bail early are rejected. We consider BOTH simple
                # identifiers AND struct-field writes (a->b, a.b): the latter are often
                # the genuinely-deep writes (e.g. 'key_info->key_reference' only written
                # past a guard), whereas a reused simple scalar like 'r' first appears
                # early even though it recurs deep. Falls back to the loop-depth heuristic.
                VULN_DEEP="$(dex "grep -nE '^[A-Za-z_][A-Za-z0-9_]*:[A-Za-z_][A-Za-z0-9_]*((->|\.)[A-Za-z_][A-Za-z0-9_]*)*[[:space:]]*=' /tmp/marker_poc.log 2>/dev/null | sed -E 's/^([0-9]+):([A-Za-z_][A-Za-z0-9_]*:[A-Za-z_][A-Za-z0-9_]*((->|\.)[A-Za-z_][A-Za-z0-9_]*)*).*/\1 \2/' | sort -k1,1n | sort -k2,2 -us | sort -k1,1nr | head -1 | sed -E 's/^[0-9]+ //'")"
                if [ -n "$VULN_DEEP" ]; then
                    MARKER_ARG="--cover-marker '${VULN_DEEP}\\b'"
                    MARKER_REGEX="${VULN_DEEP}\\b"
                    echo "   reach-target marker (benign): '${VULN_DEEP}\\b' (--tighten: deepest write on vuln build)"
                else
                    echo "   WARNING: --tighten could not derive a deep vuln marker; using non-empty-trace coverage for benign"
                fi
            else
                # Default: loop-depth marker = the most-frequently-written variable
                # (loop-carried when count > 1), forcing inputs past function entry.
                read -r MK_COUNT MK_VAR < <(dex "sed -E 's/ = .*//' /tmp/marker_poc.log 2>/dev/null | grep -E '^[A-Za-z_][A-Za-z0-9_]*:[A-Za-z_][A-Za-z0-9_]*$' | sort | uniq -c | sort -rn | head -1 | sed -E 's/^ *//'")
                if [ -n "${MK_VAR:-}" ] && [ "${MK_COUNT:-0}" -gt 1 ] 2>/dev/null; then
                    MARKER_ARG="--cover-marker $MK_VAR"
                    MARKER_REGEX="$MK_VAR"
                    echo "   reach-target marker: '$MK_VAR' (written ${MK_COUNT}x on PoC -> loop-carried)"
                else
                    echo "   reach-target marker: none (no clearly loop-carried variable; using non-empty-trace coverage)"
                fi
            fi
        fi

        # --tighten (patch kind): the patch-added assignment variable is written
        # only once execution reaches the PATCHED region, so it is the correct deep
        # marker for the patched build's coverage gate (--patch-cover-marker).
        # GUARD-ONLY patches (e.g. added `if (...) { free; LOG_TEST_RET; return; }`
        # with NO added assignment) yield an empty TIGHTEN_MARKER; in that case fall
        # back to the benign deep marker (MARKER_REGEX = deepest write on the vuln
        # build, which also exists on the patched build past the guard). This stops
        # patch_poc generation from accepting shallow inputs that bail out before the
        # patched region (e.g. on an early error-return), which would otherwise show a
        # meaningless EQUIVALENT patch_poc column.
        PATCH_MARKER_ARG=""
        PATCH_DEEP_MARKER="$TIGHTEN_MARKER"
        [ -z "$PATCH_DEEP_MARKER" ] && PATCH_DEEP_MARKER="$MARKER_REGEX"
        if [ "$TIGHTEN" -eq 1 ] && [ -n "$PATCH_DEEP_MARKER" ]; then
            PATCH_MARKER_ARG="--patch-cover-marker '$PATCH_DEEP_MARKER'"
            [ -z "${PATCH_ARGS:-}" ] || PATCH_ARGS="$PATCH_ARGS $PATCH_MARKER_ARG"
            if [ -n "$TIGHTEN_MARKER_OVERRIDE" ]; then
                echo "   reach-target marker (patch): '$PATCH_DEEP_MARKER' (--tighten-marker override)"
            elif [ -n "$TIGHTEN_MARKER" ]; then
                echo "   reach-target marker (patch): '$PATCH_DEEP_MARKER' (--tighten: patch-added write)"
            else
                echo "   reach-target marker (patch): '$PATCH_DEEP_MARKER' (--tighten: guard-only patch -> deepest vuln write)"
            fi
        fi

        # --min-iters: require the coverage marker to RECUR >=N times, i.e. the
        # input must iterate the target loop at least N times (not merely enter it
        # once). This ONLY engages when the marker is genuinely loop-carried — we
        # verify by counting how many times it actually recurs in the PoC's own
        # trace (POC_MARK_COUNT). If the target has NO loop on the PoC path
        # (marker occurs <=1x), min-iters is skipped: there is no loop to iterate,
        # so requiring N>1 recurrences would be impossible and reject everything.
        MINCOUNT_ARG=""
        if [ "$MIN_ITERS" != "1" ]; then
            if [ -z "$MARKER_REGEX" ]; then
                echo "   --min-iters $MIN_ITERS: no loop marker derived -> skipped (no loop detected on PoC path)"
            else
                POC_MARK_COUNT="$(dex "grep -cE '$MARKER_REGEX' /tmp/marker_poc.log 2>/dev/null || echo 0" | tr -dc '0-9')"
                POC_MARK_COUNT="${POC_MARK_COUNT:-0}"
                if [ "$POC_MARK_COUNT" -le 1 ] 2>/dev/null; then
                    echo "   --min-iters $MIN_ITERS: marker '$MARKER_REGEX' occurs ${POC_MARK_COUNT}x on PoC (not loop-carried) -> skipped (no loop to iterate)"
                else
                    if [ "$MIN_ITERS" = "auto" ]; then
                        _min=2   # loop confirmed; require at least a 2nd iteration
                    else
                        _min="$MIN_ITERS"
                    fi
                    # Never demand more iterations than the PoC itself achieves —
                    # that upper bound is provably reachable; beyond it may not be.
                    if [ "${_min}" -gt "$POC_MARK_COUNT" ] 2>/dev/null; then
                        echo "   --min-iters $_min exceeds PoC's ${POC_MARK_COUNT} iterations -> capping to $POC_MARK_COUNT"
                        _min="$POC_MARK_COUNT"
                    fi
                    if [ "${_min}" -gt 1 ] 2>/dev/null; then
                        MINCOUNT_ARG="--cover-min-count $_min"
                        echo "   min loop iterations (benign/patch): $_min (loop confirmed: marker recurs ${POC_MARK_COUNT}x on PoC)"
                    fi
                fi
            fi
        fi

        # Which kinds to generate (patch may have been downgraded above).
        TYPES=""
        [ "$GEN_BENIGN" -gt 0 ] && TYPES="benign"
        [ "$GEN_PATCH" -gt 0 ] && TYPES="${TYPES:+$TYPES,}patch"
        # Boundary inputs (patch-blind, divergence-capturing) are an add-on kind.
        BOUNDARY_ARGS=""
        if [ "$BOUNDARY" -eq 1 ]; then
            TYPES="${TYPES:+$TYPES,}boundary"
            [ -n "$BOUNDARY_OFFSET" ] && BOUNDARY_ARGS="$BOUNDARY_ARGS --boundary-offset '$BOUNDARY_OFFSET'"
            [ -n "$BOUNDARY_WIDTH" ]  && BOUNDARY_ARGS="$BOUNDARY_ARGS --boundary-width '$BOUNDARY_WIDTH'"
            [ -n "$BOUNDARY_ENDIAN" ] && BOUNDARY_ARGS="$BOUNDARY_ARGS --boundary-endian '$BOUNDARY_ENDIAN'"
            [ -n "$BOUNDARY_COUNT" ]  && BOUNDARY_ARGS="$BOUNDARY_ARGS --boundary-count '$BOUNDARY_COUNT'"
            [ -n "$BOUNDARY_DISCOVER_MAX_SCAN" ] && BOUNDARY_ARGS="$BOUNDARY_ARGS --boundary-discover-max-scan '$BOUNDARY_DISCOVER_MAX_SCAN'"
            [ -n "$BOUNDARY_DISCOVER_TIMEOUT" ]  && BOUNDARY_ARGS="$BOUNDARY_ARGS --boundary-discover-timeout '$BOUNDARY_DISCOVER_TIMEOUT'"
        fi
        # Per-input instrument_targets.txt content (task-level, patch-derived).
        INSTR_ARGS="--task-id '$TASK_ID' --instrument-files '${TFILES[*]}' --instrument-funcs '$FUNCS'"
        if [ -n "$TYPES" ]; then
            ATTEMPTS_ARG=""
            [ -n "$GEN_ATTEMPTS" ] && ATTEMPTS_ARG="--max-attempts $GEN_ATTEMPTS"
            STRUCTURED_ARG=""
            [ "$NO_STRUCTURED" -eq 1 ] && STRUCTURED_ARG="--no-structured"
            # NOTE: no --discriminate-run: benign generation must not look at patches.
            if [ "$GENERATE_PATCH_INPUTS_ONLY" -eq 1 ] && [ "$GEN_PATCH" -gt 0 ]; then
                _gen_fail=0
                # Patch-blind benign inputs (vulnerable build only), when the
                # caller explicitly asked for them with --gen-benign N.
                if [ "$GEN_BENIGN" -gt 0 ]; then
                    echo ">> generating patch-blind benign inputs (vulnerable build only)"
                    dex "python3 -u /tmp/gen_benign.py --poc /output/poc.bin --out-dir /output \
                         --types benign --count-benign $GEN_BENIGN \
                         --run '$RUN_HARNESS' $COVER_ARG $MARKER_ARG $MINCOUNT_ARG \
                         $ATTEMPTS_ARG $STRUCTURED_ARG $INSTR_ARGS" || _gen_fail=1
                fi
                for i in "${!CAND_NAMES[@]}"; do
                    _name="${CAND_NAMES[$i]}"
                    _patch="${CAND_FILES[$i]}"
                    if ! dex "test -x /tmp/bin_$_name"; then
                        echo "   WARNING: skipping $_name ($_patch): instrumented build missing"
                        _gen_fail=1
                        continue
                    fi
                    echo ">> generating patch inputs for $_name = $_patch"
                    dex "python3 -u /tmp/gen_benign.py --poc /output/poc.bin --out-dir /output \
                         --types patch --count-patch $GEN_PATCH --patch-prefix benign_patch_${_name}_poc \
                         --run '$RUN_HARNESS' --patch-cover-run /tmp/bin_$_name \
                         $PATCH_MARKER_ARG $MINCOUNT_ARG $ATTEMPTS_ARG $STRUCTURED_ARG $INSTR_ARGS" \
                        || _gen_fail=1
                done
                # --boundary is patch-blind (only the vuln build is consulted), so
                # it is generated ONCE here rather than per candidate patch.
                if [ "$BOUNDARY" -eq 1 ]; then
                    echo ">> generating patch-blind boundary inputs (vulnerable build only)"
                    dex "python3 -u /tmp/gen_benign.py --poc /output/poc.bin --out-dir /output \
                         --types boundary --run '$RUN_HARNESS' $COVER_ARG $MARKER_ARG $MINCOUNT_ARG \
                         $BOUNDARY_ARGS $ATTEMPTS_ARG $STRUCTURED_ARG $INSTR_ARGS" || _gen_fail=1
                fi
                if [ "$_gen_fail" -ne 0 ]; then
                    echo "ERROR: one or more selected patches or input kinds failed to build or generate inputs" >&2
                    exit 1
                fi
                echo ">> independent patch-input generation complete"
                exit 0
            elif [ "$GENERATE_PATCH_INPUTS_ONLY" -eq 1 ]; then
                # No "patch"-kind inputs requested (--gen-patch-poc 0) — e.g. only
                # --boundary and/or --gen-benign. Both remaining kinds are
                # patch-blind (vuln build only), so no per-candidate patch
                # build/loop is needed; generate once.
                dex "python3 -u /tmp/gen_benign.py --poc /output/poc.bin --out-dir /output \
                     --types $TYPES --count-benign $GEN_BENIGN --run '$RUN_HARNESS' \
                     $COVER_ARG $MARKER_ARG $MINCOUNT_ARG \
                     $BOUNDARY_ARGS $ATTEMPTS_ARG $STRUCTURED_ARG $INSTR_ARGS"
                _rc=$?
                if [ "$_rc" -ne 0 ]; then
                    echo "ERROR: input generation failed" >&2
                    exit 1
                fi
                echo ">> independent input generation complete"
                exit 0
            else
                dex "python3 -u /tmp/gen_benign.py --poc /output/poc.bin --out-dir /output \
                     --types $TYPES --count-benign $GEN_BENIGN --count-patch $GEN_PATCH \
                     --run '$RUN_HARNESS' $COVER_ARG $MARKER_ARG $MINCOUNT_ARG $PATCH_ARGS $BOUNDARY_ARGS $ATTEMPTS_ARG $STRUCTURED_ARG $INSTR_ARGS" || true
            fi
        else
            echo "   WARNING: no input kinds left to generate"
        fi

        # Collect benign_poc inputs (vulnerable-build benign columns). Use a
        # numeric-suffix glob so benign_poc_agent_p*.bin (boundary inputs) are
        # NOT miscounted here — they get their own columns below.
        # Column labels come from the filename stem (Path B style), so
        # benign_poc0.bin -> column 'benign_poc0'. Same scheme is used by
        # provided-inputs (--benign/--benign-dir) below.
        mapfile -t _gen < <(dex 'ls -1 /output/benign_poc[0-9]*.bin 2>/dev/null | sort -V')
        for g in "${_gen[@]}"; do
            [ -n "$g" ] || continue
            _lbl="$(basename "$g")"; _lbl="${_lbl%.bin}"
            _lbl="$(printf '%s' "$_lbl" | tr -c 'A-Za-z0-9_.-' '_')"
            BENIGN_PATHS+=("$g"); BENIGN_LABELS+=("$_lbl")
        done
        # Collect benign_patch_poc inputs (patched-build reach columns).
        # benign_patch_poc0.bin -> column 'benign_patch_poc0'.
        mapfile -t _genp < <(dex 'ls -1 /output/benign_patch_poc*.bin 2>/dev/null | sort -V')
        for g in "${_genp[@]}"; do
            [ -n "$g" ] || continue
            _lbl="$(basename "$g")"; _lbl="${_lbl%.bin}"
            _lbl="$(printf '%s' "$_lbl" | tr -c 'A-Za-z0-9_.-' '_')"
            BENIGN_PATHS+=("$g"); BENIGN_LABELS+=("$_lbl")
        done
        # Collect boundary inputs (benign_poc_agent_p{N}) as their own columns.
        # benign_poc_agent_p0.bin -> column 'benign_poc_agent_p0'.
        mapfile -t _genb < <(dex 'ls -1 /output/benign_poc_agent_p*.bin 2>/dev/null | sort -V')
        for g in "${_genb[@]}"; do
            [ -n "$g" ] || continue
            _lbl="$(basename "$g")"; _lbl="${_lbl%.bin}"
            _lbl="$(printf '%s' "$_lbl" | tr -c 'A-Za-z0-9_.-' '_')"
            BENIGN_PATHS+=("$g"); BENIGN_LABELS+=("$_lbl")
        done
        if [ "${#BENIGN_PATHS[@]}" -gt 0 ]; then
            echo "   RT inputs: ${BENIGN_LABELS[*]}"
        else
            echo "   WARNING: no RT input could be generated; running PoC-only differential"
        fi
    else
        echo "   WARNING: oracle build missing /out/$TARGET_PROG; skipping RT-input generation"
    fi
fi

if [ "$GENERATE_PATCH_INPUTS_ONLY" -eq 1 ]; then
    echo "ERROR: independent patch-input generation could not run because the vulnerable oracle build is unavailable" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Build (reuse stash) + trace one variant against PoC and every benign input.
# ---------------------------------------------------------------------------
build_and_trace() {
    local name="$1" patch="$2"   # patch = "" for vuln, else basename in /proj
    echo ">> [$name] build (patch=${patch:-none})"
    build_variant_stash "$name" "$patch" || return 1
    dex "cp /tmp/bin_$name /out/$TARGET_PROG"
    # trace PoC
    dex "rm -f /output/traces/${name}_poc.log; DEEPDIFF_TRACE=/output/traces/${name}_poc.log timeout 25 /out/$TARGET_PROG /output/poc.bin >/dev/null 2>&1 || true"
    local pn; pn=$(dex "[ -s /output/traces/${name}_poc.log ] && wc -l < /output/traces/${name}_poc.log || echo 0")
    echo "   $name poc trace: ${pn} lines"
    # trace each benign
    local k=1
    for b in "${BENIGN_PATHS[@]}"; do
        dex "rm -f /output/traces/${name}_benign${k}.log; DEEPDIFF_TRACE=/output/traces/${name}_benign${k}.log timeout 25 /out/$TARGET_PROG $b >/dev/null 2>&1 || true"
        local bn; bn=$(dex "[ -s /output/traces/${name}_benign${k}.log ] && wc -l < /output/traces/${name}_benign${k}.log || echo 0")
        echo "   $name benign$k trace: ${bn} lines"
        k=$((k+1))
    done
    return 0
}

# ---------------------------------------------------------------------------
# Compare (address-normalized) — echoes EQUIVALENT / DIVERGENT / NO-DATA
# ---------------------------------------------------------------------------
verdict() {
    local a="/output/traces/$1" b="/output/traces/$2"
    dex "
        # Normalize addresses to a SINGLE token (both %p hex and %ld decimal
        # pointers -> ADDR) so the same pointer printed in either format matches,
        # then compare ORDER-INDEPENDENTLY (sort) so code-motion of an otherwise
        # identical write does not count as a difference. Real differences —
        # added/removed writes, changed values, changed write counts — are still
        # detected; only pure write-reordering is treated as equivalent.
        norm(){ sed -E 's/0x[0-9a-fA-F]+/ADDR/g; s/\(nil\)/ADDR/g; s/-?[0-9]{9,}/ADDR/g' \"\$1\" | sort; }
        if [ ! -s '$a' ] || [ ! -s '$b' ]; then echo NO-DATA; exit 0; fi
        if diff <(norm '$a') <(norm '$b') >/dev/null 2>&1; then echo EQUIVALENT; else echo DIVERGENT; fi
    "
}

# ---------------------------------------------------------------------------
# Per-input coverage of the instrumented target(s), computed from the trace of
# a GIVEN build ($3, e.g. vuln, p0, p1). Prints "<reached>/<nfuncs> <hit>/<tot>":
#   * reached   = number of target functions whose entry (">>> func") appears
#                 in this build's trace of the input.
#   * hit       = DISTINCT instrumented write sites the input exercised on this
#                 build.
#   * tot       = total instrumented write sites (DT(/DT_PTR() in THIS build's
#                 instrumented source) = the max coverage achievable on it.
# Computed per build because a patch can add/remove instrumented writes and can
# change which writes an input reaches (e.g. an added guard early-returns and
# suppresses downstream writes). FUNCS is comma-separated; "$1" is a trace
# basename under /output/traces; "$3" is the build name prefix.
coverage() {
    local log="/output/traces/$1" funcs="$2" build="$3"
    dex "
        L='$log'
        if [ ! -s \"\$L\" ]; then echo '0/0 0/0'; exit 0; fi
        hit=\$(grep -E '^[A-Za-z_][A-Za-z0-9_]*:.+ = ' \"\$L\" 2>/dev/null | sed -E 's/ = .*//' | sort -u | wc -l)
        tot=\$(cat /output/traces/instrumented_src/${build}_* 2>/dev/null | grep -oE 'DT_SCALW\(|DT_PTRW\(' | wc -l)
        nf=0; rf=0
        IFS=',' read -r -a _F <<< \"$funcs\"
        for f in \"\${_F[@]}\"; do
            [ -n \"\$f\" ] || continue
            case \"\$f\" in '(all'*) continue;; esac
            nf=\$((nf+1))
            grep -qE \"^>>> \$f\$|^>>> \$f[^A-Za-z0-9_]\" \"\$L\" 2>/dev/null && rf=\$((rf+1))
        done
        echo \"\$rf/\$nf \$hit/\$tot\"
    "
}

# ---------------------------------------------------------------------------
# PATCH-RELATIVE coverage: how many instrumented write sites AT/AFTER the lines
# changed by a patch were covered by an input. Answers "did this input actually
# exercise the patched region", not merely "enter the function".
#   $1 = build name (e.g. p0, p1)      -> selects instrumented_src/<build>_*
#   $2 = patch basename (e.g. patch_1.diff, in /proj)
#   $3 = trace basename (e.g. p1_poc.log)
# Prints "<hit>/<tot>" of post-change write sites, or "n/a" if the change anchor
# cannot be located (e.g. the vulnerable build, which lacks the added lines).
# Method: find the change anchor line in the (patched) instrumented source by
# matching an added ('+') code line; the post-change region runs from that line
# to the end of the enclosing function ('}' at column 0). Instrumented write
# sites there are DT("func","lhs",...) -> label "func:lhs"; an input covers a
# site if "func:lhs = " appears in its trace.
post_change_coverage() {
    local build="$1" patch="$2" tracelog="$3"
    dex "PATCH='/proj/$patch' SRCPFX='/output/traces/instrumented_src/${build}_' TRACE='/output/traces/$tracelog' FUNCS='$FUNCS' python3 - <<'PYEOF'
import os, re
patch = os.environ['PATCH']; pfx = os.environ['SRCPFX']; trace = os.environ['TRACE']
funcs = [f for f in os.environ.get('FUNCS', '').split(',') if f and not f.startswith('(all')]
def out(s):
    print(s); raise SystemExit
if not os.path.isfile(patch) or not os.path.isfile(trace):
    out('n/a')
ptxt = open(patch, errors='replace').read().splitlines()
bn = None
for l in ptxt:
    if l.startswith('+++ b/'):
        bn = os.path.basename(l[6:].strip()); break
if not bn:
    out('n/a')
src = pfx + bn
if not os.path.isfile(src):
    out('n/a')
srclines = open(src, errors='replace').read().splitlines()
# Target-function spans, located via the injected DT_ENTER(\"func\") marker
# (robust: it sits right after the function's opening brace). Restricting the
# anchor search to these spans avoids matching a common added statement (e.g.
# 'return SC_ERROR_CORRUPTED_DATA;') in an unrelated function.
def func_end(i):
    for j in range(i + 1, len(srclines)):
        if srclines[j].startswith('}'):
            return j
    return len(srclines) - 1
spans = []
for f in funcs:
    needle = 'DT_ENTER(\"%s\")' % f
    for i, s in enumerate(srclines):
        if needle in s:
            spans.append((i, func_end(i)))
if not spans:
    out('n/a')
# added code lines from the patch (skip +++, blanks, pure braces)
added = []
for l in ptxt:
    if l.startswith('+') and not l.startswith('+++'):
        t = l[1:].strip()
        if t and t not in ('{', '}', '};'):
            added.append(t)
# anchor = earliest added-line match WITHIN a target-function span
anchor = None; span_end = None
for (s0, s1) in spans:
    for t in added:
        for i in range(s0, s1 + 1):
            if t in srclines[i]:
                if anchor is None or i < anchor:
                    anchor = i; span_end = s1
                break
if anchor is None:
    out('n/a')
rx = re.compile(r'DT(?:_SCALW|_PTRW|_PTR)?\(\"([^\"]+)\",\s*\"([^\"]+)\"')
labels = []
for i in range(anchor, span_end + 1):
    m = rx.search(srclines[i])
    if m:
        labels.append(m.group(1) + ':' + m.group(2))
labels = sorted(set(labels))
tot = len(labels)
ttxt = open(trace, errors='replace').read()
hit = sum(1 for lab in labels if (lab + ' = ') in ttxt)
out(f'{hit}/{tot}')
PYEOF"
}

# ---------------------------------------------------------------------------
# Run vuln baseline + all candidates
# ---------------------------------------------------------------------------
build_and_trace vuln "" || { echo "vuln build failed, aborting"; exit 1; }
declare -a RUN_NAMES=()
for i in "${!CAND_NAMES[@]}"; do
    nm="${CAND_NAMES[$i]}"
    if build_and_trace "$nm" "${CAND_FILES[$i]}"; then RUN_NAMES+=("$nm"); fi
done

# ---------------------------------------------------------------------------
# Unit-test reachability analysis + optional matrix column (see unit_test_report).
# ---------------------------------------------------------------------------
if [ "$UNIT_TEST" -eq 1 ]; then
    unit_test_report
    [ "$UT_COL" -eq 1 ] && echo "   -> adding 'unit_test' column" || echo "   -> skipping 'unit_test' column"
fi

# ---------------------------------------------------------------------------
# Results matrix: rows = candidate patches, columns = PoC + each benign input.
# Every cell = patched-vs-vulnerable verdict for that input.
# ---------------------------------------------------------------------------
NB=${#BENIGN_PATHS[@]}
# If the container died before/at the matrix phase, all verdict/coverage dex
# calls would fail and emit repeated docker errors into the table. Detect it up
# front and abort cleanly instead of producing a corrupted matrix.
if ! container_running; then
    echo ""
    echo "ERROR: container '$CONTAINER' is not running — cannot compute the results matrix."
    echo "       The build container was killed mid-run. Common causes:"
    echo "         * OOM: too many concurrent heavy builds (each binutils build is large)."
    echo "         * A concurrent pipeline run using the SAME --container name force-removed it."
    echo "       Re-run this task alone (or with a unique --container NAME) to get a clean matrix."
    exit 1
fi
# Persist the full matrix + interpretation next to the traces/benign inputs so it
# can be inspected later (mirrors the console output via tee).
MATRIX_FILE="$DATA_DIR/matrix_result.txt"
# --merge-new-input: keep a copy of any pre-existing matrix so the freshly
# generated one (holding this run's input columns) can be merged INTO it below,
# adding the new input(s) as extra columns instead of discarding prior results.
PREV_MATRIX=""
if [ "$MERGE_NEW_INPUT" -eq 1 ] && [ -f "$MATRIX_FILE" ]; then
    PREV_MATRIX="$(mktemp)"
    cp "$MATRIX_FILE" "$PREV_MATRIX"
    echo ">> --merge-new-input: will merge this run's input(s) into existing $MATRIX_FILE"
fi
{
echo ""
echo "=================================================================="
echo "RESULTS MATRIX (patched-vs-vulnerable, per input, address-normalized)"
echo "  task_id: $TASK_ID   generated: $(date '+%Y-%m-%d %H:%M:%S')"
echo "=================================================================="

# header
printf "%-18s | %-12s" "patch" "PoC"
for k in $(seq 1 "$NB"); do printf " | %-14s" "${BENIGN_LABELS[$((k-1))]:-benign_poc$k}"; done
[ "$UT_COL" -eq 1 ] && printf " | %-14s" "unit_test"
printf "\n"
printf -- "-------------------+--------------"
for k in $(seq 1 "$NB"); do printf -- "+----------------"; done
[ "$UT_COL" -eq 1 ] && printf -- "+----------------"
printf "\n"

# rows
for i in "${!CAND_NAMES[@]}"; do
    nm="${CAND_NAMES[$i]}"
    # only render candidates that actually built
    skip=1; for r in "${RUN_NAMES[@]}"; do [ "$r" = "$nm" ] && skip=0; done
    label="$nm (${CAND_FILES[$i]})"
    if [ "$skip" -eq 1 ]; then
        printf "%-18s | %-12s" "$label" "BUILD-FAIL"
        for k in $(seq 1 "$NB"); do printf " | %-14s" "BUILD-FAIL"; done
        [ "$UT_COL" -eq 1 ] && printf " | %-14s" "BUILD-FAIL"
        printf "\n"
        continue
    fi
    pv=$(verdict "vuln_poc.log" "${nm}_poc.log")
    printf "%-18s | %-12s" "$label" "$pv"
    for k in $(seq 1 "$NB"); do
        bv=$(verdict "vuln_benign${k}.log" "${nm}_benign${k}.log")
        printf " | %-14s" "$bv"
    done
    if [ "$UT_COL" -eq 1 ]; then
        uv=$(verdict "vuln_unittest.log" "${nm}_unittest.log")
        printf " | %-14s" "$uv"
    fi
    printf "\n"
done

echo ""
echo "Interpretation (each cell = candidate patch vs vulnerable baseline):"
echo "  * PoC = DIVERGENT       -> patch changes crash-path behaviour (candidate fix)."
echo "  * benign_poc = EQUIVALENT -> patch preserves valid-input behaviour (no regression)."
echo "  * patch_poc columns come from benign_patch_poc inputs (non-crashing on BOTH"
echo "    builds, reaching the PATCHED code); treat like benign columns for regression."
echo "  * GOOD patch: DIVERGENT on PoC AND EQUIVALENT on every benign/patch_poc."
echo "  * BAD  patch: DIVERGENT on a benign/patch_poc input (breaks legitimate inputs)."
[ "$UT_COL" -eq 1 ] && echo "  * unit_test = vuln-vs-patched trace of the project's unit tests (make check);" \
    && echo "    EQUIVALENT means the developer regression suite behaves the same under the patch."

# ---------------------------------------------------------------------------
# Benign-input classification: VALID vs MALFORMED.  DISABLED (commented out).
# This classified each benign column relative to the REFERENCE correct patch p0
# (patch.diff): VALID if p0 was EQUIVALENT on it, MALFORMED if p0 DIVERGED. That
# relies on KNOWING which candidate is the correct fix, which violates the
# patch-blind assumption of this pipeline (we do NOT know the correct patch), so
# the table is not meaningful here and is disabled. A patch-blind replacement
# would derive validity from the input's structural well-formedness or a runtime
# bounds-invariant at the crash site (from crash.log), not from p0.
# if [ "$NB" -gt 0 ]; then
#     p0_built=0; for r in "${RUN_NAMES[@]}"; do [ "$r" = "p0" ] && p0_built=1; done
#     echo ""
#     echo "BENIGN INPUT CLASSIFICATION (valid vs malformed, per reference fix p0=patch.diff):"
#     if [ "$p0_built" -eq 0 ]; then
#         echo "  (reference patch p0 did not build — cannot classify)"
#     else
#         printf "  %-16s | %-10s | %-12s\n" "input" "class" "p0 verdict"
#         printf -- "  -----------------+------------+------------\n"
#         for k in $(seq 1 "$NB"); do
#             lbl="${BENIGN_LABELS[$((k-1))]:-benign_poc$k}"
#             v=$(verdict "vuln_benign${k}.log" "p0_benign${k}.log")
#             case "$v" in
#                 EQUIVALENT) cls="VALID" ;;
#                 DIVERGENT)  cls="MALFORMED" ;;
#                 *)          cls="UNKNOWN" ;;
#             esac
#             printf "  %-16s | %-10s | %-12s\n" "$lbl" "$cls" "$v"
#         done
#         echo "  VALID     -> use as a genuine regression probe (a GOOD patch must be"
#         echo "               EQUIVALENT here; DIVERGENT = real regression)."
#         echo "  MALFORMED -> still exercises the fixed path; a correct patch MAY diverge,"
#         echo "               so DIVERGENT here is NOT by itself evidence of a regression."
#     fi
# fi

# ---------------------------------------------------------------------------
# Per-input COVERAGE (confidence signal for the verdicts above), reported for
# EVERY build: the vulnerable baseline AND each candidate patch. For each build,
# each input's trace on THAT build is measured: how many target functions it
# reached and what fraction of that build's instrumented write sites it hit.
# Reporting per patch matters because a patch can change coverage (an added
# guard early-returns, suppressing downstream writes) and can add/remove
# instrumented sites, so the same input covers different amounts on each build.
# ---------------------------------------------------------------------------
cov_row() {
    local label="$1" tracelog="$2" build="$3" patchfile="$4"
    local out reached sites hit tot pct post
    out=$(coverage "$tracelog" "$FUNCS" "$build")
    reached=${out%% *}; sites=${out##* }
    hit=${sites%%/*}; tot=${sites##*/}
    if [ "${tot:-0}" -gt 0 ] 2>/dev/null; then
        pct=$(awk "BEGIN{printf \"%.0f\", ($hit/$tot)*100}")
    else
        pct="n/a"
    fi
    # Patch-relative coverage: writes AT/AFTER the changed lines. Only meaningful
    # for a candidate patch build (vuln has no added lines -> n/a).
    if [ -n "$patchfile" ]; then
        post=$(post_change_coverage "$build" "$patchfile" "$tracelog")
    else
        post="n/a"
    fi
    printf "  %-16s | %-10s | %-16s | %-8s | %-14s\n" "$label" "$reached" "$sites" "${pct}%" "$post"
}
cov_table() {
    local build="$1" title="$2" patchfile="$3"
    echo ""
    echo "PER-INPUT COVERAGE on ${title} build:"
    printf "  %-16s | %-10s | %-16s | %-8s | %-14s\n" "input" "reached" "writes covered" "cover%" "post-change"
    printf -- "  -----------------+------------+------------------+----------+---------------\n"
    cov_row "PoC" "${build}_poc.log" "$build" "$patchfile"
    for k in $(seq 1 "$NB"); do
        cov_row "${BENIGN_LABELS[$((k-1))]:-benign_poc$k}" "${build}_benign${k}.log" "$build" "$patchfile"
    done
}

echo ""
echo "Instrumented: files=${TFILES[*]} funcs=$FUNCS"
echo "Instrument mode: $INSTR_DESC"

echo ""
echo "=================================================================="
echo "PER-INPUT COVERAGE (per build; confidence for the verdicts above)"
echo "  reached        = target functions entered / total patched functions"
echo "  writes covered = distinct instrumented write sites hit / total sites"
echo "  post-change    = write sites AT/AFTER the patch's changed lines hit /"
echo "                   total such sites (did the input exercise the PATCHED"
echo "                   region, not just enter the function). n/a on vuln."
echo "=================================================================="
cov_table vuln "vulnerable (baseline)" ""
for i in "${!CAND_NAMES[@]}"; do
    nm="${CAND_NAMES[$i]}"
    skip=1; for r in "${RUN_NAMES[@]}"; do [ "$r" = "$nm" ] && skip=0; done
    [ "$skip" -eq 1 ] && continue
    cov_table "$nm" "$nm (${CAND_FILES[$i]})" "${CAND_FILES[$i]}"
done
} | tee "$MATRIX_FILE"

# --merge-new-input: fold the freshly generated matrix (this run's input columns)
# into the previously saved one, unioning input columns/rows and keeping prior
# verdicts. Merge is by column label, so re-running an existing input is a no-op
# while a genuinely new input is appended as a new column.
if [ "$MERGE_NEW_INPUT" -eq 1 ] && [ -n "$PREV_MATRIX" ] && [ -f "$PREV_MATRIX" ]; then
    if python3 "$SCRIPT_DIR/merge_matrix.py" --old "$PREV_MATRIX" --new "$MATRIX_FILE" --out "$MATRIX_FILE"; then
        echo "Matrix merged with previous results: $MATRIX_FILE"
    else
        echo "WARNING: merge_matrix.py failed; keeping this run's (unmerged) matrix" >&2
    fi
    rm -f "$PREV_MATRIX"
fi

echo "Matrix result saved: $MATRIX_FILE"
echo "Targets recorded: $DATA_DIR/traces/instrument_targets.txt (task-level)"
echo "Per-input targets: $DATA_DIR/<input>.instrument_targets.txt (one per benign/patch_poc)"
echo "Traces saved in container:/output/traces (host: $DATA_DIR/traces)"
echo "Instrumented C sources saved: $DATA_DIR/traces/instrumented_src/<variant>_<file>.c"
