#!/usr/bin/env python3
"""
gen_benign.py — Generate validated PoC-derived inputs of two kinds.

Runs INSIDE the task container. Starting from the ground-truth ``poc.bin`` it
mutates the input and validates each candidate, then writes a per-input
``instrument_targets.txt`` alongside every accepted input so downstream tooling
knows which files/functions (and thus which write-variables) to instrument when
replaying that specific input.

Two input KINDS can be generated (choose with ``--types``):

  * ``benign``  -> ``benign_poc{N}.bin``
      A non-crashing input that still REACHES the vulnerable function:
        1. CRASH gate    — must NOT trigger the vulnerability on the *vulnerable*
           build's crash oracle (``--run``; non-zero exit / timeout == crash,
           same oracle as validate.py stage 4).
        2. COVERAGE gate — must still reach the target: the instrumented
           *vulnerable* reference build (``--cover-run``) emits a non-empty
           DEEPDIFF_TRACE (optionally matching ``--cover-marker``).
        3. DISCRIMINATION gate (optional) — with ``--discriminate-run`` the
           input is accepted only if it makes at least one candidate build
           diverge from the reference (exposes relational-operator regressions).

  * ``patch``   -> ``benign_patch_poc{N}.bin``
      A benign input that additionally reaches the PATCHED code:
        1. CRASH gate (VULNERABLE build only) — must NOT trigger the
           vulnerability on the vulnerable oracle (``--run``). The patched
           build's crash behaviour is intentionally NOT checked.
        2. COVERAGE gate — must reach the patched function: the instrumented
           *patched* build (``--patch-cover-run``) emits a non-empty
           DEEPDIFF_TRACE (optionally matching ``--patch-cover-marker``).
      (Discrimination is not applied to patch inputs.)

Counts are per-kind: ``--count`` is the default for every selected kind, and
``--count-benign`` / ``--count-patch`` override it individually. ``--types all``
is shorthand for ``benign,patch``.

In addition to the two kinds above, ``--boundary`` (or ``--types boundary``)
generates BOUNDARY inputs ``benign_boundary_poc{N}.bin`` (0-based). Instead of
accepting the first non-crashing input (which sits well inside the safe region
and only exposes over-restrictive patches), it binary-searches the *decision
boundary* — the largest value of a length-like field that still does NOT crash
the vulnerable build and still reaches the target — then samples inputs at/near
that boundary (last-valid, last-valid-1, midpoint, small-valid). This is
PATCH-BLIND (only the vulnerable crash + coverage oracles are consulted) yet the
boundary-adjacent inputs are what expose off-by-one / under-restrictive patches
that plain benign inputs miss. Provide the field with ``--boundary-offset`` /
``--boundary-width`` / ``--boundary-endian`` when known, else offsets are
auto-discovered by sweeping.

Examples (in container):
    # benign only (default) — crash + coverage
    python3 /tmp/gen_benign.py --poc /output/poc.bin --out-dir /output \
        --count 3 --run "bash /src/run_poc.sh" --cover-run /tmp/bin_vuln \
        --instrument-files "src/card-coolkey.c" --instrument-funcs "coolkey_fill_object"

    # both kinds, different counts, with patched build/oracle
    python3 /tmp/gen_benign.py --poc /output/poc.bin --out-dir /output \
        --types all --count-benign 3 --count-patch 2 \
        --run "bash /src/run_poc_vuln.sh"  --cover-run /tmp/bin_vuln \
        --patch-run "bash /src/run_poc_patch.sh" --patch-cover-run /tmp/bin_p0 \
        --instrument-files "src/card-coolkey.c" --instrument-funcs "coolkey_fill_object" \
        --task-id opensc:arvo_18798
"""
import argparse
import json
import os
import random
import re
import shlex
import subprocess
import sys
import time


# ---------------------------------------------------------------------------
# Trace normalisation (must match deepdiff_pipeline.sh verdict() so decisions
# agree). Addresses are collapsed to a SINGLE token regardless of print format:
#   - hex pointers (%p)            -> ADDR
#   - "(nil)"                      -> ADDR
#   - long ints >=9 digits (%ld pointers) -> ADDR
# and lines are compared ORDER-INDEPENDENTLY (see normalize_lines) so code-motion
# of an otherwise-identical write is not treated as a difference.
# ---------------------------------------------------------------------------
_HEX = re.compile(r"0x[0-9a-fA-F]+")
_BIGINT = re.compile(r"-?[0-9]{9,}")


def normalize(text):
    text = _HEX.sub("ADDR", text)
    text = text.replace("(nil)", "ADDR")
    text = _BIGINT.sub("ADDR", text)
    return text


def normalize_key(text):
    """Order-independent, address-normalized form used to compare two traces.
    Returns the sorted tuple of normalized lines so that a difference in write
    ORDER (e.g. a code-moved assignment) does not register as a difference,
    while added/removed writes, changed values and changed counts still do."""
    return tuple(sorted(normalize(text).splitlines()))


def run_candidate(run_cmd, cand_path, timeout):
    """Crash oracle. Return (triggered: bool, reason: str).

    Non-zero exit or timeout == triggered (crashed like the PoC)."""
    argv = shlex.split(run_cmd) + [cand_path]
    try:
        res = subprocess.run(argv, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return True, "timeout"
    if res.returncode != 0:
        return True, f"exit={res.returncode}"
    return False, "exit=0"


def trace_of(run_cmd, cand_path, timeout):
    """Run an instrumented build on the candidate and return
    (crashed: bool, normalized_trace: str). Trace is "" if the target was not
    reached / no trace was produced."""
    trace_path = cand_path + ".trace.log"
    try:
        os.remove(trace_path)
    except OSError:
        pass
    env = dict(os.environ, DEEPDIFF_TRACE=trace_path)
    argv = shlex.split(run_cmd) + [cand_path]
    crashed = False
    try:
        res = subprocess.run(argv, capture_output=True, timeout=timeout, env=env)
        crashed = res.returncode != 0
    except subprocess.TimeoutExpired:
        crashed = True
    trace = ""
    if os.path.isfile(trace_path):
        try:
            trace = open(trace_path, "r", errors="replace").read()
        except OSError:
            trace = ""
        try:
            os.remove(trace_path)
        except OSError:
            pass
    return crashed, normalize(trace)


def mutate(poc, rng):
    """Produce a mutated copy of ``poc`` (bytes) using a random strategy.

    Strategies are generic (no per-task field knowledge). The first group
    *shrinks / neutralises* the trigger; the second group *grows the buffer*
    to create slack (len+hdr < buf_len) which is what exposes over-strict
    relational-operator patches.
    """
    b = bytearray(poc)
    n = len(b)
    if n == 0:
        return bytes(b)
    strat = rng.randint(0, 7)

    if strat == 0 and n > 2:
        # truncate to a shorter length
        b = b[: rng.randint(1, n - 1)]
    elif strat == 1:
        # zero a short contiguous region (often kills length/count fields)
        start = rng.randint(0, n - 1)
        end = min(n, start + rng.randint(1, 8))
        for i in range(start, end):
            b[i] = 0
    elif strat == 2 and n >= 2:
        # shrink a 2-byte region (LE and BE) to a small value
        pos = rng.randint(0, n - 2)
        small = rng.randint(0, 4)
        b[pos] = 0
        b[pos + 1] = small
    elif strat == 3:
        # random single/multi byte flips
        for _ in range(rng.randint(1, 6)):
            i = rng.randint(0, n - 1)
            b[i] = rng.randint(0, 255)
    elif strat == 4:
        # shrink every byte's high nibble (dampens large counts) on a slice
        start = rng.randint(0, n - 1)
        end = min(n, start + rng.randint(2, 12))
        for i in range(start, end):
            b[i] &= 0x0F
    elif strat == 5:
        # SLACK: append extra trailing bytes (grows the object/buf_len while
        # inner length fields stay small -> len+hdr < buf_len)
        extra = rng.randint(1, 32)
        b = b + bytearray(rng.randint(0, 255) for _ in range(extra))
    elif strat == 6 and n >= 2:
        # SLACK: shrink a 2-byte length-like field AND append tail bytes,
        # maximising the chance of buffer slack.
        pos = rng.randint(0, n - 2)
        b[pos] = 0
        b[pos + 1] = rng.randint(0, 6)
        extra = rng.randint(2, 24)
        b = b + bytearray(rng.randint(0, 255) for _ in range(extra))
    else:
        # SLACK: duplicate a slice in place (grows buffer, keeps structure)
        if n >= 4:
            s = rng.randint(0, n - 2)
            e = min(n, s + rng.randint(1, 16))
            b = b[:e] + b[s:e] + b[e:]
        else:
            b = b + bytearray(rng.randint(0, 255) for _ in range(rng.randint(1, 8)))
    return bytes(b)


def structured_candidates(poc):
    """Yield deterministic, minimal-edit candidates for length-prefixed formats.

    Random mutation usually escapes a length-driven overflow only by corrupting
    the input so badly that parsing bails *before* reaching the target function
    (i.e. non-crashing but NO-COVERAGE), so it rarely finds a benign input that
    still exercises the target. To reliably find one, we instead shrink a single
    2-byte length-like field to a small value while keeping every other byte of
    the PoC intact. Such a minimal edit preserves structure — so the input still
    reaches the target function — while defusing the overflow when the swept
    offset is the length field. Both big- and little-endian encodings are tried
    at every offset; zeroing ``b[i]`` also neutralises a 1-byte length at ``i``.

    This is generic (no per-task field knowledge): it simply sweeps offsets. If
    no single-field shrink yields a benign+covering input, generation falls back
    to the random ``mutate`` strategies.
    """
    n = len(poc)
    for i in range(n - 1):
        c = bytearray(poc); c[i] = 0x00; c[i + 1] = 0x04; yield bytes(c)  # big-endian -> 4
        c = bytearray(poc); c[i] = 0x04; c[i + 1] = 0x00; yield bytes(c)  # little-endian -> 4


# ---------------------------------------------------------------------------
# Boundary-input generation (patch-blind).
#
# The plain benign gate accepts the FIRST non-crashing+covered candidate, which
# for length-prefixed formats sits comfortably *inside* the safe region (e.g. a
# tiny length). Such an input only exposes over-restrictive patches: it cannot
# distinguish a correct bound (``> buf_len``) from an off-by-one/under-strict
# one (``>=``/``<``) because none of those relational variants disagree far from
# the true threshold.
#
# To expose those, we instead locate the DECISION BOUNDARY empirically — the
# largest value of a length-like field that still does NOT crash the vulnerable
# build (and still reaches the target) — via binary search, then emit inputs
# clustered right at that boundary (last-valid, last-valid-1, midpoint, a small
# valid value). This is done WITHOUT consulting any patch: the boundary is a
# property of the vulnerable program's crash oracle alone.
# ---------------------------------------------------------------------------
def set_field(poc, offset, width, endian, value):
    """Return a copy of ``poc`` with the ``width``-byte integer at ``offset`` set
    to ``value`` in the given endianness."""
    b = bytearray(poc)
    for k in range(width):
        shift = (width - 1 - k) * 8 if endian == "be" else k * 8
        b[offset + k] = (value >> shift) & 0xFF
    return bytes(b)


def field_value(poc, offset, width, endian):
    v = 0
    for k in range(width):
        shift = (width - 1 - k) * 8 if endian == "be" else k * 8
        v |= poc[offset + k] << shift
    return v


def crashes(cand, cand_path, oracles, timeout):
    """True if ``cand`` triggers the crash on ANY oracle build."""
    with open(cand_path, "wb") as f:
        f.write(cand)
    for _label, run_cmd in oracles:
        triggered, _reason = run_candidate(run_cmd, cand_path, timeout)
        if triggered:
            return True
    return False


def crash_verdict(cand, cand_path, oracles, timeout, retries=1):
    """Tri-state crash classification: ``'crash'``, ``'safe'`` or ``'unknown'``.

    Unlike :func:`crashes`, a TIMEOUT is reported as ``'unknown'`` instead of as a
    crash. A timeout usually means the machine was loaded, not that the input
    hangs the target, and scoring it as a crash silently corrupts any
    *classification* derived from it — e.g. the binary search in
    :func:`field_boundary`, which would then converge on a boundary that does not
    exist and make results vary with system load. Timeouts are retried up to
    ``retries`` extra times before giving up.

    Callers making a SAFETY decision ("may this input be emitted?") should keep
    using :func:`crashes`, where treating a timeout as a crash is the conservative
    and correct choice."""
    with open(cand_path, "wb") as f:
        f.write(cand)
    for _attempt in range(retries + 1):
        timed_out = False
        for _label, run_cmd in oracles:
            triggered, reason = run_candidate(run_cmd, cand_path, timeout)
            if triggered and reason == "timeout":
                timed_out = True
                continue
            if triggered:
                return "crash"
        if not timed_out:
            return "safe"
    return "unknown"


# Final safety net: re-validate an ALREADY-WRITTEN input exactly like
# validate_inputs.py does — run the (vulnerable) crash oracle(s) on the file on
# disk. If it crashes, the input is NOT benign and must be discarded, even though
# it passed the generation-time gate. This guards against any drift between the
# candidate check and the persisted file, and makes the benign guarantee explicit
# and self-contained. Controlled by --verify-benign / --no-verify-benign.
VERIFY_BENIGN = True


def written_input_triggers(path, oracles, timeout):
    """Run each oracle on the file at ``path`` (no rewrite). Returns
    (triggered: bool, reason: str) — True if ANY oracle crashes/timeouts."""
    for label, run_cmd in oracles:
        triggered, reason = run_candidate(run_cmd, path, timeout)
        if triggered:
            return True, f"{label} ({reason})"
    return False, ""


def discard_if_triggers(path, tgt_path, oracles, timeout, kind, attempt_desc):
    """If VERIFY_BENIGN and the written file at ``path`` crashes an oracle, delete
    it (and its instrument_targets) and return True (discarded). Else False."""
    if not VERIFY_BENIGN or not oracles:
        return False
    triggered, reason = written_input_triggers(path, oracles, timeout)
    if triggered:
        for p in (path, tgt_path):
            try:
                if p:
                    os.remove(p)
            except OSError:
                pass
        print(f"  [{kind}] {attempt_desc}: FINAL-VERIFY CRASH on {reason} "
              f"-> NOT benign, discarded {os.path.basename(path)}")
        return True
    return False


def marker_count(trace, cover_marker):
    """Number of trace lines matching ``cover_marker`` (the loop-carried marker).
    Used to require an input to iterate the target loop at least N times, so a
    single-iteration ("shallow") input cannot pass a deep-reach gate."""
    if not cover_marker:
        return 0
    return sum(1 for ln in trace.splitlines() if re.search(cover_marker, ln))


def covered(cand, cand_path, cover_run, cover_marker, timeout, cover_min_count=1):
    """True if ``cand`` reaches the target (non-empty trace, matching marker at
    least ``cover_min_count`` times)."""
    if not cover_run:
        return True
    with open(cand_path, "wb") as f:
        f.write(cand)
    _crashed, trace = trace_of(cover_run, cand_path, timeout)
    if not trace.strip():
        return False
    if cover_marker:
        if cover_min_count > 1:
            if marker_count(trace, cover_marker) < cover_min_count:
                return False
        elif not re.search(cover_marker, trace):
            return False
    return True


def field_boundary(poc, offset, width, endian, maxval, cand_path, oracles, timeout):
    """Classify how the field at ``offset`` gates the crash and locate the safe/
    crash decision boundary by binary search over [0, maxval].

    Returns a dict ``{mode, boundary, samples}`` or ``None`` if the field does not
    cleanly gate the crash (both endpoints crash, or neither does), or if any
    probe is UNCLASSIFIABLE (an oracle timeout that persisted across a retry).
    Bailing out on ``unknown`` is deliberate: guessing would converge the binary
    search on a boundary that does not exist, making results depend on machine
    load.

      mode='overflow'  : value 0 is SAFE, ``maxval`` CRASHES (larger => overflow).
                         ``boundary`` = largest non-crashing value; ``samples`` are
                         at/just-below it (the safe side).
      mode='underflow' : value 0 CRASHES, ``maxval`` is SAFE (smaller => underflow,
                         e.g. ``len < 2`` -> index underflow). ``boundary`` =
                         smallest non-crashing value; ``samples`` are at/just-above
                         it (the safe side).

    Being bidirectional is what lets boundary handle underflow bugs (where the
    PoC's trigger field is SMALL and the safe values are LARGER) as well as the
    classic overflow case.
    """
    v0 = crash_verdict(set_field(poc, offset, width, endian, 0),
                       cand_path, oracles, timeout)
    vM = crash_verdict(set_field(poc, offset, width, endian, maxval),
                       cand_path, oracles, timeout)
    if v0 == "unknown" or vM == "unknown":
        return None  # oracle could not classify an endpoint -> do not guess
    c0, cM = (v0 == "crash"), (vM == "crash")
    if c0 == cM:
        return None  # field does not flip crash behaviour across its range

    def probe(val):
        """True=crash, False=safe, None=unclassifiable."""
        v = crash_verdict(set_field(poc, offset, width, endian, val),
                          cand_path, oracles, timeout)
        return None if v == "unknown" else (v == "crash")

    if not c0 and cM:
        # overflow: safe at 0, crash at max -> largest safe value.
        lo, hi = 0, maxval           # invariant: lo safe, hi crash
        while hi - lo > 1:
            mid = (lo + hi) // 2
            hit = probe(mid)
            if hit is None:
                return None
            if hit:
                hi = mid
            else:
                lo = mid
        v = lo
        samples = [v, v - 1, v - 2, v // 2, min(4, maxval)]
        return {"mode": "overflow", "boundary": v, "samples": samples}
    else:
        # underflow: crash at 0, safe at max -> smallest safe value.
        lo, hi = 0, maxval           # invariant: lo crash, hi safe
        while hi - lo > 1:
            mid = (lo + hi) // 2
            hit = probe(mid)
            if hit is None:
                return None
            if hit:
                lo = mid
            else:
                hi = mid
        v = hi
        samples = [v, v + 1, v + 2, (v + maxval) // 2, maxval]
        return {"mode": "underflow", "boundary": v, "samples": samples}


def discover_length_offsets(poc, width, endian, maxval, cand_path, oracles,
                            cover_run, cover_marker, timeout, limit,
                            max_scan=0, discover_timeout=0, deadline=None):
    """Sweep offsets to auto-discover fields that GATE the crash in EITHER
    direction (overflow or underflow), with a safe-side value that still reaches
    the target. Returns up to ``limit`` qualifying ``(offset, field_boundary)``
    pairs.

    A field qualifies when :func:`field_boundary` finds a clean safe/crash split
    AND at least one boundary-adjacent SAFE sample is non-crashing + covered.
    Unlike the old overflow-only heuristic, fields whose PoC value is already
    small are NOT skipped (an underflow trigger field is small in the PoC).

    Coverage is probed across the whole safe-side sample set rather than only at
    the boundary value V: V is the value *closest to crashing*, so it frequently
    makes the target bail out early and produce no coverage, even when slightly
    deeper-valid samples do reach the target. Requiring V specifically to be
    covered discarded otherwise-usable fields.

    The computed :func:`field_boundary` result is returned with each offset so the
    caller can reuse it: re-deriving it costs another full binary search AND can
    disagree with this one when the crash oracle is not perfectly deterministic
    (which would drop an already-validated field).

    Parameters
    ----------
    max_scan : int
        Maximum number of byte offsets to probe before giving up (0 = no limit).
    discover_timeout : float
        Wall-clock seconds budget for this call only (0 = no limit). Ignored
        when ``deadline`` is provided.
    deadline : float | None
        Absolute ``time.monotonic()`` deadline shared across multiple calls.
        Takes precedence over ``discover_timeout`` when set. Use this from
        ``generate_boundary`` so that the budget is shared across all
        width×endian combinations rather than reset per call.
    """
    found   = []
    scanned = 0
    # Prefer a caller-supplied absolute deadline; fall back to per-call timeout.
    if deadline is None and discover_timeout > 0:
        deadline = time.monotonic() + discover_timeout

    for i in range(len(poc) - width + 1):
        # Hard scan-count limit.
        if max_scan > 0 and scanned >= max_scan:
            print(f"  [boundary] discover scan limit reached ({max_scan} offsets) -> stopping")
            break
        # Wall-clock timeout limit.
        if deadline is not None and time.monotonic() >= deadline:
            print(f"  [boundary] discover timeout reached ({discover_timeout}s) -> stopping")
            break
        scanned += 1
        fb = field_boundary(poc, i, width, endian, maxval, cand_path, oracles, timeout)
        if fb is None:
            continue
        # Confirm SOME safe-side sample actually reaches the target (coverage).
        safe_val = None
        for val in fb["samples"]:
            if val < 0 or val > maxval:
                continue
            cand = set_field(poc, i, width, endian, val)
            if crashes(cand, cand_path, oracles, timeout):
                continue
            if not covered(cand, cand_path, cover_run, cover_marker, timeout):
                continue
            safe_val = val
            break
        if safe_val is None:
            continue
        found.append((i, fb))
        print(f"  [boundary] discovered {fb['mode']} field at offset {i} ({endian}, "
              f"{width}B): boundary={fb['boundary']}, safe+covered at {safe_val} "
              f"(PoC field={field_value(poc, i, width, endian)})")
        if len(found) >= limit:
            break
    return found


def generate_boundary(poc, out_dir, oracles, cover_run, cover_marker, timeout,
                      offsets, widths, endians, maxval, count, task_id,
                      tgt_files, tgt_funcs, discover_limit,
                      discover_max_scan=0, discover_timeout=0):
    """Emit boundary-adjacent benign inputs ``benign_boundary_poc{N}.bin`` (0-based).

    For each (offset, width, endian) the decision boundary V = largest
    non-crashing field value is found by binary search; inputs are then sampled
    at V, V-1, a midpoint and a small value. Only candidates that are
    non-crashing AND covered are written. Returns a list of detail dicts.

    When ``offsets`` is empty the field is auto-discovered by sweeping every
    (width, endian) combination — so the caller needs NO knowledge of the input
    format. When ``offsets`` is given, only the first width is used per offset."""
    cand_path = os.path.join(out_dir, ".benign_poc_boundary_candidate.bin")
    prefix = "benign_boundary_poc"
    print(f"== generating boundary input(s) (prefix={prefix}, count<={count}) ==")

    def width_maxval(w):
        return maxval if maxval else (1 << (8 * w)) - 1

    targets = []  # (offset, width, endian, cached_field_boundary_or_None)
    if offsets:
        w = widths[0]
        for endian in endians:
            targets.extend((off, w, endian, None) for off in offsets)
    else:
        print(f"  [boundary] no offset given -> auto-discovering length field over "
              f"widths={widths} endians={endians} (no format knowledge needed) ...")
        # Compute ONE shared deadline for the entire discovery sweep so that the
        # budget is not reset for each width×endian combination.
        shared_deadline = (time.monotonic() + discover_timeout) if discover_timeout > 0 else None
        for w in widths:
            for endian in endians:
                if shared_deadline is not None and time.monotonic() >= shared_deadline:
                    print(f"  [boundary] global discover timeout reached -> stopping sweep")
                    break
                for off, fb in discover_length_offsets(poc, w, endian, width_maxval(w),
                                                       cand_path, oracles, cover_run,
                                                       cover_marker, timeout, discover_limit,
                                                       max_scan=discover_max_scan,
                                                       deadline=shared_deadline):
                    if not any(t[:3] == (off, w, endian) for t in targets):
                        targets.append((off, w, endian, fb))
            else:
                continue
            break

    if not targets:
        print("  [boundary] no length-like field found/given -> no boundary inputs")
        try:
            os.remove(cand_path)
        except OSError:
            pass
        return []

    accepted = []
    seen_vals = set()
    for offset, width, endian, cached_fb in targets:
        if len(accepted) >= count:
            break
        if offset < 0 or offset + width > len(poc):
            print(f"  [boundary] offset {offset} out of range for width {width} -> skip")
            continue
        mv = width_maxval(width)
        # Reuse the boundary already established during auto-discovery. Recomputing
        # it here would repeat a full binary search and, with a non-deterministic
        # crash oracle, can spuriously report "does not gate the crash" for a field
        # that discovery already validated as safe+covered.
        fb = cached_fb
        if fb is None:
            fb = field_boundary(poc, offset, width, endian, mv, cand_path, oracles, timeout)
        if fb is None:
            print(f"  [boundary] offset {offset} ({endian},{width}B): does not gate the "
                  f"crash (no safe/crash split) -> skip")
            continue
        v = fb["boundary"]; mode = fb["mode"]; samples = fb["samples"]
        orig = field_value(poc, offset, width, endian)
        print(f"  [boundary] offset {offset} ({endian},{width}B): {mode} boundary V={v} "
              f"(nearest safe value); PoC field={orig}")
        # Sample boundary-adjacent values on the SAFE side, most discriminating first.
        for val in samples:
            if len(accepted) >= count:
                break
            if val < 0 or val > mv:
                continue
            key = (offset, width, endian, val)
            if key in seen_vals:
                continue
            seen_vals.add(key)
            cand = set_field(poc, offset, width, endian, val)
            if cand == poc:
                continue
            if crashes(cand, cand_path, oracles, timeout):
                print(f"      value {val}: crashes -> skip")
                continue
            if not covered(cand, cand_path, cover_run, cover_marker, timeout):
                print(f"      value {val}: non-crashing but NO-COVERAGE -> skip")
                continue
            idx = len(accepted)
            out_path = os.path.join(out_dir, f"{prefix}{idx}.bin")
            with open(out_path, "wb") as f:
                f.write(cand)
            tgt_path = write_instrument_targets(out_path, task_id, "boundary",
                                                tgt_files, tgt_funcs)
            # Final validate_inputs-style verification on the persisted file.
            if discard_if_triggers(out_path, tgt_path, oracles, timeout, "boundary",
                                   f"value {val}"):
                continue
            # Role names the sample's position relative to the safe boundary V,
            # in the direction of the safe side (below V for overflow, above for
            # underflow).
            if val == v:
                role = "boundary(nearest-valid)"
            elif mode == "overflow" and val == v - 1:
                role = "boundary-1"
            elif mode == "overflow" and val == v - 2:
                role = "boundary-2"
            elif mode == "underflow" and val == v + 1:
                role = "boundary+1"
            elif mode == "underflow" and val == v + 2:
                role = "boundary+2"
            else:
                role = "deep-valid"
            accepted.append({"path": out_path, "size": len(cand), "kind": "boundary",
                             "offset": offset, "width": width, "endian": endian,
                             "mode": mode, "field_value": val, "boundary": v,
                             "role": role, "instrument_targets": tgt_path})
            print(f"      value {val} [{role}]: ACCEPTED +covered -> saved {out_path} "
                  f"({len(cand)} bytes)")

    try:
        os.remove(cand_path)
    except OSError:
        pass
    return accepted


def write_instrument_targets(bin_path, task_id, kind, files, funcs):
    """Write a per-input ``<input>.instrument_targets.txt`` next to ``bin_path``.

    Static content: the task-level, patch-derived instrumentation targets. The
    format matches the task-level file produced by deepdiff_pipeline.sh so the
    same parser (files=/funcs=) works for both."""
    tgt_path = os.path.splitext(bin_path)[0] + ".instrument_targets.txt"
    with open(tgt_path, "w") as f:
        f.write(f"# DeepDiff instrumentation targets for {task_id}\n")
        f.write(f"# input: {os.path.basename(bin_path)} (kind={kind})\n")
        f.write("# auto-derived from patch.diff (override with --files/--funcs)\n")
        f.write(f"files={files}\n")
        f.write(f"funcs={funcs}\n")
    return tgt_path


def generate_type(kind, out_prefix, count, poc, rng, out_dir, timeout,
                  oracles, cover_run, cover_marker, disc_runs, disc_mode,
                  task_id, tgt_files, tgt_funcs, max_attempts, do_structured=True,
                  cover_min_count=1):
    """Generate ``count`` accepted inputs of one KIND.

    Candidates are drawn first from a deterministic structured sweep
    (``structured_candidates`` — minimal single-field shrinks that keep coverage
    while defusing length-driven overflows), then from random ``mutate`` once the
    sweep is exhausted. Each candidate must pass:

    ``oracles``    : list of (label, run_cmd) crash oracles that must ALL report
                     non-triggered (crash gate).
    ``cover_run``  : instrumented build whose non-empty trace proves the input
                     reaches the target ("" disables the coverage gate).
    ``cover_min_count`` : minimum number of times the loop-carried ``cover_marker``
                     must appear in the coverage trace (>1 rejects "shallow"
                     single-iteration inputs that never exercise the loop path a
                     patch changes).
    ``disc_runs``  : optional candidate builds for the discrimination gate
                     (only meaningful for the benign kind); empty disables it.

    Returns (accepted-detail-dicts, attempts, fallbacks_used)."""
    do_cover = bool(cover_run)
    do_disc = bool(disc_runs)
    cand_path = os.path.join(out_dir, f".{out_prefix}_candidate.bin")

    def run_gates(cand):
        """Return ('accept', disc_hits) | ('fallback', None) | ('reject', reason)."""
        with open(cand_path, "wb") as f:
            f.write(cand)
        # Gate 1: must NOT trigger the crash on ANY oracle build.
        for label, run_cmd in oracles:
            triggered, reason = run_candidate(run_cmd, cand_path, timeout)
            if triggered:
                return ("reject", f"TRIGGERED on {label} ({reason})")
        # Gate 2: must reach the target (non-empty trace), and — if a marker is
        # given — the DEEP/loop region it identifies. When cover_min_count>1 the
        # marker must recur that many times, i.e. the input must iterate the
        # target loop at least that many times (not merely enter it once).
        ref_trace = None
        if do_cover:
            _crashed, ref_trace = trace_of(cover_run, cand_path, timeout)
            if not ref_trace.strip():
                return ("reject", "non-crashing but NO-COVERAGE of target")
            if cover_marker:
                if cover_min_count > 1:
                    mc = marker_count(ref_trace, cover_marker)
                    if mc < cover_min_count:
                        return ("reject", f"reached target but only {mc} loop "
                                f"iteration(s) < {cover_min_count} required "
                                f"(marker /{cover_marker}/)")
                elif not re.search(cover_marker, ref_trace):
                    return ("reject", f"reached function but marker /{cover_marker}/ absent")
        # Gate 3: must discriminate at least one candidate build (benign only).
        # Use the order-independent key so a candidate build only "discriminates"
        # when it truly differs (added/removed writes, changed values/counts) —
        # not merely because a write moved position (which the matrix verdict()
        # also treats as equivalent).
        if do_disc:
            ref_key = tuple(sorted(ref_trace.splitlines())) if ref_trace else ()
            hits = []
            for i, dr in enumerate(disc_runs):
                d_crashed, d_trace = trace_of(dr, cand_path, timeout)
                d_key = tuple(sorted(d_trace.splitlines()))
                if d_crashed or d_key != ref_key:
                    hits.append(os.path.basename(dr.split()[-1]) if dr.split() else f"run{i}")
            if not hits:
                return ("fallback", None)
            return ("accept", hits)
        return ("accept", None)

    def candidate_stream():
        if do_structured:
            for c in structured_candidates(poc):
                yield ("structured", c)
        while True:
            yield ("random", mutate(poc, rng))

    accepted = []
    fallbacks = []  # (bytes, size): non-crashing+covered but non-discriminating (prefer mode)
    tried = set()
    attempts = 0
    phase_desc = "structured sweep + random" if do_structured else "random"
    print(f"== generating up to {count} '{kind}' input(s) (prefix={out_prefix}, {phase_desc}) ==")
    for phase, cand in candidate_stream():
        if len(accepted) >= count or attempts >= max_attempts:
            break
        if not cand or cand == poc:
            continue
        h = hash(cand)
        if h in tried:
            continue
        tried.add(h)
        attempts += 1

        status, info = run_gates(cand)
        if status == "reject":
            print(f"  [{kind}] attempt {attempts} ({phase}): {info} -> discard, regenerate")
            continue
        if status == "fallback":
            if disc_mode == "prefer" and len(fallbacks) < count:
                fallbacks.append((cand, len(cand)))
                print(f"  [{kind}] attempt {attempts} ({phase}): non-crashing+covered "
                      f"NON-DISCRIMINATING -> stashed as fallback ({len(fallbacks)})")
            else:
                print(f"  [{kind}] attempt {attempts} ({phase}): non-crashing+covered but "
                      f"NON-DISCRIMINATING -> discard, regenerate")
            continue

        disc_hits = info
        idx = len(accepted) + 1
        out_path = os.path.join(out_dir, f"{out_prefix}{idx}.bin")
        with open(out_path, "wb") as f:
            f.write(cand)
        tgt_path = write_instrument_targets(out_path, task_id, kind, tgt_files, tgt_funcs)
        # Final validate_inputs-style verification: the persisted file must NOT
        # crash the vulnerable oracle. If it does, it is a false benign -> discard.
        if discard_if_triggers(out_path, tgt_path, oracles, timeout, kind,
                               f"attempt {attempts} ({phase})"):
            continue
        extra = ""
        if do_cover:
            extra += " +covered"
        if do_disc:
            extra += f" +discriminates[{','.join(disc_hits)}]"
        accepted.append({"path": out_path, "size": len(cand), "kind": kind,
                         "instrument_targets": tgt_path,
                         "discriminates": disc_hits if do_disc else None})
        print(f"  [{kind}] attempt {attempts} ({phase}): ACCEPTED{extra} -> saved {out_path} "
              f"({len(cand)} bytes), targets -> {os.path.basename(tgt_path)}")

    # In 'prefer' mode, top up remaining slots with non-discriminating fallbacks.
    used_fallback = 0
    if do_disc and disc_mode == "prefer" and len(accepted) < count:
        for cand, size in fallbacks:
            if len(accepted) >= count:
                break
            idx = len(accepted) + 1
            out_path = os.path.join(out_dir, f"{out_prefix}{idx}.bin")
            with open(out_path, "wb") as f:
                f.write(cand)
            tgt_path = write_instrument_targets(out_path, task_id, kind, tgt_files, tgt_funcs)
            if discard_if_triggers(out_path, tgt_path, oracles, timeout, kind, "FALLBACK"):
                continue
            accepted.append({"path": out_path, "size": size, "kind": kind,
                             "instrument_targets": tgt_path, "discriminates": []})
            used_fallback += 1
            print(f"  [{kind}] FALLBACK: saved {out_path} ({size} bytes) "
                  f"[non-discriminating], targets -> {os.path.basename(tgt_path)}")
        if used_fallback:
            print(f"  [{kind}] NOTE: {used_fallback} input(s) are non-discriminating "
                  f"fallbacks — no discriminating input found in {attempts} attempts.")

    try:
        os.remove(cand_path)
    except OSError:
        pass
    return accepted, attempts, used_fallback


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--poc", default="/output/poc.bin", help="Ground-truth PoC path")
    ap.add_argument("--out-dir", default="/output",
                    help="Where generated *.bin and *.instrument_targets.txt are written")

    # --- which kinds / how many -------------------------------------------
    ap.add_argument("--types", default="benign",
                    help="Comma-separated kinds to generate: 'benign', 'patch', or 'all' "
                         "(= benign,patch). Default: benign.")
    ap.add_argument("--count", type=int, default=3,
                    help="Default per-kind count (used when a kind has no explicit count)")
    ap.add_argument("--count-benign", type=int, default=-1,
                    help="Override count for benign_poc inputs (default: --count)")
    ap.add_argument("--count-patch", type=int, default=-1,
                    help="Override count for benign_patch_poc inputs (default: --count)")
    ap.add_argument("--patch-prefix", default="benign_patch_poc",
                    help="Output prefix for patch inputs (default: benign_patch_poc). "
                         "Useful when generating separate inputs for multiple patched builds.")

    # --- benign (vulnerable-build) gates ----------------------------------
    ap.add_argument("--run", default="bash /src/run_poc.sh",
                    help="Vulnerable-build crash oracle; candidate path appended as last arg")
    ap.add_argument("--cover-run", default="",
                    help="Instrumented VULNERABLE build. A benign input is only accepted if "
                         "it reaches the target (non-empty DEEPDIFF_TRACE). Also the "
                         "discrimination baseline. Candidate path appended.")
    ap.add_argument("--cover-marker", default="",
                    help="Optional regex the vulnerable-reference trace MUST contain for the "
                         "input to count as reaching the deep target (empty = any non-empty).")
    ap.add_argument("--cover-min-count", type=int, default=1,
                    help="Minimum number of times --cover-marker must appear in the coverage "
                         "trace (default 1). Set >1 to require the input to iterate the target "
                         "loop at least that many times, rejecting 'shallow' single-iteration "
                         "inputs that never exercise the multi-iteration path a patch changes. "
                         "Applies to benign and patch inputs.")
    ap.add_argument("--discriminate-run", default="",
                    help="Comma-separated instrumented candidate builds (mutant patches). If "
                         "set, a benign input is accepted only if it makes at least one diverge "
                         "from --cover-run. Candidate path appended to each. (benign kind only)")
    ap.add_argument("--discriminate-mode", choices=["require", "prefer"], default="prefer",
                    help="'require': only accept discriminating benign inputs. 'prefer' "
                         "(default): fall back to non-discriminating benign+covered inputs.")

    # --- patch (patched-build) gates --------------------------------------
    ap.add_argument("--patch-run", default="",
                    help="DEPRECATED / IGNORED: patched-build crash oracle. Gate 1 now checks "
                         "only the vulnerable oracle (--run); this flag is accepted for "
                         "backward compatibility but no longer affects patch input generation.")
    ap.add_argument("--patch-cover-run", default="",
                    help="Instrumented PATCHED build. A benign_patch_poc input is only accepted "
                         "if it reaches the patched code (non-empty DEEPDIFF_TRACE).")
    ap.add_argument("--patch-cover-marker", default="",
                    help="Optional regex the patched-reference trace MUST contain (empty = any "
                         "non-empty trace).")

    # --- instrument_targets.txt content -----------------------------------
    ap.add_argument("--task-id", default="unknown",
                    help="Task id recorded in each per-input instrument_targets.txt header")
    ap.add_argument("--instrument-files", default="",
                    help="Space/comma-separated target files recorded (files=...) for every "
                         "input's instrument_targets.txt")
    ap.add_argument("--instrument-funcs", default="",
                    help="Comma-separated target functions recorded (funcs=...) for every "
                         "input's instrument_targets.txt")
    ap.add_argument("--patch-instrument-files", default="",
                    help="Override instrument files for patch inputs (default: --instrument-files)")
    ap.add_argument("--patch-instrument-funcs", default="",
                    help="Override instrument funcs for patch inputs (default: --instrument-funcs)")

    ap.add_argument("--max-attempts", type=int, default=2000,
                    help="Max candidate attempts PER KIND before giving up "
                         "(default: 2000)")
    ap.add_argument("--no-structured", action="store_true",
                    help="Disable the deterministic structured length-field sweep and use "
                         "only random mutation (not recommended for length-prefixed formats)")

    # --- boundary inputs (patch-blind divergence-capturing) ----------------
    ap.add_argument("--boundary", action="store_true",
                    help="Also generate boundary-adjacent inputs 'benign_boundary_poc{N}.bin'. "
                         "Binary-searches the largest non-crashing value of a length-like field "
                         "on the VULNERABLE build (crash + coverage gates only — no patch "
                         "consulted) and samples inputs at/near that decision boundary. These "
                         "expose off-by-one / under-restrictive patches that inside-the-safe-"
                         "region benign inputs miss.")
    ap.add_argument("--boundary-offset", default="",
                    help="Comma-separated byte offset(s) of the length-like field to sweep. "
                         "Empty -> AUTO-DISCOVER the field (no format knowledge needed): the "
                         "tool sweeps offsets x widths x endianness and picks fields where a "
                         "small value is safe+covered but a large value crashes.")
    ap.add_argument("--boundary-width", default="",
                    help="Comma-separated field width(s) in bytes. Empty -> 2 when an offset is "
                         "given, or auto-sweep {2,4,1} when auto-discovering.")
    ap.add_argument("--boundary-endian", default="",
                    help="Field endianness: 'be', 'le', or 'both'. Empty -> 'be' when an offset "
                         "is given, or 'both' when auto-discovering.")
    ap.add_argument("--boundary-count", type=int, default=4,
                    help="Max number of boundary inputs to emit (default: 4)")
    ap.add_argument("--boundary-maxval", type=int, default=0,
                    help="Max field value to consider (default: 0 -> (1<<(8*width))-1)")
    ap.add_argument("--boundary-discover-limit", type=int, default=2,
                    help="When auto-discovering offsets, stop after this many qualifying "
                         "offsets per endianness (default: 2)")
    ap.add_argument("--boundary-discover-max-scan", type=int, default=512,
                    help="Max number of byte offsets to probe during auto-discovery "
                         "before giving up (default: 512, 0 = no limit). "
                         "Prevents infinite sweeps on large/complex binary formats.")
    ap.add_argument("--boundary-discover-timeout", type=float, default=600.0,
                    help="Wall-clock seconds budget for the entire boundary "
                         "auto-discovery sweep (default: 600, 0 = no limit). "
                         "Discovery is aborted and the boundary step is skipped "
                         "if this deadline is reached.")

    ap.add_argument("--timeout", type=int, default=60, help="Seconds per candidate run")
    ap.add_argument("--seed", type=int, default=1337, help="RNG seed for reproducibility")
    ap.add_argument("--verify-benign", dest="verify_benign", action="store_true", default=True,
                    help="After writing each accepted input, re-run the vulnerable crash "
                         "oracle on the PERSISTED file (validate_inputs-style); discard it if "
                         "it crashes (false benign). Default: on.")
    ap.add_argument("--no-verify-benign", dest="verify_benign", action="store_false",
                    help="Disable the final on-disk crash re-verification of accepted inputs.")
    ap.add_argument("--force-generation", action="store_true", default=False,
                    help="Re-generate inputs even if files of that type already exist in "
                         "--out-dir. Without this flag, any kind (benign/patch/boundary) "
                         "whose output files are already present is skipped silently.")
    args = ap.parse_args()

    global VERIFY_BENIGN
    VERIFY_BENIGN = args.verify_benign

    # Resolve requested kinds.
    raw = [t.strip().lower() for t in args.types.split(",") if t.strip()]
    kinds = []
    want_boundary = args.boundary
    for t in raw:
        if t == "all":
            kinds = ["benign", "patch"]
            break
        if t == "boundary":
            want_boundary = True
            continue
        if t in ("benign", "patch"):
            if t not in kinds:
                kinds.append(t)
        else:
            print(f"ERROR: unknown --types value '{t}' (use benign, patch, boundary, or all)",
                  file=sys.stderr)
            sys.exit(2)
    # 'boundary' may be requested on its own (via --boundary or --types boundary),
    # in which case no benign/patch kinds are required.
    if not kinds and not want_boundary:
        print("ERROR: no valid kinds selected via --types", file=sys.stderr)
        sys.exit(2)

    if not os.path.isfile(args.poc):
        print(f"ERROR: poc not found: {args.poc}", file=sys.stderr)
        sys.exit(2)
    poc = open(args.poc, "rb").read()
    rng = random.Random(args.seed)

    disc_runs = [c.strip() for c in args.discriminate_run.split(",") if c.strip()]
    if disc_runs and not args.cover_run:
        print("ERROR: --discriminate-run requires --cover-run (the reference build)",
              file=sys.stderr)
        sys.exit(2)
    if "patch" in kinds and not args.patch_cover_run:
        print("ERROR: --types includes 'patch' but --patch-cover-run (instrumented patched "
              "build) was not provided", file=sys.stderr)
        sys.exit(2)
    if "patch" in kinds and args.patch_run:
        print("NOTE: --patch-run is ignored; patch inputs are validated as non-crashing on "
              "the VULNERABLE oracle only, then required to reach the patched code.")

    # Oracle sanity: confirm the PoC actually triggers under the vulnerable build.
    poc_triggered, poc_reason = run_candidate(args.run, args.poc, args.timeout)
    print(f"[oracle] poc.bin triggered={poc_triggered} ({poc_reason})")
    if not poc_triggered:
        print("[oracle] WARNING: poc.bin did NOT trigger a crash under this build; "
              "validation cannot distinguish triggering inputs. Continuing anyway.")

    # Per-kind configuration.
    p_ifiles = args.patch_instrument_files or args.instrument_files
    p_ifuncs = args.patch_instrument_funcs or args.instrument_funcs
    plans = {
        "benign": {
            "prefix": "benign_poc",
            "count": args.count_benign if args.count_benign >= 0 else args.count,
            "oracles": [("vuln", args.run)],
            "cover_run": args.cover_run,
            "cover_marker": args.cover_marker,
            "cover_min_count": args.cover_min_count,
            "disc_runs": disc_runs,
            "ifiles": args.instrument_files,
            "ifuncs": args.instrument_funcs,
        },
        "patch": {
            "prefix": args.patch_prefix,
            "count": args.count_patch if args.count_patch >= 0 else args.count,
            # Gate 1 checks the VULNERABLE oracle only: the input must not trigger
            # the vulnerability on the vulnerable build. We intentionally do NOT
            # require non-crash on the patched build — the patch kind is defined by
            # reaching the PATCHED code (Gate 2 on --patch-cover-run), not by the
            # patched build's crash behaviour.
            "oracles": [("vuln", args.run)],
            "cover_run": args.patch_cover_run,
            "cover_marker": args.patch_cover_marker,
            "cover_min_count": args.cover_min_count,
            "disc_runs": [],  # discrimination not applied to patch inputs
            "ifiles": p_ifiles,
            "ifuncs": p_ifuncs,
        },
    }

    all_details = []
    per_kind = {}
    overall_success = True

    def _existing_inputs(prefix, out_dir):
        """Return sorted list of already-generated *.bin files for ``prefix``."""
        import glob as _glob
        return sorted(_glob.glob(os.path.join(out_dir, f"{prefix}*.bin")))

    for kind in kinds:
        cfg = plans[kind]
        if cfg["count"] <= 0:
            print(f"== skipping kind '{kind}' (count=0) ==")
            continue
        existing = _existing_inputs(cfg["prefix"], args.out_dir)
        if existing and not args.force_generation:
            print(f"== skipping kind '{kind}' — {len(existing)} file(s) already exist "
                  f"(use --force-generation to regenerate) ==")
            for p in existing:
                print(f"   {os.path.basename(p)}")
            per_kind[kind] = {
                "requested": cfg["count"],
                "generated": existing,
                "attempts":  0,
                "fallbacks_used": 0,
                "success":   True,
                "skipped":   True,
            }
            all_details.extend({"path": p, "skipped": True} for p in existing)
            continue
        cfg = plans[kind]
        if cfg["count"] <= 0:
            print(f"== skipping kind '{kind}' (count=0) ==")
            continue
        max_attempts = args.max_attempts
        details, attempts, used_fb = generate_type(
            kind, cfg["prefix"], cfg["count"], poc, rng, args.out_dir, args.timeout,
            cfg["oracles"], cfg["cover_run"], cfg["cover_marker"],
            cfg["disc_runs"], args.discriminate_mode, args.task_id,
            cfg["ifiles"], cfg["ifuncs"], max_attempts, not args.no_structured,
            cfg["cover_min_count"])
        all_details.extend(details)
        per_kind[kind] = {
            "requested": cfg["count"],
            "generated": [d["path"] for d in details],
            "attempts": attempts,
            "fallbacks_used": used_fb,
            "success": len(details) == cfg["count"],
        }
        if len(details) != cfg["count"]:
            overall_success = False

    # Boundary inputs (patch-blind, divergence-capturing).
    boundary_details = []
    if want_boundary:
        boundary_prefix = "benign_boundary_poc"
        existing_boundary = _existing_inputs(boundary_prefix, args.out_dir)
        if existing_boundary and not args.force_generation:
            print(f"== skipping boundary — {len(existing_boundary)} file(s) already exist "
                  f"(use --force-generation to regenerate) ==")
            for p in existing_boundary:
                print(f"   {os.path.basename(p)}")
            boundary_details = [{"path": p, "skipped": True} for p in existing_boundary]
            per_kind["boundary"] = {
                "requested": args.boundary_count,
                "generated": existing_boundary,
                "success":   True,
                "skipped":   True,
            }
        else:
            if not args.cover_run:
                print("== boundary: WARNING — no --cover-run given; coverage gate disabled, "
                      "boundary inputs may not reach the target ==")
            maxval = args.boundary_maxval
            offsets = [int(x.strip(), 0) for x in args.boundary_offset.split(",") if x.strip()]
            if args.boundary_width.strip():
                widths = [int(x.strip(), 0) for x in args.boundary_width.split(",") if x.strip()]
            else:
                widths = [2] if offsets else [2, 4, 1]
            if args.boundary_endian.strip():
                endians = (["be", "le"] if args.boundary_endian.strip() == "both"
                           else [args.boundary_endian.strip()])
            else:
                endians = ["be"] if offsets else ["be", "le"]
            boundary_details = generate_boundary(
                poc, args.out_dir, [("vuln", args.run)], args.cover_run, args.cover_marker,
                args.timeout, offsets, widths, endians, maxval,
                args.boundary_count, args.task_id, args.instrument_files,
                args.instrument_funcs, args.boundary_discover_limit,
                discover_max_scan=args.boundary_discover_max_scan,
                discover_timeout=args.boundary_discover_timeout)
            all_details.extend(boundary_details)
            per_kind["boundary"] = {
                "requested": args.boundary_count,
                "generated": [d["path"] for d in boundary_details],
                "success": len(boundary_details) > 0,
            }
            if not boundary_details:
                overall_success = False

    summary = {
        "poc": args.poc,
        "poc_triggered": poc_triggered,
        "types": kinds,
        "per_kind": per_kind,
        "generated": [d["path"] for d in all_details],
        "details": all_details,
        "success": overall_success,
    }
    print("SUMMARY: " + json.dumps(summary))
    if not all_details:
        print("ERROR: could not generate any input meeting the requested gates",
              file=sys.stderr)
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
