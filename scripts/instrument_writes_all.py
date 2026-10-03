#!/usr/bin/env python3
"""Instrument C source (ALL-writes variant).

Unlike ``instrument_writes.py`` — which only instruments the patch-derived
TARGET_FUNCS — this script instruments the write-traces of **every** function
defined in each file, regardless of whether the patch/change touches it. Use it
when you want whole-file write coverage (e.g. to see side effects a change has
*outside* the patched function, or to build a baseline trace that does not
depend on which functions the patch happened to modify).

What is traced (identical, compile-safe policy to instrument_writes.py):
  * DT_ENTER on entry to every detected function definition.
  * DT / DT_PTR on scalar / pointer assignments that are safe to cast to
    ``long`` / ``void*``. Struct-type fields (path, label, ...), string
    assignments, and buffer calls (memcpy, strncpy, ...) are skipped because
    they cannot be cast to a scalar and would not compile.
  * DT_RET on simple identifier / small-int returns.

Function selection:
  * Default: ALL functions in the file.
  * Optional restriction via the ``DEEPDIFF_ONLY_FUNCS`` env var (comma-separated
    names). A DISTINCT name from ``DEEPDIFF_FUNCS`` is used on purpose so this
    script keeps instrumenting everything even when invoked from a pipeline that
    sets ``DEEPDIFF_FUNCS`` for the conservative script.

Usage:
    python3 instrument_writes_all.py file1.c [file2.c ...]
    DEEPDIFF_ONLY_FUNCS=foo,bar python3 instrument_writes_all.py file.c
"""
import re, sys, os

# Optional allow-list. Empty/unset => instrument ALL functions. Deliberately NOT
# DEEPDIFF_FUNCS so a pipeline that sets that (for the conservative script)
# doesn't accidentally restrict this all-writes variant.
_only = os.environ.get("DEEPDIFF_ONLY_FUNCS", "").strip()
ONLY_FUNCS = {f.strip() for f in _only.split(",") if f.strip()} if _only else None

TRACE_HEADER = '''
/* DeepDiff write-trace (all-writes) */
#ifndef DEEPDIFF_WRITE_TRACE_H
#define DEEPDIFF_WRITE_TRACE_H
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>   /* getenv */
static FILE *__dtfp = NULL;
static inline FILE* __dt_fp(void) {
    if (!__dtfp) {
        const char *p = getenv("DEEPDIFF_TRACE");
        if (p && p[0]) { __dtfp = fopen(p, "a"); if (__dtfp) setvbuf(__dtfp, NULL, _IOLBF, 0); }
        if (!__dtfp) __dtfp = stderr;
    }
    return __dtfp;
}
static inline void __dt_scal(const char *func, const char *lhs, long v) { fprintf(__dt_fp(), "%s:%s = %ld\\n", func, lhs, v); }
static inline void __dt_ptrv(const char *func, const char *lhs, const void *p) { fprintf(__dt_fp(), "%s:%s = %p\\n", func, lhs, p); }
static inline void __dt_skip(const char *func, const char *lhs) { (void)func; (void)lhs; }
/* __builtin_classify_type codes: integer=1,char=2,enum=3,bool=4,pointer=5 */
#define __DT_SCAL(x) (__builtin_classify_type(x) >= 1 && __builtin_classify_type(x) <= 4)
#define __DT_PTRT(x) (__builtin_classify_type(x) == 5)
/* DTW picks scalar/pointer/skip at COMPILE TIME. Unlike _Generic, the untaken
   __builtin_choose_expr branches are NOT type-checked, so passing a struct/array
   lvalue compiles to a harmless no-op instead of an "aggregate cast" error. The
   chosen branch evaluates x exactly once (classify_type does not evaluate). */
#define DTW(func, lhs, x) __builtin_choose_expr(__DT_SCAL(x), __dt_scal((func), (lhs), (long)__builtin_choose_expr(__DT_SCAL(x), (x), 0)), __builtin_choose_expr(__DT_PTRT(x), __dt_ptrv((func), (lhs), (const void*)__builtin_choose_expr(__DT_PTRT(x), (x), (void*)0)), __dt_skip((func), (lhs))))
#define DT_ENTER(func) fprintf(__dt_fp(), ">>> %s\\n", func)
#define DT_RET(func, r) fprintf(__dt_fp(), "<<< %s = %ld\\n", func, (long)(r))
#endif /* DEEPDIFF_WRITE_TRACE_H */
/* end DeepDiff */
'''

_CTRL_KEYWORDS = {'if', 'for', 'while', 'switch', 'return', 'sizeof', 'do',
                  'else', 'typedef'}


def _extract_def_name(head):
    """Given the text of a definition head (everything before the body ``{``),
    return the function name, or None if ``head`` is not a function definition.

    The function name is the identifier immediately preceding the parameter
    list's opening paren. Assignments/initializers (``x = ... {``) and control
    keywords are rejected."""
    idx = head.find('(')
    if idx < 0:
        return None
    before = head[:idx]
    # A definition head never assigns; `x = foo(` / `arr[] = {` are not defs.
    if '=' in before:
        return None
    ids = re.findall(r'[A-Za-z_]\w*', before)
    if not ids:
        return None
    name = ids[-1]
    if name in _CTRL_KEYWORDS:
        return None
    return name


def _is_braceless_control_header(s):
    """Deprecated: superseded by the paren-tracking state machine in instrument().
    Retained only for reference; no longer used."""
    return False


def _strip_comments(s):
    """Remove inline block comments and any trailing line comment from ``s``."""
    s = re.sub(r'/\*.*?\*/', ' ', s)
    s = re.sub(r'//.*$', '', s)
    return s.strip()


def _find_first_func_line(lines):
    """Return the source line index at which the first function definition
    begins (its return-type/signature start), or None if the file defines no
    functions. Mirrors the accumulator used in :func:`instrument`."""
    brace_depth = 0
    sig_start = None
    sig_parts = []
    for i, line in enumerate(lines):
        s = line.strip()
        if brace_depth == 0:
            if s == '' or s.startswith('#'):
                sig_parts = []
                sig_start = None
            elif s.startswith(('//', '/*', '*')):
                pass  # comment line: don't accumulate, don't reset a pending sig
            else:
                if not sig_parts:
                    sig_start = i
                sig_parts.append(s)
                joined = ' '.join(sig_parts)
                if '{' in s:
                    if _extract_def_name(joined.split('{', 1)[0]):
                        return sig_start
                    sig_parts = []
                    sig_start = None
                elif s.endswith(';') or s.endswith('}'):
                    sig_parts = []
                    sig_start = None
        for ch in s:
            if ch == '{':
                brace_depth += 1
            elif ch == '}':
                if brace_depth > 0:
                    brace_depth -= 1
    return None


def instrument(filepath):
    # latin-1 is byte-preserving (0x00-0xFF round-trip), so files with non-UTF-8
    # bytes (e.g. Latin-1 author names in comments) instrument correctly instead
    # of raising a UnicodeDecodeError.
    with open(filepath, encoding='latin-1') as f:
        lines = f.readlines()

    # Insert the trace header after the last TOP-LEVEL #include that precedes the
    # first function definition (so the DT_* macros are declared before use and
    # are not compiled out inside a #if block). If no function is defined there
    # is nothing to instrument.
    first_func_line = _find_first_func_line(lines)
    if first_func_line is None:
        with open(filepath, 'w', encoding='latin-1') as f:
            f.writelines(lines)
        return 0

    # Choose an insertion point for the trace header that is guaranteed to be at
    # conditional-nesting depth 0, so the DT_*/DTW macros are ALWAYS compiled in
    # (regardless of which #ifdef branches are active in a given build). Some
    # OpenSC files wrap their whole body — including every #include — in a single
    # `#ifdef ENABLE_OPENSSL`; placing the header inside that block would leave
    # functions after its #endif (or the whole file, when the macro is off) with
    # the macros undeclared. We therefore prefer the last DEPTH-0 #include, and
    # otherwise fall back to the last DEPTH-0 boundary line (a blank line or an
    # #endif) before the first function — never a point inside an #ifdef.
    last_inc0 = None       # last depth-0 #include before the first function
    last_boundary0 = 0     # last safe depth-0 line (blank / #endif) — top by default
    cond_depth = 0
    in_block_comment = False
    for i, line in enumerate(lines):
        if i >= first_func_line:
            break
        s = line.strip()
        # Track (crudely) whether we are inside a /* ... */ block so we never
        # anchor the header inside a comment.
        was_in_comment = in_block_comment
        if in_block_comment:
            if '*/' in s:
                in_block_comment = False
        elif s.count('/*') > s.count('*/'):
            in_block_comment = True
        if was_in_comment:
            continue
        if re.match(r'^#\s*(if|ifdef|ifndef)\b', s):
            cond_depth += 1
        elif re.match(r'^#\s*endif\b', s):
            if cond_depth > 0:
                cond_depth -= 1
            if cond_depth == 0:
                last_boundary0 = i + 1
        elif cond_depth == 0:
            if s.startswith('#include'):
                last_inc0 = i
            elif s == '':
                last_boundary0 = i + 1
    insert_at = (last_inc0 + 1) if last_inc0 is not None else last_boundary0
    lines.insert(insert_at, TRACE_HEADER + "\n")

    output = []
    current_func = None
    brace_depth = 0
    in_func = False
    func_brace_start = 0
    sig_parts = []          # accumulates a candidate signature at brace_depth 0
    in_hdr = False          # inside a multi-line control header condition (...)
    hdr_paren = 0           # unbalanced parens of an in-progress control header
    body_pending = False    # next statement is a braceless controlled body
    in_macro = False        # inside a multi-line #define ... \ continuation
    count = 0

    for line in lines:
        output.append(line)
        stripped = line.strip()

        # Skip everything inside a #define (including multi-line \-continued
        # macros). Functions defined via macros (e.g. `#define M(A) static T \\
        # getA(...) { ... }`) must not be instrumented: a DT_ENTER/DTW inserted
        # into the macro body drops the trailing backslash and mangles the macro.
        this_in_macro = in_macro or stripped.startswith('#define') or stripped.startswith('# define')
        in_macro = this_in_macro and stripped.endswith('\\')
        if this_in_macro:
            continue

        # Detect ANY function definition generically while at top level and not
        # already inside a function body.
        if not in_func and brace_depth == 0:
            if stripped == '' or stripped.startswith('#'):
                sig_parts = []
            elif stripped.startswith(('//', '/*', '*')):
                pass
            else:
                if not sig_parts:
                    sig_parts = []
                sig_parts.append(stripped)
                joined = ' '.join(sig_parts)
                if '{' in stripped:
                    name = _extract_def_name(joined.split('{', 1)[0])
                    if name and (ONLY_FUNCS is None or name in ONLY_FUNCS):
                        current_func = name
                    else:
                        current_func = None
                    sig_parts = []
                elif stripped.endswith(';') or stripped.endswith('}'):
                    sig_parts = []

        # Track braces (simplified: ignores braces inside strings/comments).
        entered_enter_idx = None   # output index of a DT_ENTER appended this line
        for ch in stripped:
            if ch == '{':
                brace_depth += 1
                if current_func and not in_func:
                    in_func = True
                    func_brace_start = brace_depth
                    output.append(f'    DT_ENTER("{current_func}");\n')
                    entered_enter_idx = len(output) - 1
                    in_hdr = False; hdr_paren = 0; body_pending = False
            elif ch == '}':
                brace_depth -= 1
                if in_func and brace_depth < func_brace_start:
                    in_func = False
                    # Single-line body: the function opened AND closed on this same
                    # line (e.g. `foo(void) { return 1; }`), so the DT_ENTER we just
                    # appended would sit AFTER the closing brace at file scope —
                    # invalid C. Drop it; there is nothing to instrument inside.
                    if entered_enter_idx is not None:
                        output.pop(entered_enter_idx)
                        entered_enter_idx = None
                    current_func = None

        if not in_func or not current_func:
            continue

        # Skip comments, preprocessor, control flow.
        if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
            continue
        if stripped.startswith('#'):
            continue

        # ------------------------------------------------------------------
        # Braceless-body tracking. A trace must NOT be inserted after the single
        # un-braced statement controlled by an if/else/for/while, because that
        # would detach a trailing `else`/loop (a compile error) or run the trace
        # unconditionally. We track control headers (including multi-line ones and
        # trailing comments) via paren balance and flag the statement that follows
        # as a braceless body to skip.
        # ------------------------------------------------------------------
        code_s = _strip_comments(stripped)
        if not code_s:
            continue
        net = code_s.count('(') - code_s.count(')')
        # A control header may be preceded by the closing brace of a previous
        # block on the same line (e.g. `} else if (...)`, `} else`, `} while(...)`);
        # strip a leading run of `}`/whitespace before matching keywords.
        ctrl_s = re.sub(r'^[}\s]+', '', code_s)

        this_is_braceless_body = False
        if in_hdr:
            # Still consuming a multi-line control-header condition.
            hdr_paren += net
            if hdr_paren <= 0:
                in_hdr = False
                hdr_paren = 0
                if code_s.endswith('{') or code_s.endswith(';'):
                    body_pending = False   # braced body, or body on this line
                else:
                    body_pending = True    # braceless body on following line(s)
            continue
        elif re.match(r'^(if|for|while|switch)\b', ctrl_s) or re.match(r'^else\s+if\b', ctrl_s):
            if net > 0:
                in_hdr = True              # header continues on next line(s)
                hdr_paren = net
            else:
                if code_s.endswith('{') or code_s.endswith(';'):
                    body_pending = False
                else:
                    body_pending = True
            continue
        elif re.match(r'^else\b', ctrl_s):
            # Bare `else` (body on next line), `else {` (braced), or an inline
            # `else STMT;` (controlled statement on this same line). Only a lone
            # `else` has its body on the following line; in every case the text
            # after `else` must NOT be parsed as a top-level assignment.
            body_pending = (ctrl_s == 'else')
            continue
        elif ctrl_s == 'do':
            body_pending = True
            continue
        else:
            # A normal statement. If it is the pending braceless body, consume the
            # flag and skip instrumenting it.
            if body_pending:
                this_is_braceless_body = True
            body_pending = False

        if re.match(r'^(goto|break|continue|case|default)\b', code_s):
            continue
        if not code_s.endswith(';'):
            continue

        if this_is_braceless_body:
            continue

        # Skip statement lines whose parentheses/brackets are unbalanced: these
        # are fragments of a MULTI-LINE statement (or span a macro), and emitting
        # a trace built from a fragment produces malformed / unbalanced DTW args
        # ("unterminated macro invocation").
        if code_s.count('(') != code_s.count(')') or code_s.count('[') != code_s.count(']'):
            continue

        # Handle return.
        if re.match(r'^return\b', code_s):
            ret_m = re.match(r'^return\s+([A-Z_]\w*)\s*;$', code_s)
            if ret_m:
                rval = ret_m.group(1)
                indent = line[:len(line) - len(line.lstrip())]
                output.insert(-1, f'{indent}DT_RET("{current_func}", ({rval}));\n')
            elif re.match(r'^return\s+(-?\d+|r|rv|ret|rc|len|count|result)\s*;$', code_s):
                rval = re.match(r'^return\s+(.+?)\s*;$', code_s).group(1)
                indent = line[:len(line) - len(line.lstrip())]
                output.insert(-1, f'{indent}DT_RET("{current_func}", ({rval}));\n')
            continue

        code = code_s

        # Find the '=' that is the assignment operator (not ==, !=, <=, >=, and
        # not inside a string/char literal).
        eq_pos = None
        i = 0
        while i < len(code):
            if code[i] == '"':
                i += 1
                while i < len(code) and code[i] != '"':
                    if code[i] == '\\': i += 1
                    i += 1
                i += 1
                continue
            if code[i] == '\'':
                i += 1
                while i < len(code) and code[i] != '\'':
                    if code[i] == '\\': i += 1
                    i += 1
                i += 1
                continue
            if code[i] == '=' and i > 0:
                prev = code[i-1]
                nxt = code[i+1] if i+1 < len(code) else ''
                if prev not in '!<>=' and nxt != '=':
                    eq_pos = i
                    break
            i += 1

        if eq_pos is None:
            continue

        lhs = code[:eq_pos].rstrip()
        rhs = code[eq_pos+1:].rstrip(';').strip()

        # Compound assignment (+=, -=, ...): strip the trailing operator off lhs.
        if lhs and lhs[-1] in '+-*/%&|^':
            lhs = lhs[:-1].rstrip()

        # Extract the variable name, stripping any leading type from a decl
        # (e.g. `sc_profile_t *profile`, `struct foo *bar`).
        var_name = lhs
        lhs_norm = re.sub(r'\s+', ' ', lhs).strip()
        decl_m = re.match(
            r'^(?:(?:const|static|unsigned|signed|volatile|struct|enum|register)\s+'
            r'|[A-Za-z_]\w*\s+)+\**\s*(\w+)$',
            lhs_norm
        )
        if decl_m:
            var_name = decl_m.group(1)

        # Never emit a type/declaration fragment as a value expression.
        if re.search(r'[\s*]', var_name) and '->' not in var_name and '.' not in var_name:
            continue

        # Skip LHS with a side effect we would otherwise re-execute in the trace
        # (DTW evaluates the lvalue once, but re-reading e.g. buf[i++] would still
        # advance i a second time relative to the original statement).
        if '++' in var_name or '--' in var_name or '++' in lhs or '--' in lhs:
            continue

        # Skip buffer/log calls mis-parsed as assignments (no scalar value).
        if re.match(r'^(strncpy|memcpy|memset|memmove|sc_log|snprintf)\s*\(', lhs) or \
           re.match(r'^(strncpy|memcpy|memset|memmove|sc_log|snprintf)\s*\(', code):
            continue

        # Only trace SIMPLE lvalues: identifiers, ptr->field, struct.field, and
        # array elements (possibly nested). Reject anything with unbalanced or
        # present parentheses, a ternary/comparison/logical operator, or a comma —
        # i.e. expression-like LHS (casts, ternaries, multi-line fragments) that
        # would emit malformed or misleading DTW arguments.
        if var_name.count('[') != var_name.count(']'):
            continue
        if '(' in var_name or ')' in var_name:
            continue
        if re.search(r'[?:;,]|==|<=|>=|!=|&&|\|\||<<|>>', var_name):
            continue

        indent = line[:len(line) - len(line.lstrip())]
        # DTW auto-selects scalar / pointer / skip at COMPILE TIME, so passing any
        # lvalue is safe: struct/array assignments compile to a no-op instead of
        # an aggregate-cast error. This is what lets us instrument ALL functions.
        trace = f'{indent}DTW("{current_func}", "{var_name}", ({var_name}));\n'
        output.append(trace)
        count += 1

    with open(filepath, 'w', encoding='latin-1') as f:
        f.writelines(output)
    return count


if __name__ == '__main__':
    total = 0
    for path in sys.argv[1:]:
        # Resilient: whole-program mode passes hundreds of files; one file that
        # trips the parser must not abort the rest. On failure we leave that file
        # untouched (instrument() only writes at the very end, so a mid-parse
        # exception cannot corrupt it) and continue.
        try:
            n = instrument(path)
            print(f"  Instrumented {path}: {n} trace points")
            total += n
        except Exception as e:  # noqa: BLE001 - best-effort across many files
            print(f"  SKIP {path}: instrumentation error: {e}", file=sys.stderr)
    scope = "ALL functions" if ONLY_FUNCS is None else f"functions={sorted(ONLY_FUNCS)}"
    print(f"  Total: {total} trace points ({scope})")
