#!/usr/bin/env python3
"""Instrument C source v4: Conservative — only traces clearly scalar/pointer assignments.

Target functions default to the coolkey crash chain, but can be overridden by
setting the DEEPDIFF_FUNCS environment variable to a comma-separated list.
"""
import re, sys, os

TARGET_FUNCS = [
    "coolkey_v0_get_attribute_data",
    "coolkey_v0_get_attribute_len",
    "coolkey_get_attribute_bytes",
    "coolkey_get_attribute",
    "coolkey_find_attribute",
    "coolkey_fill_object",
    "sc_pkcs15emu_coolkey_init",
]

_env_funcs = os.environ.get("DEEPDIFF_FUNCS", "").strip()
if _env_funcs:
    TARGET_FUNCS = [f.strip() for f in _env_funcs.split(",") if f.strip()]

TRACE_HEADER = '''
/* DeepDiff write-trace */
#ifndef DEEPDIFF_WRITE_TRACE_H
#define DEEPDIFF_WRITE_TRACE_H
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>   /* getenv */
/* Some projects (e.g. ghostscript) poison libc calls via macros like
   `#define fopen DO_NOT_USE_FOPEN` to force their sandboxed I/O API. This
   header is inserted AFTER the project includes, so #undef restores the real
   libc symbols just for the trace helper below. */
#undef fopen
static FILE *__dtfp = NULL;
static inline FILE* __dt_fp(void) {
    if (!__dtfp) {
        const char *p = getenv("DEEPDIFF_TRACE");
        if (p && p[0]) { __dtfp = fopen(p, "a"); if (__dtfp) setvbuf(__dtfp, NULL, _IOLBF, 0); }
        /* Fallback via /dev/stderr rather than the `stderr` identifier: some
           projects (e.g. ghostscript) #define stderr to a banned symbol
           (gs_stderr) that is undeclared in most translation units. */
        if (!__dtfp) __dtfp = fopen("/dev/stderr", "a");
        if (!__dtfp) __dtfp = fopen("/dev/null", "a");
    }
    return __dtfp;
}
#define DT(func, lhs, fmt, ...) fprintf(__dt_fp(), "%s:" lhs " = " fmt "\\n", func, ##__VA_ARGS__)
#define DT_PTR(func, lhs, val) fprintf(__dt_fp(), "%s:" lhs " = %p\\n", func, (void*)(uintptr_t)(val))
#define DT_ENTER(func) fprintf(__dt_fp(), ">>> %s\\n", func)
#define DT_RET(func, r) fprintf(__dt_fp(), "<<< %s = %ld\\n", func, (long)(r))
static inline void __dt_scal(const char *func, const char *lhs, long v) { fprintf(__dt_fp(), "%s:%s = %ld\\n", func, lhs, v); }
static inline void __dt_ptrv(const char *func, const char *lhs, const void *p) { fprintf(__dt_fp(), "%s:%s = %p\\n", func, lhs, p); }
static inline void __dt_skip(const char *func, const char *lhs) { (void)func; (void)lhs; }
/* __builtin_classify_type aggregate codes: record(struct)=12, union=13. A whole
   struct/union value can't be cast to long/uintptr_t, so a write copying one
   (e.g. `ipsp->cs_data = *pgd;`) would break the build. __DT_AGG detects it. */
#define __DT_AGG(x) (__builtin_classify_type(x) == 12 || __builtin_classify_type(x) == 13)
/* DT_SCALW / DT_PTRW behave EXACTLY like the DT scalar / DT_PTR forms for every
   non-aggregate value (same "%ld" / "%p" output, same cast), and compile-time
   skip (emit nothing) only for struct/union values. Because __builtin_choose_expr
   does not type-check the untaken branch, the aggregate case compiles to a no-op
   instead of an invalid cast. This is result-preserving: for scalars/pointers the
   emitted line is byte-identical to the previous macros, and aggregate writes
   previously failed to compile (so they have no prior trace to change). */
#define DT_SCALW(func, lhs, x) __builtin_choose_expr(__DT_AGG(x), __dt_skip((func), (lhs)), __dt_scal((func), (lhs), (long)__builtin_choose_expr(__DT_AGG(x), 0, (x))))
#define DT_PTRW(func, lhs, x)  __builtin_choose_expr(__DT_AGG(x), __dt_skip((func), (lhs)), __dt_ptrv((func), (lhs), (const void*)(uintptr_t)__builtin_choose_expr(__DT_AGG(x), 0, (x))))
#endif /* DEEPDIFF_WRITE_TRACE_H */
/* end DeepDiff */
'''

# LHS patterns that are SAFE to cast to long (scalar types)
SCALAR_LHS_PATTERNS = [
    r'^[a-z_]\w*$',                          # simple var: r, len, i, count
    r'^[a-z_]\w*->[a-z_]\w*$',               # ptr->scalar_field
    r'^[a-z_]\w*\.[a-z_]\w*$',               # struct.scalar_field
    r'^[a-z_]\w*->[a-z_]\w*->[a-z_]\w*$',    # ptr->ptr->field
]

# Known struct fields that are NOT scalar (skip these)
STRUCT_FIELDS = ['path', 'label', 'auth_id', 'id', 'name', 'subject', 'issuer']

# Known pointer fields
PTR_FIELDS = ['data', 'value', 'attribute_value', 'ctx', 'card']

def _is_func_def(stripped, fn):
    """Return True only if `stripped` begins a DEFINITION of function `fn`,
    not a call, forward declaration, or other use.

    OpenSC-style definitions put the return type on the previous line, so the
    definition line typically starts with `fn(`. Calls look like `x = fn(` or
    `!(y = fn(`; forward declarations end with `;`/`,` (and usually carry a
    leading return type on the same line). We exclude all of those.
    """
    if stripped.startswith(('//', '*', '#', '/*')):
        return False
    m = re.search(rf'\b{fn}\s*\(', stripped)
    if not m:
        return False
    before = stripped[:m.start()]
    # Assignment/call: `... = fn(` — the name is used as a sub-expression.
    if '=' in before:
        return False
    # A statement ending in ';' is a forward declaration or a call, never a
    # definition header.
    if stripped.endswith(';'):
        return False
    # Multi-line signatures: OpenSC puts the return type on the previous line, so
    # a DEFINITION line often begins with `fn(` and ends with ',' or '(' because
    # the parameter list continues below. Accept that ONLY when the name starts
    # the line (before is empty) — calls/decls with a leading return type or
    # assignment are already excluded above. A same-line-return-type forward
    # declaration would end with ';' (handled) so it won't reach here.
    if stripped.endswith(',') or stripped.endswith('('):
        # Multi-line definitions where the return type is on the previous line
        # start with `fn(` (before is empty). Same-line definitions like
        # `static int fn(param,` have a return-type prefix consisting only of
        # type keywords / identifiers / pointer stars — no parentheses, commas,
        # equals, etc. (calls/assignments/expressions were already rejected).
        b = before.strip()
        if b == '':
            return True
        return re.match(r'^[A-Za-z_][\w\s\*]*$', b) is not None
    # Used inside an expression/condition: preceded by an operator/paren.
    prev = before.rstrip()
    if prev and prev[-1] in '(!,&|.*-+/><=':
        return False
    # Control-flow keywords that can be followed by '(' are not definitions.
    if re.match(r'^(for|while|if|else|switch|return|sizeof)\b', stripped):
        return False
    return True


def is_inside_string(line, pos):
    """Check if position 'pos' in line is inside a string literal."""
    in_str = False
    quote_char = None
    i = 0
    while i < pos:
        c = line[i]
        if not in_str and c in '"\'':
            in_str = True
            quote_char = c
        elif in_str and c == quote_char and (i == 0 or line[i-1] != '\\'):
            in_str = False
        i += 1
    return in_str


def strip_code_comment(s):
    """Return the code portion of a source line with any trailing/inline comment
    removed. Scans char-by-char honouring string and char literals so a ``//`` or
    ``/*`` inside a string (e.g. "http://x") is NOT treated as a comment. Cuts at
    the first comment that begins outside a literal; for our single-statement
    lines this reliably strips a trailing ``; /* ... */`` or ``; // ...``."""
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == '"':
            i += 1
            while i < n and s[i] != '"':
                if s[i] == '\\':
                    i += 1
                i += 1
            i += 1
            continue
        if c == "'":
            i += 1
            while i < n and s[i] != "'":
                if s[i] == '\\':
                    i += 1
                i += 1
            i += 1
            continue
        if c == '/' and i + 1 < n and s[i + 1] in '/*':
            return s[:i].rstrip()
        i += 1
    return s.rstrip()


def _brace_delta(line, in_block):
    """Return (net brace delta, still_in_block_comment) for one source line.

    Braces inside string/char literals and comments are ignored. Used to track
    whether an ``#include`` sits at true file scope: binutils' i386-dis.c (and
    similar table-driven code) places includes INSIDE a brace-enclosed array
    initializer, e.g.

        static const struct dis386 mod_table[][2] = {
          ...
        #include "i386-dis-evex-mod.h"
        };

    Inserting a declaration there is invalid C, so such includes must not be
    treated as valid anchors for the trace header."""
    delta = 0
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if in_block:
            if c == '*' and i + 1 < n and line[i + 1] == '/':
                in_block = False
                i += 2
                continue
            i += 1
            continue
        if c == '/' and i + 1 < n and line[i + 1] == '*':
            in_block = True
            i += 2
            continue
        if c == '/' and i + 1 < n and line[i + 1] == '/':
            break
        if c == '"' or c == "'":
            q = c
            i += 1
            while i < n and line[i] != q:
                if line[i] == '\\':
                    i += 1
                i += 1
            i += 1
            continue
        if c == '{':
            delta += 1
        elif c == '}':
            delta -= 1
        i += 1
    return delta, in_block


def is_braceless_header(pc):
    """True if ``pc`` (a previous, comment-stripped code line) is a control-flow
    header whose body is a single brace-less statement — i.e. ``if(...)``,
    ``else if(...)``, ``for(...)``, ``while(...)``, ``switch(...)`` with no
    trailing ``{``, or a bare ``else`` / ``do``. When the next statement is that
    body, a trace must be wrapped in braces or it silently detaches the body
    (making a following ``return`` unconditional / dead code)."""
    if not pc:
        return False
    pc = pc.strip()
    if pc.endswith('{') or pc.endswith(';') or pc.endswith('}'):
        return False
    core = pc[1:].strip() if pc.startswith('}') else pc  # tolerate "} else"
    if core in ('else', 'do'):
        return True
    if re.match(r'^(if|else\s+if|for|while|switch)\b', core) and core.endswith(')'):
        return True
    return False


def instrument(filepath):
    with open(filepath) as f:
        lines = f.readlines()

    # Insert header after the last TOP-LEVEL #include (conditional-nesting depth
    # 0) that appears BEFORE the first target-function definition. Two hazards:
    #  - includes nested inside #if/#ifdef blocks may be compiled out, so the
    #    header (with the DT/DT_ENTER macros) must not be dropped there;
    #  - some files place stray top-level includes near the bottom (e.g. a
    #    `#include <setjmp.h>` before an `#ifdef TEST main()`), which would put
    #    the header AFTER the instrumented function and leave DT_* undeclared.
    # If no target function is detected there is nothing to instrument, so we
    # skip inserting the header (avoids landing it at line 1 inside the top
    # license comment — which produced invalid C for multi-line signatures).
    first_func_line = None
    for i, line in enumerate(lines):
        s = line.strip()
        if any(_is_func_def(s, fn) for fn in TARGET_FUNCS):
            first_func_line = i
            break
    if first_func_line is None:
        with open(filepath, 'w') as f:
            f.writelines(lines)
        return 0
    last_inc = None
    cond_depth = 0
    brace_depth = 0
    in_block_comment = False
    for i, line in enumerate(lines):
        if i >= first_func_line:
            break
        s = line.strip()
        if re.match(r'^#\s*(if|ifdef|ifndef)\b', s):
            cond_depth += 1
        elif re.match(r'^#\s*endif\b', s):
            if cond_depth > 0:
                cond_depth -= 1
        elif s.startswith('#include') and cond_depth == 0 and brace_depth == 0:
            last_inc = i
        # Track brace nesting on non-preprocessor lines so an #include that sits
        # inside a brace-enclosed initializer is never chosen as the anchor.
        if not s.startswith('#'):
            d, in_block_comment = _brace_delta(line, in_block_comment)
            brace_depth += d
            if brace_depth < 0:
                brace_depth = 0
    # Insert after the last top-level include if one exists before the function;
    # otherwise just before the function's return-type/signature block. We back
    # up over any contiguous preceding lines that belong to the definition's
    # return type (non-empty, non-brace) so we never split `static int\nfoo(...)`.
    if last_inc is not None:
        insert_at = last_inc + 1
    else:
        insert_at = first_func_line
        while insert_at > 0 and lines[insert_at - 1].strip() \
                and not lines[insert_at - 1].strip().endswith((';', '}', '{', '*/')):
            insert_at -= 1
    lines.insert(insert_at, TRACE_HEADER + "\n")

    output = []
    current_func = None
    brace_depth = 0
    in_func = False
    func_brace_start = 0
    count = 0

    def prev_code_of(idx):
        """Logical preceding control header, reconstructed across continuation
        lines, used to detect a brace-less control header.

        A multi-line control header such as

            if (a &&
                (b || c))
                body;

        leaves the nearest single preceding code line as the condition tail
        ``(b || c))`` — which does not start with ``if`` — so testing only that
        line would miss the brace-less body and detach it (orphaning a following
        ``else``; see ghostscript arvo_53619). We therefore gather the preceding
        code lines and join progressively more of them (nearest last) so the
        reconstructed statement begins with the control keyword and can be matched
        by ``is_braceless_header``."""
        def collect_seq(start):
            seq = []
            j = start
            while j >= 0 and len(seq) < 12:
                s = lines[j].strip()
                if not s or s.startswith(('//', '/*', '*', '#')):
                    j -= 1
                    continue
                seq.append(strip_code_comment(s))
                j -= 1
            return seq

        def try_seq(seq):
            # seq[0] is the nearest preceding code line. Try joining 1..N lines
            # (reversed so the earliest comes first) and return the first join
            # that looks like a brace-less control header.
            for k in range(1, len(seq) + 1):
                joined = ' '.join(reversed(seq[:k]))
                if is_braceless_header(joined):
                    return joined
            return None

        seq = collect_seq(idx - 1)
        if not seq:
            return None
        found = try_seq(seq)
        if found:
            return found

        # The immediately preceding line(s) may instead be a continuation of
        # the CURRENT (possibly multi-line) statement itself — e.g. a chained
        # assignment split as ``a =\n    b = 1;`` where idx is the LAST line.
        # Such lines end in an operator rather than a statement terminator and
        # are not themselves a control header, so the join above never lands on
        # a string ending in ')' and silently fails to detect the TRUE
        # preceding brace-less header (see wamr oss-fuzz_404921047, where this
        # missed an `if (...)  a = b = 1;` body and orphaned the following
        # `else`). Skip past such continuation lines to find the real
        # preceding construct and retry.
        j = idx - 1
        while j >= 0:
            s = lines[j].strip()
            if not s or s.startswith(('//', '/*', '*', '#')):
                j -= 1
                continue
            core = strip_code_comment(s)
            if core.endswith((';', '{', '}')) or is_braceless_header(core) \
               or re.match(r'^(if|else\b|for|while|switch|do)\b', core):
                break
            j -= 1
        if j != idx - 1:
            seq2 = collect_seq(j)
            found2 = try_seq(seq2)
            if found2:
                return found2

        return seq[0]

    def emit_trace(trace, position, braceless):
        """Insert ``trace`` relative to the current statement (output[-1]).

        position: 'before' (e.g. before a return) or 'after' (after a write).
        braceless: when True the current statement is the single brace-less body
        of a control header, so wrap {statement + trace} in braces to preserve
        control flow instead of detaching the body."""
        if braceless:
            stmt = output.pop()
            ind = stmt[:len(stmt) - len(stmt.lstrip())]
            block = ind + "{\n"
            block += (trace + stmt) if position == 'before' else (stmt + trace)
            block += ind + "}\n"
            output.append(block)
        else:
            if position == 'before':
                output.insert(-1, trace)
            else:
                output.append(trace)

    for idx, line in enumerate(lines):
        output.append(line)
        stripped = line.strip()

        # Detect function definition (not a call or forward declaration).
        if not in_func:
            for fn in TARGET_FUNCS:
                if _is_func_def(stripped, fn):
                    current_func = fn
                    break

        # Track braces (only in non-string, non-comment context - simplified)
        for ch in stripped:
            if ch == '{':
                brace_depth += 1
                if current_func and not in_func:
                    in_func = True
                    func_brace_start = brace_depth
                    struct_locals = set()
                    output.append(f'    DT_ENTER("{current_func}");\n')
            elif ch == '}':
                brace_depth -= 1
                if in_func and brace_depth < func_brace_start:
                    in_func = False
                    current_func = None

        if not in_func or not current_func:
            continue

        # Record aggregate (struct/union/enum, non-pointer) locals declared
        # ANYWHERE in this function — including inside `for (...)` headers and
        # plain declarations — so a later whole-struct copy of one (e.g.
        # `dst->field = isym;`) is not traced with an invalid `(long)` cast. This
        # runs before the control-flow skip below precisely so `for (struct T v;`
        # loop-scoped declarations are captured. Pointer decls (`struct T *p`) are
        # excluded so they can still be traced as pointers. `enum` is NOT included:
        # enums are scalar (castable to long) and were traced in prior results.
        _scan = strip_code_comment(stripped)
        for _m in re.finditer(r'\b(?:struct|union)\s+\w+\s+([A-Za-z_]\w*)\s*[;,=)]', _scan):
            if not _scan[:_m.start(1)].rstrip().endswith('*'):
                struct_locals.add(_m.group(1))

        # Skip comments, preprocessor, control flow
        if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
            continue
        if stripped.startswith('#'):
            continue
        if re.match(r'^(for|while|if|else|switch|goto|break|continue|case|default)\b', stripped):
            continue
        # Strip a trailing/inline comment so `stmt; /* ... */` is still recognised
        # as a statement (endswith ';') and instrumented. All parsing below uses
        # this comment-free form.
        stripped = strip_code_comment(stripped)
        if not stripped.endswith(';'):
            continue

        # Is this statement the single brace-less body of a control header? If so
        # any inserted trace must be wrapped in braces (else it detaches the body,
        # e.g. making a following `return` unconditional — see arvo_25885).
        braceless = is_braceless_header(prev_code_of(idx))

        # Handle return
        if re.match(r'^return\b', stripped):
            ret_m = re.match(r'^return\s+([A-Z_]\w*)\s*;$', stripped)
            if ret_m:
                # Only trace simple identifier returns (SC_SUCCESS, SC_ERROR_*, etc.)
                rval = ret_m.group(1)
                indent = line[:len(line) - len(line.lstrip())]
                emit_trace(f'{indent}DT_RET("{current_func}", ({rval}));\n', 'before', braceless)
            elif re.match(r'^return\s+(-?\d+|r|rv|ret|rc|len|count|result)\s*;$', stripped):
                rval = re.match(r'^return\s+(.+?)\s*;$', stripped).group(1)
                indent = line[:len(line) - len(line.lstrip())]
                emit_trace(f'{indent}DT_RET("{current_func}", ({rval}));\n', 'before', braceless)
            continue

        # Skip lines that have function calls (likely not simple assignments)
        # But allow lines like "x = func_call();"
        code = stripped

        # Find the '=' that is the assignment operator (not inside strings, not == etc.)
        # Simple approach: split on first = that isn't part of ==, !=, <=, >=
        eq_pos = None
        i = 0
        while i < len(code):
            if code[i] == '"':
                # skip string literal
                i += 1
                while i < len(code) and code[i] != '"':
                    if code[i] == '\\': i += 1
                    i += 1
                i += 1
                continue
            if code[i] == '\'' :
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
                    # Check for compound: +=, -=, *=, /=, etc.
                    if prev in '+-*/%&|^':
                        eq_pos = i
                        break
                    else:
                        eq_pos = i
                        break
            i += 1

        if eq_pos is None:
            # No assignment operator. Still record aggregate (struct/union,
            # non-pointer) local declarations like `struct internal_syment isym;`
            # so a later whole-struct copy of `isym` is not traced with (long).
            # `enum` is excluded (scalar, castable to long, traced in prior results).
            m_agg = re.match(
                r'^(?:(?:const|static|volatile|register)\s+)*'
                r'(?:struct|union)\s+\w+\s+([A-Za-z_]\w*)\s*;$',
                re.sub(r'\s+', ' ', code).strip())
            if m_agg and '*' not in code:
                struct_locals.add(m_agg.group(1))
            continue

        lhs = code[:eq_pos].rstrip()
        rhs = code[eq_pos+1:].rstrip(';').strip()

        # Skip multi-line-LHS continuations: this line-based scanner never joins
        # physical lines, so a base object on the PREVIOUS line (e.g.
        # `module->import_tables[table_idx]` then, on the next line,
        # `.u.table.table_type.possible_grow = true;`) leaves `lhs` as a bare
        # leading `.field`/`->field` chain with no primary expression before it.
        # Emitting that fragment as a standalone macro argument is invalid C
        # (e.g. `DT_SCALW(..., .u.table.table_type.possible_grow)` -> "expected
        # expression"). Skip instrumenting such lines rather than miscompiling.
        if lhs.lstrip().startswith('.') or lhs.lstrip().startswith('->'):
            continue

        # Skip the tail of a CHAINED multi-line assignment: `a =\n    b = 1;`
        # is one statement whose value (`b = 1`, itself an expression) is
        # assigned to `a`. Treating the second line as an independent
        # instrumentable statement is unsafe: wrapping it (and its trace) in
        # braces to preserve a brace-less `if`/`else` body turns `a = { ...
        # }`, which is invalid C (a block cannot be an assignment's RHS); NOT
        # wrapping it instead risks silently detaching a brace-less control
        # body (see wamr oss-fuzz_404921047). Detect this by checking whether
        # the nearest preceding code line ends in a bare `=` (an assignment
        # continuing onto this line) and skip instrumenting if so.
        j = idx - 1
        while j >= 0:
            s = lines[j].strip()
            if not s or s.startswith(('//', '/*', '*', '#')):
                j -= 1
                continue
            prev_core = strip_code_comment(s)
            break
        else:
            prev_core = ''
        if prev_core.endswith('=') and not prev_core.endswith(('==', '!=', '<=', '>=')):
            continue

        # Handle compound assignment (lhs includes the operator)
        is_compound = False
        if lhs and lhs[-1] in '+-*/%&|^':
            lhs = lhs[:-1].rstrip()
            is_compound = True

        # Extract just the variable name for declarations. Handle ANY leading
        # type (e.g. `sc_profile_t *profile`, `struct foo *bar`), not just a
        # hardcoded list, and normalise tabs to single spaces first.
        var_name = lhs
        lhs_norm = re.sub(r'\s+', ' ', lhs).strip()
        decl_m = re.match(
            r'^(?:(?:const|static|unsigned|signed|volatile|struct|enum|register)\s+'
            r'|[A-Za-z_]\w*\s+)+\**\s*(\w+)$',
            lhs_norm
        )
        if decl_m:
            var_name = decl_m.group(1)

        # Skip if variable name still contains whitespace or '*' (bad parse):
        # never emit a type/declaration as a value expression.
        if re.search(r'[\s*]', var_name) and '->' not in var_name and '.' not in var_name:
            continue

        # Skip known struct-type fields that can't be cast to long
        field_name = var_name.split('->')[-1].split('.')[-1] if ('->' in var_name or '.' in var_name) else var_name
        if field_name in STRUCT_FIELDS:
            continue

        # Skip aggregate (struct/union) VALUE declarations: a whole struct
        # value can't be cast to long (e.g. `struct sym_cache cache = {0,0};`
        # would produce the invalid `(long)(cache)`). A POINTER to such a type
        # carries a '*' in the lhs and is fine — it falls through to DT_PTR.
        # Also remember the declared name as an aggregate local so later copies
        # of it (e.g. `dst->field = cache;`) are likewise skipped. `enum` is
        # excluded (scalar, castable to long, traced in prior results).
        if re.match(r'^(?:const|static|volatile|register|unsigned|signed)\s+'
                    r'(?:.*\s+)?(?:struct|union)\b', lhs_norm) \
           or re.match(r'^(?:struct|union)\b', lhs_norm):
            if '*' not in lhs:
                struct_locals.add(var_name)
                continue

        # Skip if RHS contains quotes (string assignment, not numeric)
        if '"' in rhs:
            continue

        # Skip brace / aggregate initializers (e.g. `= {0, 0}` or `= { .a = 1 }`):
        # these are struct/array values, not scalars, so `(long)(...)` is invalid.
        if rhs.startswith('{'):
            continue

        # Skip whole-aggregate copies: `dst = agg;` where `agg` is a bare struct
        # local we recorded above. The value is a struct, so `(long)(dst)` would
        # be an invalid cast (e.g. `newentry->isym = isym;` with struct isym).
        if rhs in struct_locals:
            continue

        # Skip strncpy, memcpy, memset calls (not assignments)
        if re.match(r'^(strncpy|memcpy|memset|memmove|sc_log|snprintf)\s*\(', lhs) or \
           re.match(r'^(strncpy|memcpy|memset|memmove|sc_log|snprintf)\s*\(', code):
            continue

        indent = line[:len(line) - len(line.lstrip())]

        # Choose scalar vs pointer with the SAME heuristic as before, so the
        # emitted trace line is byte-identical to the prior DT/DT_PTR output for
        # every scalar/pointer value. The only behavioural difference vs the old
        # macros is that a struct/union value (which the old `(long)`/`(uintptr_t)`
        # cast could not compile — e.g. `ipsp->cs_data = *pgd;`) is skipped at
        # compile time instead of breaking the build. Such aggregate writes had no
        # prior trace (the build failed), so this changes no existing result.
        is_ptr = (field_name in PTR_FIELDS or
                  rhs == 'NULL' or
                  'malloc' in rhs or 'calloc' in rhs or
                  '&' == rhs[0:1] or
                  re.search(r'\w+\s*\+\s*sizeof', rhs) or
                  re.search(r'\w+\s*\+\s*\w+', rhs) and '*' in lhs)

        if is_ptr or ('*' in lhs and '->' not in lhs):
            trace = f'{indent}DT_PTRW("{current_func}", "{var_name}", {var_name});\n'
        else:
            trace = f'{indent}DT_SCALW("{current_func}", "{var_name}", {var_name});\n'

        emit_trace(trace, 'after', braceless)
        count += 1

    with open(filepath, 'w') as f:
        f.writelines(output)
    return count

if __name__ == '__main__':
    total = 0
    for path in sys.argv[1:]:
        n = instrument(path)
        print(f"  Instrumented {path}: {n} trace points")
        total += n
    print(f"  Total: {total} trace points")
