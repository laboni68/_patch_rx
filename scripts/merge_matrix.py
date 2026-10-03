#!/usr/bin/env python3
"""
merge_matrix.py — Merge a freshly-generated matrix_result.txt into a previously
existing one, ADDING the new run's input(s) as extra columns without discarding
the results already present.

deepdiff_pipeline.sh normally regenerates matrix_result.txt from scratch, so a
re-run with a different input would overwrite (and lose) the earlier columns.
With --merge-new-input the pipeline calls this script to combine the two:

  * RESULTS MATRIX  — input COLUMNS are unioned. Existing columns keep their
    old verdicts (authoritative); genuinely new inputs are appended as new
    columns. Merge is keyed by column label, so re-running the same input is
    idempotent (no duplicate column) while a new input is added.
  * PER-INPUT COVERAGE tables — input ROWS are unioned per build, same rule.

All other text (task header, interpretation, instrumentation notes, coverage
preamble) is taken from the NEW file so it reflects the latest run.

Usage:
  merge_matrix.py --old OLD.txt --new NEW.txt --out OUT.txt
  (--out defaults to the --new path, i.e. an in-place merge of the new file.)
"""

import argparse
import re
import sys


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
def _is_sep(line):
    s = line.strip()
    return s != "" and set(s) <= set("-+")


def parse_results(lines):
    """Return (header_idx, table_end_idx, columns, rows).

    columns = input labels including 'PoC' (the leading 'patch' cell dropped).
    rows    = list of (row_label, {col_label: verdict}), preserving file order.
    header_idx / table_end_idx delimit the table region in `lines`
    (table_end_idx is the index of the first blank line after the data rows).
    """
    hdr_i = None
    for i, ln in enumerate(lines):
        if re.match(r"^\s*patch\s*\|", ln) and "PoC" in ln:
            hdr_i = i
            break
    if hdr_i is None:
        return None, None, [], []
    columns = [c.strip() for c in lines[hdr_i].split("|")][1:]
    rows = []
    j = hdr_i + 1
    while j < len(lines):
        ln = lines[j]
        if ln.strip() == "":
            break
        if _is_sep(ln):
            j += 1
            continue
        if "|" not in ln:
            break
        cells = [c.strip() for c in ln.split("|")]
        label = cells[0]
        if not re.match(r"^p\d+\s*\(", label):
            break
        verdicts = cells[1:]
        cellmap = {}
        for k, col in enumerate(columns):
            cellmap[col] = verdicts[k] if k < len(verdicts) else "NO-DATA"
        rows.append((label, cellmap))
        j += 1
    return hdr_i, j, columns, rows


def parse_coverage(lines):
    """Return ordered list of [title, row_order, row_map].

    row_map[input_label] = [reached, writes, cover, post] (the 4 data cells).
    """
    sections = []
    i = 0
    while i < len(lines):
        m = re.match(r"^PER-INPUT COVERAGE on (.*) build:\s*$", lines[i])
        if not m:
            i += 1
            continue
        title = m.group(1)
        order, rowmap = [], {}
        k = i + 1
        while k < len(lines):
            ln = lines[k]
            if ln.strip() == "":
                break
            if ln.startswith("PER-INPUT COVERAGE on "):
                break
            if "|" in ln:
                cells = [c.strip() for c in ln.split("|")]
                if cells[0] != "input":  # skip the header row
                    order.append(cells[0])
                    rowmap[cells[0]] = cells[1:]
            k += 1
        sections.append([title, order, rowmap])
        i = k
    return sections


# --------------------------------------------------------------------------
# Formatting
# --------------------------------------------------------------------------
def fmt_results(columns, rows):
    out = []
    # header: 'patch' + PoC + remaining input columns
    header = f"{'patch':<18} | {columns[0]:<12}"
    for col in columns[1:]:
        header += f" | {col:<14}"
    out.append(header)
    sep = "-" * 19 + "+" + "-" * 14
    for _ in columns[1:]:
        sep += "+" + "-" * 16
    out.append(sep)
    for label, cellmap in rows:
        line = f"{label:<18} | {cellmap.get(columns[0], 'NO-DATA'):<12}"
        for col in columns[1:]:
            line += f" | {cellmap.get(col, 'NO-DATA'):<14}"
        out.append(line)
    return out


def fmt_coverage(sections):
    out = []
    hdr = (f"  {'input':<16} | {'reached':<10} | {'writes covered':<16} | "
           f"{'cover%':<8} | {'post-change':<14}")
    sep = ("  -----------------+------------+------------------+"
           "----------+---------------")
    for title, order, rowmap in sections:
        out.append("")
        out.append(f"PER-INPUT COVERAGE on {title} build:")
        out.append(hdr)
        out.append(sep)
        for inp in order:
            c = rowmap[inp]
            c = (c + ["", "", "", ""])[:4]
            out.append(f"  {inp:<16} | {c[0]:<10} | {c[1]:<16} | "
                       f"{c[2]:<8} | {c[3]:<14}")
    return out


# --------------------------------------------------------------------------
# Merging
# --------------------------------------------------------------------------
def merge_results(old_cols, old_rows, new_cols, new_rows):
    """Union columns (old first, then new-only); old columns keep old verdicts."""
    merged_cols = list(old_cols)
    for c in new_cols:
        if c not in merged_cols:
            merged_cols.append(c)
    old_map = {lbl: cm for lbl, cm in old_rows}
    new_map = {lbl: cm for lbl, cm in new_rows}
    # row order: old rows first, then any new-only patch rows.
    row_labels = [lbl for lbl, _ in old_rows]
    for lbl, _ in new_rows:
        if lbl not in old_map:
            row_labels.append(lbl)
    merged_rows = []
    for lbl in row_labels:
        om = old_map.get(lbl, {})
        nm = new_map.get(lbl, {})
        cellmap = {}
        for col in merged_cols:
            if col in old_cols and col in om:
                cellmap[col] = om[col]           # existing result preserved
            elif col in nm:
                cellmap[col] = nm[col]            # new input's verdict
            elif col in om:
                cellmap[col] = om[col]
            else:
                cellmap[col] = "NO-DATA"
        merged_rows.append((lbl, cellmap))
    return merged_cols, merged_rows


def merge_coverage(old_secs, new_secs):
    old_by = {t: (o, m) for t, o, m in old_secs}
    new_by = {t: (o, m) for t, o, m in new_secs}
    titles = [t for t, _, _ in new_secs]
    for t, _, _ in old_secs:
        if t not in titles:
            titles.append(t)
    merged = []
    for t in titles:
        oo, om = old_by.get(t, ([], {}))
        no, nm = new_by.get(t, ([], {}))
        order, rowmap = [], {}
        for inp in oo:                 # existing rows preserved (authoritative)
            order.append(inp)
            rowmap[inp] = om[inp]
        for inp in no:                 # new input rows appended
            if inp not in rowmap:
                order.append(inp)
                rowmap[inp] = nm[inp]
        merged.append([t, order, rowmap])
    return merged


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--old", required=True, help="Previously existing matrix file")
    ap.add_argument("--new", required=True, help="Freshly generated matrix file")
    ap.add_argument("--out", default=None,
                    help="Output path (default: --new, in-place)")
    args = ap.parse_args()
    out_path = args.out or args.new

    try:
        old_lines = open(args.old, errors="replace").read().splitlines()
        new_lines = open(args.new, errors="replace").read().splitlines()
    except OSError as e:
        print(f"merge_matrix: cannot read input: {e}", file=sys.stderr)
        sys.exit(1)

    o_hdr, o_end, o_cols, o_rows = parse_results(old_lines)
    n_hdr, n_end, n_cols, n_rows = parse_results(new_lines)
    if n_hdr is None:
        print("merge_matrix: no RESULTS MATRIX in new file; leaving new as-is",
              file=sys.stderr)
        # Nothing to merge into; keep the new file.
        if out_path != args.new:
            open(out_path, "w").write("\n".join(new_lines) + "\n")
        sys.exit(0)
    if o_hdr is None:
        print("merge_matrix: no RESULTS MATRIX in old file; keeping new file",
              file=sys.stderr)
        open(out_path, "w").write("\n".join(new_lines) + "\n")
        sys.exit(0)

    merged_cols, merged_rows = merge_results(o_cols, o_rows, n_cols, n_rows)
    merged_cov = merge_coverage(parse_coverage(old_lines),
                                parse_coverage(new_lines))

    # Reassemble using the NEW file's surrounding text.
    head = new_lines[:n_hdr]
    # first per-build coverage section in the new file
    cov_i = None
    for i, ln in enumerate(new_lines):
        if ln.startswith("PER-INPUT COVERAGE on "):
            cov_i = i
            break
    if cov_i is None:
        mid = new_lines[n_end:]
        cov_out = []
    else:
        mid = new_lines[n_end:cov_i]
        cov_out = fmt_coverage(merged_cov)
    # trim trailing blank lines from mid (coverage section adds its own blank)
    while mid and mid[-1].strip() == "":
        mid.pop()

    out = []
    out += head
    out += fmt_results(merged_cols, merged_rows)
    out += mid
    out += cov_out

    with open(out_path, "w") as fh:
        fh.write("\n".join(out) + "\n")

    added = [c for c in merged_cols if c not in o_cols]
    print(f"merge_matrix: merged -> {out_path}  "
          f"(columns now: {len(merged_cols)}; added: {added or 'none'})")


if __name__ == "__main__":
    main()
