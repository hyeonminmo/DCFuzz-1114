#!/usr/bin/env python3
"""Build a dominator manifest with BB source-line sets and structural BB fingerprints.

Input (from extract_dominator_v2.py):
  program_dominators:
    - function:bb=<bb>  # line=<rep>|? lines=<l1,l2,...>|? fingerprint=<fp>|?

Output TSV:
  <id> <function> <original_bb> <representative_line> <source_lines_csv> <bb_fingerprint>

The fifth column keeps every debug source line observed in the analysis-time BB.
The sixth column stores a structural fingerprint (instruction count/opcode sequence/
call-kind sequence/terminator) for resolving source-line overlap ties.
"""

import argparse
import re
import sys
from pathlib import Path
from typing import List, Optional, Tuple


DOM_LINE_RE = re.compile(
    r'^\s*-\s+'
    r'(?P<func>[^:\s][^:]*)\s*:\s*'
    r'bb\s*=\s*(?P<bb>[^#\s]+)'
    r'(?:\s*#\s*line\s*=\s*(?P<line>\?|[0-9]+))?'
    r'(?:\s+lines\s*=\s*(?P<lines>\?|[0-9]+(?:,[0-9]+)*))?'
    r'(?:\s+fingerprint\s*=\s*(?P<fingerprint>\S+))?'
    r'\s*$'
)


def parse_line_number(text: str) -> Optional[int]:
    text = (text or "").strip()
    if not text or text == "?":
        return None
    try:
        value = int(text)
    except ValueError:
        return None
    return value if value > 0 else None


def parse_source_lines(text: str, rep_line: Optional[int]) -> Tuple[int, ...]:
    text = (text or "").strip()
    values = set()
    if text and text != "?":
        for token in text.split(","):
            try:
                value = int(token)
            except ValueError:
                continue
            if value > 0:
                values.add(value)
    # Backward compatibility: if an older extractor only emitted line=N,
    # preserve that N as a one-element source-line set.
    if not values and rep_line is not None:
        values.add(rep_line)
    return tuple(sorted(values))


def parse_fingerprint(text: str) -> str:
    text = (text or "").strip()
    return text if text else "?"


def parse_program_dominators(path: Path):
    """Return (function, original_bb, representative_line, source_lines, fingerprint)."""
    rows: List[Tuple[str, str, Optional[int], Tuple[int, ...], str]] = []
    row_index = {}
    in_program_dom_section = False

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n")
            stripped = line.strip()

            if not stripped:
                continue
            if stripped.startswith("#"):
                in_program_dom_section = False
                continue
            if stripped == "program_dominators:":
                in_program_dom_section = True
                continue
            if not in_program_dom_section:
                continue
            if not line.startswith((" ", "\t", "-")) and stripped.endswith(":"):
                in_program_dom_section = False
                continue
            if stripped == "<none>":
                in_program_dom_section = False
                continue

            m = DOM_LINE_RE.match(line)
            if not m:
                continue

            func = m.group("func").strip()
            bb = m.group("bb").strip() or "entry"
            if not func or not bb:
                continue

            rep_line = parse_line_number(m.group("line") or "")
            source_lines = parse_source_lines(m.group("lines") or "", rep_line)
            fingerprint = parse_fingerprint(m.group("fingerprint") or "")
            if rep_line is None and source_lines:
                rep_line = source_lines[0]

            key = (func, bb)
            if key in row_index:
                idx = row_index[key]
                old_func, old_bb, old_rep, old_lines, old_fp = rows[idx]
                merged = tuple(sorted(set(old_lines) | set(source_lines)))
                merged_rep = old_rep if old_rep is not None else rep_line
                if merged_rep is None and merged:
                    merged_rep = merged[0]

                if old_fp == "?":
                    merged_fp = fingerprint
                elif fingerprint == "?" or old_fp == fingerprint:
                    merged_fp = old_fp
                else:
                    # Conflicting fingerprints for the same function/BB should
                    # never be guessed.  Keep the row but disable fingerprint
                    # matching for it.
                    merged_fp = "?"

                rows[idx] = (old_func, old_bb, merged_rep, merged, merged_fp)
                continue

            row_index[key] = len(rows)
            rows.append((func, bb, rep_line, source_lines, fingerprint))

    return rows


def write_manifest(rows, out_path: Path):
    """Write six columns consumed by DominatorCoveragePass_v2.cpp."""
    with out_path.open("w", encoding="utf-8") as out:
        for idx, (func, bb, rep_line, source_lines, fingerprint) in enumerate(rows):
            rep_text = str(rep_line) if rep_line is not None else "?"
            lines_text = ",".join(str(x) for x in source_lines) if source_lines else "?"
            fp_text = fingerprint if fingerprint else "?"
            out.write(
                f"{idx}\t{func}\t{bb}\t{rep_text}\t{lines_text}\t{fp_text}\n"
            )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dominator_nodes", help="input dominator_nodes.txt")
    ap.add_argument("out_tsv", help="output dominator_map.tsv")
    args = ap.parse_args()

    in_path = Path(args.dominator_nodes)
    out_path = Path(args.out_tsv)

    if not in_path.exists():
        print(f"[make_dominator_0907] ERROR: input not found: {in_path}", file=sys.stderr)
        return 2

    rows = parse_program_dominators(in_path)
    if not rows:
        out_path.write_text("", encoding="utf-8")
        print(
            f"[make_dominator_0907] ERROR: no dominator entries found in {in_path}",
            file=sys.stderr,
        )
        return 1

    write_manifest(rows, out_path)

    known_rep = sum(1 for _, _, line, _, _ in rows if line is not None)
    with_line_sets = sum(1 for _, _, _, lines, _ in rows if lines)
    with_fingerprints = sum(1 for _, _, _, _, fp in rows if fp and fp != "?")
    print(
        f"[make_dominator_0907] wrote {len(rows)} entries to {out_path} "
        f"(representative_line_known={known_rep}, source_line_sets={with_line_sets}, "
        f"bb_fingerprints={with_fingerprints})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
