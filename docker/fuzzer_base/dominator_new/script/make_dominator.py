#!/usr/bin/env python3
import argparse
import re
import sys
from pathlib import Path


DOM_LINE_RE = re.compile(
    r'^\s*-\s+(?P<func>[^:\s][^:]*)\s*:\s*bb\s*=\s*(?P<bb>[^#\s]+)'
)


def parse_program_dominators(path: Path):
    """
    Parse only the exact `program_dominators:` sections from dominator_nodes.txt.

    Expected lines:
      program_dominators:
        - function:bb=<bb>  # line=<line>
        - function:bb=<bb>  # line=?

    Important:
      extract_dominator.py also prints other sections such as:
        target_basic_blocks:
          - function:bb=<bb>
      These must NOT be parsed as dominators.
    """
    rows = []
    seen = set()
    in_program_dom_section = False

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n")
            stripped = line.strip()

            if not stripped:
                continue

            # New target separator or comment block: close current section.
            if stripped.startswith("#"):
                in_program_dom_section = False
                continue

            # Start of the only section we want.
            if stripped == "program_dominators:":
                in_program_dom_section = True
                continue

            if not in_program_dom_section:
                continue

            # If a new top-level section starts, stop parsing program_dominators.
            # Example:
            #   target:
            #   target_function:
            #   bb_rep_lines:
            #   icfg_summary:
            if not line.startswith((" ", "\t", "-")) and stripped.endswith(":"):
                in_program_dom_section = False
                continue

            # No dominators for this target.
            # Do not break the whole file because later targets may still have results.
            if stripped == "<none>":
                in_program_dom_section = False
                continue

            m = DOM_LINE_RE.match(line)
            if not m:
                continue

            func = m.group("func").strip()
            bb = m.group("bb").strip()

            if not func or not bb:
                continue

            # LLVM pass normalizes entry block as "entry".
            if bb == "":
                bb = "entry"

            key = (func, bb)
            if key in seen:
                continue

            seen.add(key)
            rows.append(key)

    return rows


def write_manifest(rows, out_path: Path):
    """
    Output format required by DominatorCoveragePass.cpp:
      <id> TAB <function> TAB <bb>
    """
    with out_path.open("w", encoding="utf-8") as out:
        for idx, (func, bb) in enumerate(rows):
            out.write(f"{idx}\t{func}\t{bb}\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dominator_nodes", help="input dominator_nodes.txt")
    ap.add_argument("out_tsv", help="output dominator_map.tsv")
    args = ap.parse_args()

    in_path = Path(args.dominator_nodes)
    out_path = Path(args.out_tsv)

    if not in_path.exists():
        print(f"[make_dominator] ERROR: input not found: {in_path}", file=sys.stderr)
        return 2

    rows = parse_program_dominators(in_path)

    if not rows:
        # Create an empty file for debugging, but fail the build explicitly.
        out_path.write_text("", encoding="utf-8")
        print(
            f"[make_dominator] ERROR: no dominator entries found in {in_path}",
            file=sys.stderr,
        )
        return 1

    write_manifest(rows, out_path)

    print(f"[make_dominator] wrote {len(rows)} entries to {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())