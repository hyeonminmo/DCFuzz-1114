#!/usr/bin/env python3
import sys

if len(sys.argv) != 3:
    print(f"usage: {sys.argv[0]} <dominator_nodes.txt> <out.tsv>", file=sys.stderr)
    sys.exit(2)

infile, outfile = sys.argv[1], sys.argv[2]

in_section = False
rows = []
seen = set()

with open(infile, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        s = line.rstrip("\n")

        if s.strip() == "program_dominators:":
            in_section = True
            continue

        if not in_section:
            continue

        s = s.strip()
        if not s:
            continue
        if s == "<none>":
            break
        if not s.startswith("- "):
            continue

        item = s[2:].strip()   # function:bb=<name>
        if ":" not in item:
            continue

        func, tail = item.split(":", 1)
        func = func.strip()
        tail = tail.strip()

        if not tail.startswith("bb="):
            continue

        bb_name = tail[len("bb="):].strip()

        # trailing comment 제거
        if "#" in bb_name:
            bb_name = bb_name.split("#", 1)[0].strip()

        if not bb_name:
            continue

        key = (func, bb_name)
        if key not in seen:
            seen.add(key)
            rows.append(key)

with open(outfile, "w", encoding="utf-8") as out:
    for idx, (func, bb_name) in enumerate(rows):
        out.write(f"{idx}\t{func}\t{bb_name}\n")
