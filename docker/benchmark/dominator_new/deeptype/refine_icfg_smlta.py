#!/usr/bin/env python3
"""
refine_icfg_smlta.py - Phase 7

Refine an SVF-normalized ICFG with DeepType SMLTA indirect-call targets.

Input
-----
--icfg-dir
    Phase-6 normalized ICFG directory containing:
      icfg_nodes.tsv
      icfg_edges.tsv
      icfg_cfg_edges.tsv
      icfg_call_edges.tsv
      icfg_return_edges.tsv
      icfg_phi.tsv
      icfg_callsites.tsv
      icfg_functions.tsv

--smlta-map
    Phase-6 map_smlta_callsites.py output:
      callsite_id, target_func

Output
------
--outdir
    SMLTA-corrected normalized ICFG.

Policy
------
1. Only callsites present in smlta_callsite_map.tsv are refined.
2. A mapped callsite must be an SVF callsite classified as "indirect".
3. For mapped callsites, the final target set is exactly the SMLTA target set.
4. Unmapped callsites preserve their original SVF call/return/phi relations.
5. call, return and phi relations are updated as one logical unit.
6. Existing SVF relations are reused whenever possible.
7. A target that SMLTA adds beyond SVF is materialized using the callee's
   unique entry/exit nodes from icfg_functions.tsv.  If that cannot be done
   unambiguously, refinement fails rather than guessing.

The original ICFG directory is never modified.
"""

from __future__ import annotations

import argparse
import csv
import shutil
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


def raise_csv_field_limit() -> None:
    """
    SVF-normalized TSV files can contain very large DOT labels / IR strings.
    Python's csv module defaults to a field-size limit of 131072 bytes, which
    is too small for some real SVF ICFG nodes. Raise it defensively to the
    largest value accepted by this Python build.
    """
    limit = sys.maxsize
    while True:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


raise_csv_field_limit()


CALL_HEADER = [
    "callsite_node",
    "callee_entry_node",
    "caller_func",
    "callee_func",
    "callsite_id",
]
RETURN_HEADER = [
    "callee_exit_node",
    "return_node",
    "caller_func",
    "callee_func",
    "callsite_id",
]
PHI_HEADER = [
    "call_edge_src",
    "call_edge_dst",
    "return_edge_src",
    "return_edge_dst",
    "callsite_id",
    "caller_func",
    "callee_func",
]
EDGE_HEADER = ["src", "dst", "kind", "callsite_id", "raw_label"]


def norm_text(value: object) -> str:
    return str(value if value is not None else "").strip()


def norm_func(value: object) -> str:
    s = norm_text(value).strip('"')
    if s.startswith("@"):
        s = s[1:]
    return s


def split_nodes(value: object) -> List[str]:
    return [x.strip() for x in norm_text(value).split(",") if x.strip()]


def callsite_sort_key(callsite_id: str) -> Tuple[int, str]:
    s = norm_text(callsite_id)
    if s.startswith("cs"):
        try:
            return int(s[2:]), s
        except ValueError:
            pass
    return 10**18, s


def read_tsv(path: Path) -> Tuple[List[str], List[Dict[str, str]]]:
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        if reader.fieldnames is None:
            raise RuntimeError("TSV has no header: %s" % path)
        return list(reader.fieldnames), list(reader)


def require_columns(
    path: Path,
    header: Sequence[str],
    required: Iterable[str],
) -> None:
    missing = [name for name in required if name not in header]
    if missing:
        raise RuntimeError(
            "missing required column(s) in %s: %s"
            % (path, ", ".join(missing))
        )


def write_dict_tsv(
    path: Path,
    header: Sequence[str],
    rows: Iterable[Dict[str, str]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=list(header),
            delimiter="\t",
            lineterminator="\n",
            extrasaction="ignore",
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({name: norm_text(row.get(name, "")) for name in header})


def write_rows_tsv(
    path: Path,
    header: Sequence[str],
    rows: Iterable[Sequence[object]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, delimiter="\t", lineterminator="\n")
        writer.writerow(list(header))
        for row in rows:
            writer.writerow([norm_text(x) for x in row])


def row_tuple(row: Dict[str, str], header: Sequence[str]) -> Tuple[str, ...]:
    return tuple(norm_text(row.get(name, "")) for name in header)


def dedup_rows(
    rows: Iterable[Dict[str, str]],
    header: Sequence[str],
) -> List[Dict[str, str]]:
    result: List[Dict[str, str]] = []
    seen: Set[Tuple[str, ...]] = set()
    for row in rows:
        key = row_tuple(row, header)
        if key in seen:
            continue
        seen.add(key)
        result.append({name: norm_text(row.get(name, "")) for name in header})
    return result


def load_function_index(
    functions_path: Path,
    nodes_path: Path,
) -> Dict[str, Dict[str, Set[str]]]:
    func_header, func_rows = read_tsv(functions_path)
    require_columns(
        functions_path,
        func_header,
        ["function", "entry_nodes", "exit_nodes"],
    )

    result: Dict[str, Dict[str, Set[str]]] = {}
    for row in func_rows:
        fn = norm_func(row.get("function", ""))
        if not fn:
            continue
        ent = result.setdefault(fn, {"entries": set(), "exits": set()})
        ent["entries"].update(split_nodes(row.get("entry_nodes", "")))
        ent["exits"].update(split_nodes(row.get("exit_nodes", "")))

    # Defensive fallback for a function omitted from icfg_functions.tsv.
    node_header, node_rows = read_tsv(nodes_path)
    require_columns(nodes_path, node_header, ["node_id", "function", "kind"])
    for row in node_rows:
        fn = norm_func(row.get("function", ""))
        nid = norm_text(row.get("node_id", ""))
        kind = norm_text(row.get("kind", "")).lower()
        if not fn or not nid:
            continue
        ent = result.setdefault(fn, {"entries": set(), "exits": set()})
        if not ent["entries"] and kind == "entry":
            ent["entries"].add(nid)
        if not ent["exits"] and kind == "exit":
            ent["exits"].add(nid)

    return result


def get_unique_entry_exit(
    func_index: Dict[str, Dict[str, Set[str]]],
    target_func: str,
) -> Tuple[str, str]:
    data = func_index.get(target_func)
    if data is None:
        raise RuntimeError(
            "SMLTA target function is absent from icfg_functions.tsv: %s"
            % target_func
        )

    entries = sorted(data.get("entries", set()))
    exits = sorted(data.get("exits", set()))

    if len(entries) != 1:
        raise RuntimeError(
            "cannot materialize SMLTA target %s: expected exactly one entry "
            "node, found %d (%s)"
            % (target_func, len(entries), ",".join(entries) or "<none>")
        )
    if len(exits) != 1:
        raise RuntimeError(
            "cannot materialize SMLTA target %s: expected exactly one exit "
            "node, found %d (%s)"
            % (target_func, len(exits), ",".join(exits) or "<none>")
        )

    return entries[0], exits[0]


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--icfg-dir",
        required=True,
        help="Phase-6 normalized ICFG directory",
    )
    ap.add_argument(
        "--smlta-map",
        required=True,
        help="smlta_callsite_map.tsv from Phase 6",
    )
    ap.add_argument(
        "--outdir",
        required=True,
        help="output directory for the SMLTA-refined ICFG",
    )
    ap.add_argument(
        "--diff-out",
        help="per-callsite refinement diff TSV",
    )
    ap.add_argument(
        "--summary-out",
        help="text summary outside the refined ICFG directory",
    )
    args = ap.parse_args(argv)

    icfg_dir = Path(args.icfg_dir)
    smlta_map_path = Path(args.smlta_map)
    outdir = Path(args.outdir)

    diff_path = (
        Path(args.diff_out)
        if args.diff_out
        else outdir.parent / "smlta_refine_diff.tsv"
    )
    summary_path = (
        Path(args.summary_out)
        if args.summary_out
        else outdir.parent / "smlta_refine_summary.txt"
    )

    if outdir.resolve() == icfg_dir.resolve():
        print(
            "[refine-smlta] ERROR: --outdir must differ from --icfg-dir; "
            "the original SVF ICFG is intentionally preserved",
            file=sys.stderr,
        )
        return 2

    required_files = [
        "icfg_nodes.tsv",
        "icfg_edges.tsv",
        "icfg_cfg_edges.tsv",
        "icfg_call_edges.tsv",
        "icfg_return_edges.tsv",
        "icfg_phi.tsv",
        "icfg_callsites.tsv",
        "icfg_functions.tsv",
    ]
    try:
        for name in required_files:
            if not (icfg_dir / name).exists():
                raise FileNotFoundError(icfg_dir / name)

        edge_header, edge_rows = read_tsv(icfg_dir / "icfg_edges.tsv")
        call_header, call_rows = read_tsv(icfg_dir / "icfg_call_edges.tsv")
        ret_header, ret_rows = read_tsv(icfg_dir / "icfg_return_edges.tsv")
        phi_header, phi_rows = read_tsv(icfg_dir / "icfg_phi.tsv")
        cs_header, callsite_rows = read_tsv(icfg_dir / "icfg_callsites.tsv")
        map_header, map_rows = read_tsv(smlta_map_path)

        require_columns(
            icfg_dir / "icfg_edges.tsv",
            edge_header,
            EDGE_HEADER,
        )
        require_columns(
            icfg_dir / "icfg_call_edges.tsv",
            call_header,
            CALL_HEADER,
        )
        require_columns(
            icfg_dir / "icfg_return_edges.tsv",
            ret_header,
            RETURN_HEADER,
        )
        require_columns(
            icfg_dir / "icfg_phi.tsv",
            phi_header,
            PHI_HEADER,
        )
        require_columns(
            icfg_dir / "icfg_callsites.tsv",
            cs_header,
            [
                "callsite_id",
                "callsite_node",
                "return_node",
                "caller_func",
                "call_kind",
            ],
        )
        require_columns(
            smlta_map_path,
            map_header,
            ["callsite_id", "target_func"],
        )

        func_index = load_function_index(
            icfg_dir / "icfg_functions.tsv",
            icfg_dir / "icfg_nodes.tsv",
        )
    except Exception as exc:
        print("[refine-smlta] ERROR: %s" % exc, file=sys.stderr)
        return 2

    # ------------------------------------------------------------------
    # Callsite metadata.
    # ------------------------------------------------------------------
    callsite_meta: Dict[str, Dict[str, str]] = {}
    for row in callsite_rows:
        cs = norm_text(row.get("callsite_id", ""))
        if not cs:
            continue
        old = callsite_meta.get(cs)
        if old is not None:
            # There should be one row per SVF callsite.
            if (
                norm_text(old.get("callsite_node", ""))
                != norm_text(row.get("callsite_node", ""))
            ):
                print(
                    "[refine-smlta] ERROR: duplicate callsite_id with different "
                    "callsite nodes: %s" % cs,
                    file=sys.stderr,
                )
                return 2
            continue
        callsite_meta[cs] = dict(row)

    # ------------------------------------------------------------------
    # SMLTA target map.
    # ------------------------------------------------------------------
    smlta_targets: Dict[str, Set[str]] = defaultdict(set)
    for row in map_rows:
        cs = norm_text(row.get("callsite_id", ""))
        target = norm_func(row.get("target_func", ""))
        if not cs or not target:
            print(
                "[refine-smlta] ERROR: smlta map contains an empty "
                "callsite_id/target_func",
                file=sys.stderr,
            )
            return 2
        smlta_targets[cs].add(target)

    for cs in sorted(smlta_targets, key=callsite_sort_key):
        meta = callsite_meta.get(cs)
        if meta is None:
            print(
                "[refine-smlta] ERROR: mapped callsite_id is absent from "
                "icfg_callsites.tsv: %s" % cs,
                file=sys.stderr,
            )
            return 2
        call_kind = norm_text(meta.get("call_kind", "")).lower()
        if call_kind != "indirect":
            print(
                "[refine-smlta] ERROR: SMLTA mapping refers to non-indirect "
                "callsite %s (call_kind=%s)" % (cs, call_kind or "<empty>"),
                file=sys.stderr,
            )
            return 2

    # Normalize callee/caller names in the working relation tables.
    for row in call_rows:
        row["caller_func"] = norm_func(row.get("caller_func", ""))
        row["callee_func"] = norm_func(row.get("callee_func", ""))
    for row in ret_rows:
        row["caller_func"] = norm_func(row.get("caller_func", ""))
        row["callee_func"] = norm_func(row.get("callee_func", ""))
    for row in phi_rows:
        row["caller_func"] = norm_func(row.get("caller_func", ""))
        row["callee_func"] = norm_func(row.get("callee_func", ""))

    calls_by_cs: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    rets_by_cs: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    phis_by_cs: Dict[str, List[Dict[str, str]]] = defaultdict(list)

    for row in call_rows:
        calls_by_cs[norm_text(row.get("callsite_id", ""))].append(row)
    for row in ret_rows:
        rets_by_cs[norm_text(row.get("callsite_id", ""))].append(row)
    for row in phi_rows:
        phis_by_cs[norm_text(row.get("callsite_id", ""))].append(row)

    original_targets: Dict[str, Set[str]] = defaultdict(set)
    for row in call_rows:
        cs = norm_text(row.get("callsite_id", ""))
        target = norm_func(row.get("callee_func", ""))
        if cs and target:
            original_targets[cs].add(target)

    # Preserve every original relation belonging to an unmapped callsite.
    refined_calls: List[Dict[str, str]] = [
        dict(row)
        for row in call_rows
        if norm_text(row.get("callsite_id", "")) not in smlta_targets
    ]
    refined_rets: List[Dict[str, str]] = [
        dict(row)
        for row in ret_rows
        if norm_text(row.get("callsite_id", "")) not in smlta_targets
    ]
    refined_phis: List[Dict[str, str]] = [
        dict(row)
        for row in phi_rows
        if norm_text(row.get("callsite_id", "")) not in smlta_targets
    ]

    added_pairs = 0
    removed_pairs = 0
    kept_pairs = 0

    # ------------------------------------------------------------------
    # Rebuild each mapped indirect callsite exactly to the SMLTA target set.
    # ------------------------------------------------------------------
    for cs in sorted(smlta_targets, key=callsite_sort_key):
        meta = callsite_meta[cs]
        wanted = set(smlta_targets[cs])
        old_targets = set(original_targets.get(cs, set()))

        callsite_node = norm_text(meta.get("callsite_node", ""))
        return_node = norm_text(meta.get("return_node", ""))
        caller_func = norm_func(meta.get("caller_func", ""))

        if not callsite_node:
            print(
                "[refine-smlta] ERROR: mapped callsite has no callsite_node: %s"
                % cs,
                file=sys.stderr,
            )
            return 2

        kept_pairs += len(old_targets & wanted)
        removed_pairs += len(old_targets - wanted)
        added_pairs += len(wanted - old_targets)

        for target in sorted(wanted):
            existing_calls = [
                row
                for row in calls_by_cs.get(cs, [])
                if norm_func(row.get("callee_func", "")) == target
            ]

            if target in old_targets:
                if len(existing_calls) != 1:
                    print(
                        "[refine-smlta] ERROR: expected exactly one original "
                        "call edge for %s -> %s, found %d"
                        % (cs, target, len(existing_calls)),
                        file=sys.stderr,
                    )
                    return 2

                # Reuse the exact SVF physical call relation.
                kept_call = dict(existing_calls[0])
                refined_calls.append(kept_call)

                # Reuse only return/phi relations belonging to this exact target.
                target_rets = [
                    dict(row)
                    for row in rets_by_cs.get(cs, [])
                    if norm_func(row.get("callee_func", "")) == target
                ]
                target_phis = [
                    dict(row)
                    for row in phis_by_cs.get(cs, [])
                    if norm_func(row.get("callee_func", "")) == target
                ]

                refined_rets.extend(target_rets)
                refined_phis.extend(target_phis)
                continue

            # New SMLTA target not present in the original SVF target set.
            try:
                entry_node, exit_node = get_unique_entry_exit(
                    func_index,
                    target,
                )
            except Exception as exc:
                print(
                    "[refine-smlta] ERROR: %s (callsite=%s)" % (exc, cs),
                    file=sys.stderr,
                )
                return 2

            if not return_node:
                print(
                    "[refine-smlta] ERROR: cannot add returning target %s to %s: "
                    "callsite has no structural return_node"
                    % (target, cs),
                    file=sys.stderr,
                )
                return 2

            refined_calls.append(
                {
                    "callsite_node": callsite_node,
                    "callee_entry_node": entry_node,
                    "caller_func": caller_func,
                    "callee_func": target,
                    "callsite_id": cs,
                }
            )
            refined_rets.append(
                {
                    "callee_exit_node": exit_node,
                    "return_node": return_node,
                    "caller_func": caller_func,
                    "callee_func": target,
                    "callsite_id": cs,
                }
            )
            refined_phis.append(
                {
                    "call_edge_src": callsite_node,
                    "call_edge_dst": entry_node,
                    "return_edge_src": exit_node,
                    "return_edge_dst": return_node,
                    "callsite_id": cs,
                    "caller_func": caller_func,
                    "callee_func": target,
                }
            )

    refined_calls = dedup_rows(refined_calls, CALL_HEADER)
    refined_rets = dedup_rows(refined_rets, RETURN_HEADER)
    refined_phis = dedup_rows(refined_phis, PHI_HEADER)

    refined_calls.sort(
        key=lambda r: (
            callsite_sort_key(r.get("callsite_id", "")),
            norm_func(r.get("callee_func", "")),
            r.get("callee_entry_node", ""),
        )
    )
    refined_rets.sort(
        key=lambda r: (
            callsite_sort_key(r.get("callsite_id", "")),
            norm_func(r.get("callee_func", "")),
            r.get("callee_exit_node", ""),
            r.get("return_node", ""),
        )
    )
    refined_phis.sort(
        key=lambda r: (
            callsite_sort_key(r.get("callsite_id", "")),
            norm_func(r.get("callee_func", "")),
            r.get("call_edge_dst", ""),
        )
    )

    # ------------------------------------------------------------------
    # Rebuild the integrated icfg_edges.tsv from:
    #   unchanged non-call/return edges
    #   + refined call table
    #   + refined return table
    #
    # This guarantees that the four interdependent files do not drift apart.
    # ------------------------------------------------------------------
    original_edge_label: Dict[Tuple[str, str, str, str], str] = {}
    non_interproc_edges: List[Dict[str, str]] = []
    for row in edge_rows:
        kind = norm_text(row.get("kind", ""))
        key = (
            norm_text(row.get("src", "")),
            norm_text(row.get("dst", "")),
            kind,
            norm_text(row.get("callsite_id", "")),
        )
        if key not in original_edge_label:
            original_edge_label[key] = norm_text(row.get("raw_label", ""))

        if kind not in ("call", "return"):
            non_interproc_edges.append(
                {name: norm_text(row.get(name, "")) for name in EDGE_HEADER}
            )

    refined_edges = list(non_interproc_edges)

    for row in refined_calls:
        key = (
            row["callsite_node"],
            row["callee_entry_node"],
            "call",
            row["callsite_id"],
        )
        raw = original_edge_label.get(key, "smlta-added-call")
        refined_edges.append(
            {
                "src": row["callsite_node"],
                "dst": row["callee_entry_node"],
                "kind": "call",
                "callsite_id": row["callsite_id"],
                "raw_label": raw,
            }
        )

    for row in refined_rets:
        key = (
            row["callee_exit_node"],
            row["return_node"],
            "return",
            row["callsite_id"],
        )
        raw = original_edge_label.get(key, "smlta-added-return")
        refined_edges.append(
            {
                "src": row["callee_exit_node"],
                "dst": row["return_node"],
                "kind": "return",
                "callsite_id": row["callsite_id"],
                "raw_label": raw,
            }
        )

    refined_edges = dedup_rows(refined_edges, EDGE_HEADER)

    # ------------------------------------------------------------------
    # Write the refined ICFG.
    # ------------------------------------------------------------------
    if outdir.exists():
        shutil.rmtree(str(outdir))
    outdir.mkdir(parents=True, exist_ok=True)

    # Unchanged normalized metadata.
    copy_names = [
        "icfg_nodes.tsv",
        "icfg_cfg_edges.tsv",
        "icfg_callsites.tsv",
        "icfg_functions.tsv",
        "icfg_callsite_pairs.tsv",
        "icfg_removed_summary_edges.tsv",
    ]
    for name in copy_names:
        src = icfg_dir / name
        if src.exists():
            shutil.copy2(str(src), str(outdir / name))

    write_dict_tsv(outdir / "icfg_edges.tsv", EDGE_HEADER, refined_edges)
    write_dict_tsv(outdir / "icfg_call_edges.tsv", CALL_HEADER, refined_calls)
    write_dict_tsv(outdir / "icfg_return_edges.tsv", RETURN_HEADER, refined_rets)
    write_dict_tsv(outdir / "icfg_phi.tsv", PHI_HEADER, refined_phis)

    # ------------------------------------------------------------------
    # Per-callsite diff.  Keep it focused on indirect callsites because
    # SMLTA does not refine direct calls.
    # ------------------------------------------------------------------
    refined_targets: Dict[str, Set[str]] = defaultdict(set)
    for row in refined_calls:
        cs = norm_text(row.get("callsite_id", ""))
        target = norm_func(row.get("callee_func", ""))
        if cs and target:
            refined_targets[cs].add(target)

    diff_header = [
        "callsite_id",
        "caller_func",
        "call_kind",
        "mapping_status",
        "svf_targets",
        "smlta_targets",
        "refined_targets",
        "kept_targets",
        "removed_targets",
        "added_targets",
        "svf_target_count",
        "smlta_target_count",
        "refined_target_count",
    ]
    diff_rows: List[List[object]] = []

    indirect_callsites = [
        (cs, meta)
        for cs, meta in callsite_meta.items()
        if norm_text(meta.get("call_kind", "")).lower() == "indirect"
    ]
    indirect_callsites.sort(key=lambda item: callsite_sort_key(item[0]))

    for cs, meta in indirect_callsites:
        svf = set(original_targets.get(cs, set()))
        smlta = set(smlta_targets.get(cs, set()))
        refined = set(refined_targets.get(cs, set()))

        if cs in smlta_targets:
            status = "mapped-refined"
            kept = svf & smlta
            removed = svf - smlta
            added = smlta - svf
        else:
            status = "unmapped-kept"
            kept = svf
            removed = set()
            added = set()

        diff_rows.append(
            [
                cs,
                norm_func(meta.get("caller_func", "")),
                "indirect",
                status,
                ",".join(sorted(svf)),
                ",".join(sorted(smlta)),
                ",".join(sorted(refined)),
                ",".join(sorted(kept)),
                ",".join(sorted(removed)),
                ",".join(sorted(added)),
                len(svf),
                len(smlta),
                len(refined),
            ]
        )

    write_rows_tsv(diff_path, diff_header, diff_rows)

    # ------------------------------------------------------------------
    # Summary.
    # ------------------------------------------------------------------
    mapped_callsites = set(smlta_targets)
    mapped_svf_pairs = sum(
        len(original_targets.get(cs, set())) for cs in mapped_callsites
    )
    mapped_smlta_pairs = sum(len(v) for v in smlta_targets.values())

    summary_lines = [
        "SMLTA ICFG refinement summary",
        "============================",
        "policy: mapped indirect callsites use exactly the SMLTA target set",
        "policy_unmapped: preserve original SVF call/return/phi relations",
        "original_icfg_dir: %s" % icfg_dir,
        "smlta_map: %s" % smlta_map_path,
        "refined_icfg_dir: %s" % outdir,
        "mapped_callsites: %d" % len(mapped_callsites),
        "mapped_svf_target_pairs: %d" % mapped_svf_pairs,
        "mapped_smlta_target_pairs: %d" % mapped_smlta_pairs,
        "kept_targets: %d" % kept_pairs,
        "removed_targets: %d" % removed_pairs,
        "added_targets: %d" % added_pairs,
        "original_call_edges: %d" % len(call_rows),
        "refined_call_edges: %d" % len(refined_calls),
        "original_return_edges: %d" % len(ret_rows),
        "refined_return_edges: %d" % len(refined_rets),
        "original_phi_rows: %d" % len(phi_rows),
        "refined_phi_rows: %d" % len(refined_phis),
        "note: icfg_cross_product.tsv is not copied because its legacy SVF "
        "diagnostic would be stale after refinement",
        "diff: %s" % diff_path,
    ]
    summary_text = "\n".join(summary_lines) + "\n"

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(summary_text, encoding="utf-8")
    (outdir / "icfg_summary.txt").write_text(summary_text, encoding="utf-8")

    print(
        "[refine-smlta] mapped_callsites=%d kept=%d removed=%d added=%d"
        % (
            len(mapped_callsites),
            kept_pairs,
            removed_pairs,
            added_pairs,
        ),
        file=sys.stderr,
    )
    print("[refine-smlta] refined ICFG: %s" % outdir, file=sys.stderr)
    print("[refine-smlta] diff: %s" % diff_path, file=sys.stderr)
    print("[refine-smlta] summary: %s" % summary_path, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
