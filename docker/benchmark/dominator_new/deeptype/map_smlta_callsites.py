#!/usr/bin/env python3
"""
map_smlta_callsites_v2.py - Phase 6 mapping + source-location diagnostics

Production mapping remains conservative and uses the original stable key:

    caller_func + src_file + src_line + src_col + call_ordinal

This v2 additionally compares SVF and DeepType by a diagnostic identity:

    caller_func + func_indirect_ordinal

The diagnostic identity is NOT used to refine the ICFG.  It exists only to
answer whether the two tools appear to refer to the same function-wide
indirect call while reporting different source locations.

Inputs
------
icfg_callsites.tsv
    callsite_id, callsite_node, return_node, caller_func, bb,
    call_kind, direct_callee, src_file, src_line, src_col,
    call_ordinal, func_indirect_ordinal, ir

deeptype_targets.tsv
    caller_func, src_file, src_line, src_col, call_ordinal,
    func_indirect_ordinal, target_func, call_ir

Outputs
-------
smlta_callsite_map.tsv
    callsite_id, target_func

smlta_unmatched_targets.tsv
    unmatched DeepType target rows

smlta_callsite_location_debug.tsv
    caller/function-wide-ordinal comparison of SVF vs DeepType location and IR

Important policy
----------------
Only exact production stable-key matches enter smlta_callsite_map.tsv.
Diagnostic matches never authorize Phase-7 edge removal/refinement.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple


StableKey = Tuple[str, str, str, str, str]
DiagnosticKey = Tuple[str, str]


def norm_text(value: str) -> str:
    return (value or "").strip()


def norm_func(value: str) -> str:
    value = norm_text(value).strip('"')
    if value.startswith("@"):
        value = value[1:]
    return value


def norm_src_file(value: str) -> str:
    value = norm_text(value).replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    return value


def norm_integer_text(value: str) -> str:
    value = norm_text(value)
    if not value:
        return ""
    try:
        return str(int(value, 10))
    except ValueError:
        return value


def norm_ir(value: str) -> str:
    """Normalize IR only for diagnostics; never use it as production identity."""
    s = norm_text(value).replace("\\n", " ").replace("\\t", " ")
    # Both exporters can print LLVM metadata after the call instruction.
    s = re.sub(r",\s*!dbg\s*!\d+", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def stable_key(row: Dict[str, str]) -> StableKey:
    return (
        norm_func(row.get("caller_func", "")),
        norm_src_file(row.get("src_file", "")),
        norm_integer_text(row.get("src_line", "")),
        norm_integer_text(row.get("src_col", "")),
        norm_integer_text(row.get("call_ordinal", "")),
    )


def key_is_resolved(key: StableKey) -> bool:
    caller, src_file, src_line, _src_col, ordinal = key
    # LLVM debug column 0 is valid.
    return bool(caller and src_file and src_line and ordinal != "")


def diagnostic_key(row: Dict[str, str]) -> DiagnosticKey:
    return (
        norm_func(row.get("caller_func", "")),
        norm_integer_text(row.get("func_indirect_ordinal", "")),
    )


def diagnostic_key_is_resolved(key: DiagnosticKey) -> bool:
    caller, ordinal = key
    return bool(caller and ordinal != "")


def read_tsv(path: Path) -> Tuple[List[str], List[Dict[str, str]]]:
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        if reader.fieldnames is None:
            raise RuntimeError(f"TSV has no header: {path}")
        return list(reader.fieldnames), list(reader)


def require_columns(path: Path, header: Sequence[str], required: Iterable[str]) -> None:
    missing = [name for name in required if name not in header]
    if missing:
        raise RuntimeError(
            f"missing required column(s) in {path}: {', '.join(missing)}"
        )


def write_tsv(path: Path, header: Sequence[str], rows: Iterable[Sequence[object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, delimiter="\t", lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)


def callsite_sort_key(callsite_id: str) -> Tuple[int, str]:
    s = norm_text(callsite_id)
    if s.startswith("cs"):
        try:
            return int(s[2:]), s
        except ValueError:
            pass
    return 10**18, s


def key_to_fields(key: StableKey) -> Tuple[str, str, str, str, str]:
    return key


def location_tuple(row: Dict[str, str]) -> Tuple[str, str, str]:
    return (
        norm_src_file(row.get("src_file", "")),
        norm_integer_text(row.get("src_line", "")),
        norm_integer_text(row.get("src_col", "")),
    )


def diagnostic_signature(row: Dict[str, str], ir_field: str) -> Tuple[str, str, str, str, str]:
    return (
        *location_tuple(row),
        norm_integer_text(row.get("call_ordinal", "")),
        norm_ir(row.get(ir_field, "")),
    )


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--icfg-callsites", required=True, help="Phase-6-v2 icfg_callsites.tsv")
    ap.add_argument("--deeptype-targets", required=True, help="DeepType v4 deeptype_targets.tsv")
    ap.add_argument("--out", required=True, help="output smlta_callsite_map.tsv")
    ap.add_argument(
        "--unmatched-out",
        help="optional unmatched DeepType rows TSV; default: sibling smlta_unmatched_targets.tsv",
    )
    ap.add_argument(
        "--summary-out",
        help="optional text summary; default: sibling smlta_callsite_map_summary.txt",
    )
    ap.add_argument(
        "--debug-out",
        help="optional SVF/DeepType callsite diagnostic TSV; default: sibling smlta_callsite_location_debug.tsv",
    )
    ap.add_argument(
        "--strict-unmatched",
        action="store_true",
        help="return non-zero when any DeepType target row cannot be mapped",
    )
    args = ap.parse_args(argv)

    icfg_path = Path(args.icfg_callsites)
    deeptype_path = Path(args.deeptype_targets)
    out_path = Path(args.out)
    unmatched_path = (
        Path(args.unmatched_out)
        if args.unmatched_out
        else out_path.with_name("smlta_unmatched_targets.tsv")
    )
    summary_path = (
        Path(args.summary_out)
        if args.summary_out
        else out_path.with_name("smlta_callsite_map_summary.txt")
    )
    debug_path = (
        Path(args.debug_out)
        if args.debug_out
        else out_path.with_name("smlta_callsite_location_debug.tsv")
    )

    try:
        icfg_header, icfg_rows = read_tsv(icfg_path)
        dt_header, dt_rows = read_tsv(deeptype_path)

        require_columns(
            icfg_path,
            icfg_header,
            [
                "callsite_id",
                "caller_func",
                "call_kind",
                "src_file",
                "src_line",
                "src_col",
                "call_ordinal",
                "func_indirect_ordinal",
                "ir",
            ],
        )
        require_columns(
            deeptype_path,
            dt_header,
            [
                "caller_func",
                "src_file",
                "src_line",
                "src_col",
                "call_ordinal",
                "func_indirect_ordinal",
                "target_func",
                "call_ir",
            ],
        )
    except Exception as exc:
        print(f"[map-smlta-v2] ERROR: {exc}", file=sys.stderr)
        return 2

    indirect_rows = [
        row
        for row in icfg_rows
        if norm_text(row.get("call_kind", "")).lower() == "indirect"
    ]

    # ------------------------------------------------------------------
    # Production stable-key mapping. This behavior remains conservative.
    # ------------------------------------------------------------------
    svf_index: Dict[StableKey, str] = {}
    unresolved_svf: List[Tuple[str, StableKey]] = []
    duplicate_keys: Dict[StableKey, List[str]] = {}

    for row in indirect_rows:
        cs = norm_text(row.get("callsite_id", ""))
        key = stable_key(row)

        if not cs:
            print(
                "[map-smlta-v2] ERROR: indirect SVF row has empty callsite_id",
                file=sys.stderr,
            )
            return 2

        if not key_is_resolved(key):
            unresolved_svf.append((cs, key))
            continue

        old = svf_index.get(key)
        if old is None:
            svf_index[key] = cs
        elif old != cs:
            duplicate_keys.setdefault(key, [old]).append(cs)

    if duplicate_keys:
        print(
            "[map-smlta-v2] ERROR: ambiguous SVF stable key(s); refusing to guess",
            file=sys.stderr,
        )
        for key, callsites in sorted(duplicate_keys.items()):
            print(
                "[map-smlta-v2]   key="
                + "|".join(key)
                + " callsites="
                + ",".join(sorted(set(callsites), key=callsite_sort_key)),
                file=sys.stderr,
            )
        return 2

    mapped_pairs = set()
    matched_dt_rows = 0
    unmatched_rows: List[Tuple[str, str, str, str, str, str, str, str, str]] = []
    unmatched_reasons = Counter()

    for row in dt_rows:
        target = norm_func(row.get("target_func", ""))
        key = stable_key(row)
        func_ord = norm_integer_text(row.get("func_indirect_ordinal", ""))
        call_ir = norm_text(row.get("call_ir", ""))

        if not target:
            reason = "empty_target_func"
        elif not key_is_resolved(key):
            reason = "unresolved_stable_key"
        else:
            cs = svf_index.get(key)
            if cs is None:
                reason = "no_svf_callsite"
            else:
                matched_dt_rows += 1
                mapped_pairs.add((cs, target))
                continue

        unmatched_reasons[reason] += 1
        unmatched_rows.append(
            (*key_to_fields(key), func_ord, target, call_ir, reason)
        )

    mapped_rows = sorted(
        mapped_pairs,
        key=lambda item: (callsite_sort_key(item[0]), item[1]),
    )

    write_tsv(out_path, ["callsite_id", "target_func"], mapped_rows)
    write_tsv(
        unmatched_path,
        [
            "caller_func",
            "src_file",
            "src_line",
            "src_col",
            "call_ordinal",
            "func_indirect_ordinal",
            "target_func",
            "call_ir",
            "reason",
        ],
        unmatched_rows,
    )

    # ------------------------------------------------------------------
    # Diagnostic mapping by caller + function-wide indirect ordinal.
    # This never contributes to smlta_callsite_map.tsv.
    # ------------------------------------------------------------------
    svf_diag: Dict[DiagnosticKey, List[Dict[str, str]]] = defaultdict(list)
    unresolved_svf_diag = 0
    for row in indirect_rows:
        key = diagnostic_key(row)
        if not diagnostic_key_is_resolved(key):
            unresolved_svf_diag += 1
            continue
        svf_diag[key].append(row)

    dt_diag: Dict[DiagnosticKey, List[Dict[str, str]]] = defaultdict(list)
    unresolved_dt_diag_rows = 0
    for row in dt_rows:
        key = diagnostic_key(row)
        if not diagnostic_key_is_resolved(key):
            unresolved_dt_diag_rows += 1
            continue
        dt_diag[key].append(row)

    debug_rows: List[List[object]] = []
    diagnostic_counts = Counter()

    for key in sorted(dt_diag):
        caller, func_ord = key
        dt_group = dt_diag[key]
        dt_variants = {
            diagnostic_signature(row, "call_ir")
            for row in dt_group
        }

        svf_group = svf_diag.get(key, [])

        if not svf_group:
            diagnostic_counts["no_svf_diagnostic_key"] += 1
            sample = dt_group[0]
            debug_rows.append(
                [
                    caller,
                    func_ord,
                    "",
                    "",
                    "",
                    "",
                    "",
                    norm_src_file(sample.get("src_file", "")),
                    norm_integer_text(sample.get("src_line", "")),
                    norm_integer_text(sample.get("src_col", "")),
                    norm_integer_text(sample.get("call_ordinal", "")),
                    "",
                    "",
                    "",
                    norm_text(sample.get("call_ir", "")),
                    "no_svf_diagnostic_key",
                ]
            )
            continue

        if len(svf_group) != 1:
            diagnostic_counts["ambiguous_svf_diagnostic_key"] += 1
            sample = dt_group[0]
            debug_rows.append(
                [
                    caller,
                    func_ord,
                    ",".join(
                        sorted(
                            {
                                norm_text(x.get("callsite_id", ""))
                                for x in svf_group
                            },
                            key=callsite_sort_key,
                        )
                    ),
                    "",
                    "",
                    "",
                    "",
                    norm_src_file(sample.get("src_file", "")),
                    norm_integer_text(sample.get("src_line", "")),
                    norm_integer_text(sample.get("src_col", "")),
                    norm_integer_text(sample.get("call_ordinal", "")),
                    "",
                    "",
                    "",
                    norm_text(sample.get("call_ir", "")),
                    "ambiguous_svf_diagnostic_key",
                ]
            )
            continue

        if len(dt_variants) != 1:
            diagnostic_counts["ambiguous_deeptype_diagnostic_key"] += 1
            svf = svf_group[0]
            debug_rows.append(
                [
                    caller,
                    func_ord,
                    norm_text(svf.get("callsite_id", "")),
                    norm_src_file(svf.get("src_file", "")),
                    norm_integer_text(svf.get("src_line", "")),
                    norm_integer_text(svf.get("src_col", "")),
                    norm_integer_text(svf.get("call_ordinal", "")),
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    norm_text(svf.get("ir", "")),
                    "",
                    "ambiguous_deeptype_diagnostic_key",
                ]
            )
            continue

        svf = svf_group[0]
        dt = dt_group[0]

        same_location = location_tuple(svf) == location_tuple(dt)
        same_ir = bool(norm_ir(svf.get("ir", ""))) and (
            norm_ir(svf.get("ir", "")) == norm_ir(dt.get("call_ir", ""))
        )

        if same_location:
            diagnostic_counts["location_match"] += 1
        else:
            diagnostic_counts["location_mismatch"] += 1

        if same_ir:
            diagnostic_counts["ir_match"] += 1
        else:
            diagnostic_counts["ir_mismatch"] += 1

        if same_location and same_ir:
            status = "same_callsite_same_location_ir"
        elif (not same_location) and same_ir:
            status = "same_ordinal_same_ir_different_location"
        elif same_location and (not same_ir):
            status = "same_ordinal_same_location_different_ir"
        else:
            status = "same_ordinal_different_location_and_ir"

        diagnostic_counts[status] += 1

        debug_rows.append(
            [
                caller,
                func_ord,
                norm_text(svf.get("callsite_id", "")),
                norm_src_file(svf.get("src_file", "")),
                norm_integer_text(svf.get("src_line", "")),
                norm_integer_text(svf.get("src_col", "")),
                norm_integer_text(svf.get("call_ordinal", "")),
                norm_src_file(dt.get("src_file", "")),
                norm_integer_text(dt.get("src_line", "")),
                norm_integer_text(dt.get("src_col", "")),
                norm_integer_text(dt.get("call_ordinal", "")),
                "yes" if same_location else "no",
                "yes" if same_ir else "no",
                norm_text(svf.get("ir", "")),
                norm_text(dt.get("call_ir", "")),
                status,
            ]
        )

    write_tsv(
        debug_path,
        [
            "caller_func",
            "func_indirect_ordinal",
            "svf_callsite_id",
            "svf_src_file",
            "svf_src_line",
            "svf_src_col",
            "svf_call_ordinal",
            "deeptype_src_file",
            "deeptype_src_line",
            "deeptype_src_col",
            "deeptype_call_ordinal",
            "same_location",
            "same_ir",
            "svf_ir",
            "deeptype_call_ir",
            "status",
        ],
        debug_rows,
    )

    # Count unique DeepType callsites independently from target-row count.
    dt_unique_stable_keys = {
        stable_key(row)
        for row in dt_rows
        if key_is_resolved(stable_key(row))
    }
    dt_unique_diag_keys = {
        diagnostic_key(row)
        for row in dt_rows
        if diagnostic_key_is_resolved(diagnostic_key(row))
    }

    mapped_callsites = {cs for cs, _target in mapped_rows}
    summary_lines = [
        "SMLTA callsite mapping summary (v2)",
        "==================================",
        f"icfg_callsites: {icfg_path}",
        f"deeptype_targets: {deeptype_path}",
        f"output: {out_path}",
        f"debug_output: {debug_path}",
        f"svf_total_callsites: {len(icfg_rows)}",
        f"svf_indirect_callsites: {len(indirect_rows)}",
        f"svf_indirect_resolved_keys: {len(svf_index)}",
        f"svf_indirect_unresolved_keys: {len(unresolved_svf)}",
        f"svf_indirect_resolved_diagnostic_keys: {len(svf_diag)}",
        f"svf_indirect_unresolved_diagnostic_keys: {unresolved_svf_diag}",
        f"deeptype_target_rows: {len(dt_rows)}",
        f"deeptype_unique_stable_callsites: {len(dt_unique_stable_keys)}",
        f"deeptype_unique_diagnostic_callsites: {len(dt_unique_diag_keys)}",
        f"deeptype_unresolved_diagnostic_rows: {unresolved_dt_diag_rows}",
        f"deeptype_rows_mapped: {matched_dt_rows}",
        f"deeptype_rows_unmatched: {len(unmatched_rows)}",
        f"mapped_callsites: {len(mapped_callsites)}",
        f"mapped_callsite_target_pairs: {len(mapped_rows)}",
        "stable_key: caller_func+src_file+src_line+src_col+call_ordinal",
        "diagnostic_key: caller_func+func_indirect_ordinal",
        "call_ordinal: zero-based among indirect calls with the same caller/source location",
        "func_indirect_ordinal: zero-based among all indirect calls in one caller function",
        "policy: diagnostic matches never refine the ICFG; only exact stable-key matches do",
        "policy: unmapped callsites must retain their original SVF edges in Phase 7",
    ]

    for reason, count in sorted(unmatched_reasons.items()):
        summary_lines.append(f"unmatched_{reason}: {count}")
    for name, count in sorted(diagnostic_counts.items()):
        summary_lines.append(f"diagnostic_{name}: {count}")

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

    print(
        f"[map-smlta-v2] mapped {len(mapped_rows)} target pair(s) across "
        f"{len(mapped_callsites)} SVF callsite(s); unmatched DeepType rows="
        f"{len(unmatched_rows)}",
        file=sys.stderr,
    )
    print(
        f"[map-smlta-v2] diagnostic unique DeepType callsites="
        f"{len(dt_unique_diag_keys)} location_mismatch="
        f"{diagnostic_counts.get('location_mismatch', 0)}",
        file=sys.stderr,
    )
    print(f"[map-smlta-v2] output: {out_path}", file=sys.stderr)
    print(f"[map-smlta-v2] summary: {summary_path}", file=sys.stderr)
    print(f"[map-smlta-v2] unmatched: {unmatched_path}", file=sys.stderr)
    print(f"[map-smlta-v2] debug: {debug_path}", file=sys.stderr)

    if args.strict_unmatched and unmatched_rows:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
