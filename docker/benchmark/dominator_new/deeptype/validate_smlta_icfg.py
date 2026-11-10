#!/usr/bin/env python3
"""
validate_smlta_icfg.py - Phase 8

Validate a Phase-7 SMLTA-refined normalized ICFG against:
  * the original Phase-6 SVF normalized ICFG, and
  * smlta_callsite_map.tsv.

Checks include:
  - mapped SMLTA callsite count
  - mapping failure count
  - original SVF / SMLTA / refined target counts
  - added and removed targets
  - zero-target callsites
  - synchronized icfg_edges.tsv vs explicit call/return tables
  - call/return/phi consistency
  - missing / duplicate phi relations
  - caller/callee mismatches
  - unknown edge endpoint nodes
  - unmapped-callsite mutation
  - mapped target reachability from program entry

Fatal structural/semantic errors return status 1.
Reachability failures and unmatched DeepType rows are reported as warnings
because they can describe dead/unreachable static code rather than corruption
of the refined ICFG itself.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter, defaultdict, deque
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


def norm_text(value: object) -> str:
    return str(value if value is not None else "").strip()


def norm_func(value: object) -> str:
    s = norm_text(value).strip('"')
    if s.startswith("@"):
        s = s[1:]
    return s


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


def load_icfg(icfg_dir: Path) -> Dict[str, object]:
    names = {
        "nodes": "icfg_nodes.tsv",
        "edges": "icfg_edges.tsv",
        "calls": "icfg_call_edges.tsv",
        "returns": "icfg_return_edges.tsv",
        "phi": "icfg_phi.tsv",
        "callsites": "icfg_callsites.tsv",
        "functions": "icfg_functions.tsv",
    }

    data: Dict[str, object] = {}
    headers: Dict[str, List[str]] = {}

    for key, name in names.items():
        header, rows = read_tsv(icfg_dir / name)
        headers[key] = header
        data[key] = rows

    require_columns(
        icfg_dir / names["nodes"],
        headers["nodes"],
        ["node_id", "function", "kind"],
    )
    require_columns(
        icfg_dir / names["edges"],
        headers["edges"],
        ["src", "dst", "kind", "callsite_id"],
    )
    require_columns(
        icfg_dir / names["calls"],
        headers["calls"],
        [
            "callsite_node",
            "callee_entry_node",
            "caller_func",
            "callee_func",
            "callsite_id",
        ],
    )
    require_columns(
        icfg_dir / names["returns"],
        headers["returns"],
        [
            "callee_exit_node",
            "return_node",
            "caller_func",
            "callee_func",
            "callsite_id",
        ],
    )
    require_columns(
        icfg_dir / names["phi"],
        headers["phi"],
        [
            "call_edge_src",
            "call_edge_dst",
            "return_edge_src",
            "return_edge_dst",
            "callsite_id",
            "caller_func",
            "callee_func",
        ],
    )
    require_columns(
        icfg_dir / names["callsites"],
        headers["callsites"],
        [
            "callsite_id",
            "callsite_node",
            "return_node",
            "caller_func",
            "call_kind",
        ],
    )
    require_columns(
        icfg_dir / names["functions"],
        headers["functions"],
        ["function", "entry_nodes", "exit_nodes"],
    )

    return data


def split_nodes(value: object) -> List[str]:
    return [x.strip() for x in norm_text(value).split(",") if x.strip()]


def build_targets(call_rows: List[Dict[str, str]]) -> Dict[str, Set[str]]:
    result: Dict[str, Set[str]] = defaultdict(set)
    for row in call_rows:
        cs = norm_text(row.get("callsite_id", ""))
        target = norm_func(row.get("callee_func", ""))
        if cs and target:
            result[cs].add(target)
    return result


def build_callsite_meta(
    rows: List[Dict[str, str]],
) -> Dict[str, Dict[str, str]]:
    result: Dict[str, Dict[str, str]] = {}
    for row in rows:
        cs = norm_text(row.get("callsite_id", ""))
        if cs and cs not in result:
            result[cs] = row
    return result


def build_roots(
    data: Dict[str, object],
    entry_function: str,
) -> List[str]:
    function_rows = data["functions"]  # type: ignore[assignment]
    for row in function_rows:  # type: ignore[union-attr]
        if norm_func(row.get("function", "")) != entry_function:
            continue
        entries = split_nodes(row.get("entry_nodes", ""))
        if entries:
            return entries

    # Fallback compatible with extract_dominator.py's conservative root idea.
    node_rows = data["nodes"]  # type: ignore[assignment]
    edge_rows = data["edges"]  # type: ignore[assignment]
    nodes = {
        norm_text(row.get("node_id", ""))
        for row in node_rows  # type: ignore[union-attr]
        if norm_text(row.get("node_id", ""))
    }
    incoming_non_return: Set[str] = set()
    for row in edge_rows:  # type: ignore[union-attr]
        if norm_text(row.get("kind", "")) != "return":
            dst = norm_text(row.get("dst", ""))
            if dst:
                incoming_non_return.add(dst)
    roots = sorted(nodes - incoming_non_return)
    return roots[:1]


def reachable_nodes(
    data: Dict[str, object],
    roots: Sequence[str],
) -> Set[str]:
    adjacency: Dict[str, List[str]] = defaultdict(list)
    edge_rows = data["edges"]  # type: ignore[assignment]
    for row in edge_rows:  # type: ignore[union-attr]
        src = norm_text(row.get("src", ""))
        dst = norm_text(row.get("dst", ""))
        if src and dst:
            adjacency[src].append(dst)

    seen: Set[str] = set()
    q = deque([r for r in roots if r])
    while q:
        cur = q.popleft()
        if cur in seen:
            continue
        seen.add(cur)
        for nxt in adjacency.get(cur, []):
            if nxt not in seen:
                q.append(nxt)
    return seen


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--original-icfg-dir", required=True)
    ap.add_argument("--refined-icfg-dir", required=True)
    ap.add_argument("--smlta-map", required=True)
    ap.add_argument(
        "--unmatched",
        help="optional smlta_unmatched_targets.tsv from Phase 6",
    )
    ap.add_argument("--report", required=True)
    ap.add_argument("--details", required=True)
    ap.add_argument("--entry-function", default="main")
    args = ap.parse_args(argv)

    original_dir = Path(args.original_icfg_dir)
    refined_dir = Path(args.refined_icfg_dir)
    smlta_map_path = Path(args.smlta_map)
    report_path = Path(args.report)
    details_path = Path(args.details)

    try:
        original = load_icfg(original_dir)
        refined = load_icfg(refined_dir)
        map_header, map_rows = read_tsv(smlta_map_path)
        require_columns(
            smlta_map_path,
            map_header,
            ["callsite_id", "target_func"],
        )
    except Exception as exc:
        print("[validate-smlta] ERROR: %s" % exc, file=sys.stderr)
        return 2

    original_calls: List[Dict[str, str]] = original["calls"]  # type: ignore[assignment]
    refined_calls: List[Dict[str, str]] = refined["calls"]  # type: ignore[assignment]
    original_rets: List[Dict[str, str]] = original["returns"]  # type: ignore[assignment]
    refined_rets: List[Dict[str, str]] = refined["returns"]  # type: ignore[assignment]
    refined_phi: List[Dict[str, str]] = refined["phi"]  # type: ignore[assignment]
    refined_edges: List[Dict[str, str]] = refined["edges"]  # type: ignore[assignment]
    refined_nodes_rows: List[Dict[str, str]] = refined["nodes"]  # type: ignore[assignment]
    original_callsites: List[Dict[str, str]] = original["callsites"]  # type: ignore[assignment]
    refined_callsites: List[Dict[str, str]] = refined["callsites"]  # type: ignore[assignment]

    original_targets = build_targets(original_calls)
    refined_targets = build_targets(refined_calls)
    original_meta = build_callsite_meta(original_callsites)
    refined_meta = build_callsite_meta(refined_callsites)

    smlta_targets: Dict[str, Set[str]] = defaultdict(set)
    malformed_map_rows = 0
    for row in map_rows:
        cs = norm_text(row.get("callsite_id", ""))
        target = norm_func(row.get("target_func", ""))
        if not cs or not target:
            malformed_map_rows += 1
            continue
        smlta_targets[cs].add(target)

    fatal: List[str] = []
    warnings: List[str] = []
    pair_errors_by_cs: Dict[str, List[str]] = defaultdict(list)

    if malformed_map_rows:
        fatal.append(
            "smlta map contains %d malformed empty callsite/target row(s)"
            % malformed_map_rows
        )

    # Mapping failures emitted by Phase 6.
    mapping_failures = 0
    if args.unmatched:
        unmatched_path = Path(args.unmatched)
        if unmatched_path.exists():
            try:
                _h, unmatched_rows = read_tsv(unmatched_path)
                mapping_failures = len(unmatched_rows)
                if mapping_failures:
                    warnings.append(
                        "%d DeepType target row(s) were unmatched in Phase 6"
                        % mapping_failures
                    )
            except Exception as exc:
                fatal.append("failed to read unmatched mapping report: %s" % exc)
        else:
            warnings.append(
                "unmatched mapping report was not found: %s" % unmatched_path
            )

    # ------------------------------------------------------------------
    # Semantic target-set checks.
    # ------------------------------------------------------------------
    all_original_cs = set(original_meta)
    all_refined_cs = set(refined_meta)

    if all_original_cs != all_refined_cs:
        missing = sorted(all_original_cs - all_refined_cs, key=callsite_sort_key)
        added = sorted(all_refined_cs - all_original_cs, key=callsite_sort_key)
        if missing:
            fatal.append(
                "refined icfg_callsites.tsv lost callsite(s): %s"
                % ",".join(missing)
            )
        if added:
            fatal.append(
                "refined icfg_callsites.tsv unexpectedly added callsite(s): %s"
                % ",".join(added)
            )

    for cs in sorted(smlta_targets, key=callsite_sort_key):
        meta = original_meta.get(cs)
        if meta is None:
            fatal.append("SMLTA map references unknown callsite: %s" % cs)
            continue
        kind = norm_text(meta.get("call_kind", "")).lower()
        if kind != "indirect":
            fatal.append(
                "SMLTA map references non-indirect callsite %s (kind=%s)"
                % (cs, kind or "<empty>")
            )
            continue

        expected = smlta_targets[cs]
        actual = refined_targets.get(cs, set())
        if actual != expected:
            fatal.append(
                "mapped callsite %s target mismatch: SMLTA={%s} refined={%s}"
                % (
                    cs,
                    ",".join(sorted(expected)),
                    ",".join(sorted(actual)),
                )
            )

    # Unmapped callsites, including direct/unknown calls, must be unchanged.
    for cs in sorted(all_original_cs, key=callsite_sort_key):
        if cs in smlta_targets:
            continue
        old = original_targets.get(cs, set())
        new = refined_targets.get(cs, set())
        if old != new:
            fatal.append(
                "unmapped callsite mutated: %s SVF={%s} refined={%s}"
                % (
                    cs,
                    ",".join(sorted(old)),
                    ",".join(sorted(new)),
                )
            )

    zero_target_callsites: List[str] = []
    for cs in sorted(all_original_cs, key=callsite_sort_key):
        if original_targets.get(cs) and not refined_targets.get(cs):
            zero_target_callsites.append(cs)
            fatal.append(
                "callsite became zero-target after refinement: %s" % cs
            )

    # ------------------------------------------------------------------
    # Integrated-edge <-> explicit table synchronization.
    # ------------------------------------------------------------------
    integrated_calls = {
        (
            norm_text(r.get("src", "")),
            norm_text(r.get("dst", "")),
            norm_text(r.get("callsite_id", "")),
        )
        for r in refined_edges
        if norm_text(r.get("kind", "")) == "call"
    }
    table_calls = {
        (
            norm_text(r.get("callsite_node", "")),
            norm_text(r.get("callee_entry_node", "")),
            norm_text(r.get("callsite_id", "")),
        )
        for r in refined_calls
    }

    integrated_rets = {
        (
            norm_text(r.get("src", "")),
            norm_text(r.get("dst", "")),
            norm_text(r.get("callsite_id", "")),
        )
        for r in refined_edges
        if norm_text(r.get("kind", "")) == "return"
    }
    table_rets = {
        (
            norm_text(r.get("callee_exit_node", "")),
            norm_text(r.get("return_node", "")),
            norm_text(r.get("callsite_id", "")),
        )
        for r in refined_rets
    }

    missing_integrated_calls = table_calls - integrated_calls
    extra_integrated_calls = integrated_calls - table_calls
    missing_integrated_rets = table_rets - integrated_rets
    extra_integrated_rets = integrated_rets - table_rets

    for item in sorted(missing_integrated_calls):
        fatal.append(
            "icfg_call_edges.tsv edge missing from icfg_edges.tsv: %s->%s cs=%s"
            % item
        )
    for item in sorted(extra_integrated_calls):
        fatal.append(
            "icfg_edges.tsv call missing from icfg_call_edges.tsv: %s->%s cs=%s"
            % item
        )
    for item in sorted(missing_integrated_rets):
        fatal.append(
            "icfg_return_edges.tsv edge missing from icfg_edges.tsv: %s->%s cs=%s"
            % item
        )
    for item in sorted(extra_integrated_rets):
        fatal.append(
            "icfg_edges.tsv return missing from icfg_return_edges.tsv: %s->%s cs=%s"
            % item
        )

    # ------------------------------------------------------------------
    # Unknown node endpoints.
    # ------------------------------------------------------------------
    node_ids = {
        norm_text(row.get("node_id", ""))
        for row in refined_nodes_rows
        if norm_text(row.get("node_id", ""))
    }
    unknown_node_edges = 0
    for row in refined_edges:
        src = norm_text(row.get("src", ""))
        dst = norm_text(row.get("dst", ""))
        if src not in node_ids or dst not in node_ids:
            unknown_node_edges += 1
            fatal.append(
                "edge references unknown node: %s -> %s kind=%s cs=%s"
                % (
                    src,
                    dst,
                    norm_text(row.get("kind", "")),
                    norm_text(row.get("callsite_id", "")),
                )
            )

    # ------------------------------------------------------------------
    # Call/return/phi consistency.
    # ------------------------------------------------------------------
    call_by_key: Dict[
        Tuple[str, str, str], List[Dict[str, str]]
    ] = defaultdict(list)
    ret_by_key: Dict[
        Tuple[str, str, str], List[Dict[str, str]]
    ] = defaultdict(list)

    for row in refined_calls:
        key = (
            norm_text(row.get("callsite_node", "")),
            norm_text(row.get("callee_entry_node", "")),
            norm_text(row.get("callsite_id", "")),
        )
        call_by_key[key].append(row)

    for row in refined_rets:
        key = (
            norm_text(row.get("callee_exit_node", "")),
            norm_text(row.get("return_node", "")),
            norm_text(row.get("callsite_id", "")),
        )
        ret_by_key[key].append(row)

    exact_phi_counter: Counter = Counter()
    phi_by_call_key: Dict[Tuple[str, str, str], List[Dict[str, str]]] = defaultdict(list)
    phi_by_ret_key: Dict[Tuple[str, str, str], List[Dict[str, str]]] = defaultdict(list)

    for row in refined_phi:
        ckey = (
            norm_text(row.get("call_edge_src", "")),
            norm_text(row.get("call_edge_dst", "")),
            norm_text(row.get("callsite_id", "")),
        )
        rkey = (
            norm_text(row.get("return_edge_src", "")),
            norm_text(row.get("return_edge_dst", "")),
            norm_text(row.get("callsite_id", "")),
        )
        exact_key = ckey + rkey[:2]
        exact_phi_counter[exact_key] += 1
        phi_by_call_key[ckey].append(row)
        phi_by_ret_key[rkey].append(row)

        cs = ckey[2]

        if ckey not in call_by_key:
            msg = (
                "phi references missing call edge: %s->%s cs=%s"
                % ckey
            )
            fatal.append(msg)
            pair_errors_by_cs[cs].append(msg)

        if rkey not in ret_by_key:
            msg = (
                "phi references missing return edge: %s->%s cs=%s"
                % rkey
            )
            fatal.append(msg)
            pair_errors_by_cs[cs].append(msg)

        call_candidates = call_by_key.get(ckey, [])
        ret_candidates = ret_by_key.get(rkey, [])

        phi_caller = norm_func(row.get("caller_func", ""))
        phi_callee = norm_func(row.get("callee_func", ""))

        for crow in call_candidates:
            if (
                norm_func(crow.get("caller_func", "")) != phi_caller
                or norm_func(crow.get("callee_func", "")) != phi_callee
            ):
                msg = (
                    "phi/call caller-callee mismatch at cs=%s target=%s"
                    % (cs, phi_callee)
                )
                fatal.append(msg)
                pair_errors_by_cs[cs].append(msg)
                break

        for rrow in ret_candidates:
            if (
                norm_func(rrow.get("caller_func", "")) != phi_caller
                or norm_func(rrow.get("callee_func", "")) != phi_callee
            ):
                msg = (
                    "phi/return caller-callee mismatch at cs=%s target=%s"
                    % (cs, phi_callee)
                )
                fatal.append(msg)
                pair_errors_by_cs[cs].append(msg)
                break

    duplicate_phi = 0
    for key, count in exact_phi_counter.items():
        if count > 1:
            duplicate_phi += count - 1
            cs = key[2]
            msg = "duplicate phi relation at cs=%s count=%d" % (cs, count)
            fatal.append(msg)
            pair_errors_by_cs[cs].append(msg)

    # Multiple different phi rows for one call edge are ambiguous under the
    # unique-exit normalized ICFG model.
    multiple_phi_per_call = 0
    for ckey, rows in phi_by_call_key.items():
        unique_returns = {
            (
                norm_text(r.get("return_edge_src", "")),
                norm_text(r.get("return_edge_dst", "")),
            )
            for r in rows
        }
        if len(unique_returns) > 1:
            multiple_phi_per_call += 1
            cs = ckey[2]
            msg = (
                "one call edge maps to multiple return edges at cs=%s "
                "call=%s->%s"
                % (cs, ckey[0], ckey[1])
            )
            fatal.append(msg)
            pair_errors_by_cs[cs].append(msg)

    # A return edge must always be paired.  A call edge may legitimately have
    # no return/phi for a non-returning or unmodelled callee.
    orphan_returns = 0
    for rkey, rows in ret_by_key.items():
        if rkey not in phi_by_ret_key:
            orphan_returns += len(rows)
            cs = rkey[2]
            msg = (
                "return edge has no phi relation: %s->%s cs=%s"
                % rkey
            )
            fatal.append(msg)
            pair_errors_by_cs[cs].append(msg)

    missing_phi = 0
    calls_by_cs_target: Dict[Tuple[str, str], List[Tuple[str, str, str]]] = defaultdict(list)
    rets_by_cs_target: Dict[Tuple[str, str], List[Tuple[str, str, str]]] = defaultdict(list)

    for key, rows in call_by_key.items():
        for row in rows:
            calls_by_cs_target[
                (
                    norm_text(row.get("callsite_id", "")),
                    norm_func(row.get("callee_func", "")),
                )
            ].append(key)

    for key, rows in ret_by_key.items():
        for row in rows:
            rets_by_cs_target[
                (
                    norm_text(row.get("callsite_id", "")),
                    norm_func(row.get("callee_func", "")),
                )
            ].append(key)

    # If both a call and a return relation exist for the same cs/target, a phi
    # relation must connect them.
    for cs_target in sorted(set(calls_by_cs_target) & set(rets_by_cs_target)):
        cs, target = cs_target
        calls_for_target = calls_by_cs_target[cs_target]
        rets_for_target = rets_by_cs_target[cs_target]
        linked = False
        for ckey in calls_for_target:
            for prow in phi_by_call_key.get(ckey, []):
                prkey = (
                    norm_text(prow.get("return_edge_src", "")),
                    norm_text(prow.get("return_edge_dst", "")),
                    norm_text(prow.get("callsite_id", "")),
                )
                if prkey in rets_for_target:
                    linked = True
                    break
            if linked:
                break

        if not linked:
            missing_phi += 1
            msg = "missing phi for cs=%s target=%s" % (cs, target)
            fatal.append(msg)
            pair_errors_by_cs[cs].append(msg)

    call_without_phi = 0
    for ckey, rows in call_by_key.items():
        if ckey not in phi_by_call_key:
            call_without_phi += len(rows)

    # ------------------------------------------------------------------
    # Reachability.
    # ------------------------------------------------------------------
    roots = build_roots(refined, args.entry_function)
    reachable = reachable_nodes(refined, roots)

    reachability_failures = 0
    unreachable_pairs: List[Tuple[str, str]] = []
    callsite_reachability: Dict[str, bool] = {}
    target_pair_reachability: Dict[Tuple[str, str], bool] = {}

    for cs, targets in smlta_targets.items():
        meta = refined_meta.get(cs) or original_meta.get(cs) or {}
        callsite_node = norm_text(meta.get("callsite_node", ""))
        callsite_reachability[cs] = bool(
            callsite_node and callsite_node in reachable
        )

        for target in targets:
            dests = [
                norm_text(row.get("callee_entry_node", ""))
                for row in refined_calls
                if norm_text(row.get("callsite_id", "")) == cs
                and norm_func(row.get("callee_func", "")) == target
            ]
            ok = bool(dests) and any(d in reachable for d in dests)
            target_pair_reachability[(cs, target)] = ok
            if not ok:
                reachability_failures += 1
                unreachable_pairs.append((cs, target))

    if unreachable_pairs:
        warnings.append(
            "%d mapped SMLTA target pair(s) are not graph-reachable from roots"
            % len(unreachable_pairs)
        )

    # ------------------------------------------------------------------
    # Counts required by Phase 8.
    # ------------------------------------------------------------------
    mapped_callsites = set(smlta_targets)
    svf_target_count = sum(
        len(original_targets.get(cs, set())) for cs in mapped_callsites
    )
    smlta_target_count = sum(len(v) for v in smlta_targets.values())
    refined_target_count = sum(
        len(refined_targets.get(cs, set())) for cs in mapped_callsites
    )

    added_target_count = 0
    removed_target_count = 0
    kept_target_count = 0
    for cs in mapped_callsites:
        old = original_targets.get(cs, set())
        new = smlta_targets.get(cs, set())
        added_target_count += len(new - old)
        removed_target_count += len(old - new)
        kept_target_count += len(old & new)

    # Structural pair error total uses the distinct validation findings above,
    # while call_without_phi is reported separately because a non-returning
    # function may legitimately have no return edge.
    call_return_pair_errors = (
        sum(len(messages) for messages in pair_errors_by_cs.values())
        + len(missing_integrated_calls)
        + len(extra_integrated_calls)
        + len(missing_integrated_rets)
        + len(extra_integrated_rets)
    )

    # ------------------------------------------------------------------
    # Details TSV.
    # ------------------------------------------------------------------
    detail_header = [
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
        "zero_target",
        "callsite_reachable",
        "all_smlta_targets_reachable",
        "pair_error_count",
        "status",
    ]
    detail_rows: List[List[object]] = []

    for cs in sorted(all_original_cs, key=callsite_sort_key):
        meta = original_meta.get(cs, {})
        old = original_targets.get(cs, set())
        smlta = smlta_targets.get(cs, set())
        new = refined_targets.get(cs, set())

        mapped = cs in smlta_targets
        kept = old & smlta if mapped else old
        removed = old - smlta if mapped else set()
        added = smlta - old if mapped else set()

        cs_reach = callsite_reachability.get(cs)
        if mapped:
            target_reach_ok = all(
                target_pair_reachability.get((cs, t), False)
                for t in smlta
            )
        else:
            target_reach_ok = ""

        pair_count = len(pair_errors_by_cs.get(cs, []))

        status_parts: List[str] = []
        if cs in zero_target_callsites:
            status_parts.append("zero-target")
        if pair_count:
            status_parts.append("pair-error")
        if mapped and new != smlta:
            status_parts.append("target-mismatch")
        if (not mapped) and new != old:
            status_parts.append("unmapped-mutated")
        if mapped and target_reach_ok is False:
            status_parts.append("unreachable")
        if not status_parts:
            status_parts.append("ok")

        detail_rows.append(
            [
                cs,
                norm_func(meta.get("caller_func", "")),
                norm_text(meta.get("call_kind", "")),
                "mapped" if mapped else "unmapped-kept",
                ",".join(sorted(old)),
                ",".join(sorted(smlta)),
                ",".join(sorted(new)),
                ",".join(sorted(kept)),
                ",".join(sorted(removed)),
                ",".join(sorted(added)),
                "yes" if cs in zero_target_callsites else "no",
                (
                    "yes"
                    if cs_reach is True
                    else "no"
                    if cs_reach is False
                    else ""
                ),
                (
                    "yes"
                    if target_reach_ok is True
                    else "no"
                    if target_reach_ok is False
                    else ""
                ),
                pair_count,
                ",".join(status_parts),
            ]
        )

    write_rows_tsv(details_path, detail_header, detail_rows)

    # ------------------------------------------------------------------
    # Human-readable report.
    # ------------------------------------------------------------------
    fatal_count = len(fatal)
    warning_count = len(warnings)
    status = "PASS" if fatal_count == 0 else "FAIL"

    report_lines = [
        "SMLTA ICFG validation report",
        "============================",
        "status: %s" % status,
        "original_icfg_dir: %s" % original_dir,
        "refined_icfg_dir: %s" % refined_dir,
        "smlta_map: %s" % smlta_map_path,
        "entry_function: %s" % args.entry_function,
        "roots: %s" % (",".join(roots) if roots else "<none>"),
        "",
        "Required Phase-8 metrics",
        "------------------------",
        "smlta_mapped_callsites: %d" % len(mapped_callsites),
        "mapping_failures: %d" % mapping_failures,
        "svf_target_count_for_mapped_callsites: %d" % svf_target_count,
        "smlta_target_count: %d" % smlta_target_count,
        "refined_target_count_for_mapped_callsites: %d" % refined_target_count,
        "kept_targets: %d" % kept_target_count,
        "added_targets: %d" % added_target_count,
        "removed_targets: %d" % removed_target_count,
        "zero_target_callsites: %d" % len(zero_target_callsites),
        "call_return_pair_errors: %d" % call_return_pair_errors,
        "phi_missing: %d" % missing_phi,
        "phi_duplicates: %d" % duplicate_phi,
        "target_reachability_failures: %d" % reachability_failures,
        "",
        "Additional structural metrics",
        "-----------------------------",
        "unknown_node_edges: %d" % unknown_node_edges,
        "orphan_return_edges: %d" % orphan_returns,
        "call_edges_without_phi_allowed_as_nonreturning_or_unmodelled: %d"
        % call_without_phi,
        "missing_integrated_call_edges: %d" % len(missing_integrated_calls),
        "extra_integrated_call_edges: %d" % len(extra_integrated_calls),
        "missing_integrated_return_edges: %d" % len(missing_integrated_rets),
        "extra_integrated_return_edges: %d" % len(extra_integrated_rets),
        "fatal_errors: %d" % fatal_count,
        "warnings: %d" % warning_count,
    ]

    if fatal:
        report_lines.extend(["", "Fatal errors", "------------"])
        report_lines.extend("- " + msg for msg in fatal)

    if warnings:
        report_lines.extend(["", "Warnings", "--------"])
        report_lines.extend("- " + msg for msg in warnings)

    if unreachable_pairs:
        report_lines.extend(
            ["", "Unreachable mapped targets", "--------------------------"]
        )
        for cs, target in sorted(
            unreachable_pairs,
            key=lambda item: (callsite_sort_key(item[0]), item[1]),
        ):
            report_lines.append("- %s -> %s" % (cs, target))

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    print(
        "[validate-smlta] status=%s mapped=%d svf_targets=%d "
        "smlta_targets=%d added=%d removed=%d pair_errors=%d "
        "reachability_failures=%d"
        % (
            status,
            len(mapped_callsites),
            svf_target_count,
            smlta_target_count,
            added_target_count,
            removed_target_count,
            call_return_pair_errors,
            reachability_failures,
        ),
        file=sys.stderr,
    )
    print("[validate-smlta] report: %s" % report_path, file=sys.stderr)
    print("[validate-smlta] details: %s" % details_path, file=sys.stderr)

    return 0 if fatal_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
