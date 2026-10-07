#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
validate_dominator_context_sensitive.py

Extract (do not compare) target dominators from a normalized/SMLTA-refined ICFG
using a definition-based context-sensitive reachability oracle.

Core definition
---------------
A candidate D dominates target T iff there is NO valid interprocedural path
from a program root to T that avoids D.

This implementation does not treat the ICFG as an ordinary directed graph.
Call/return matching is respected through a finite summary fixed point:

  1. Ordinary intra-procedural CFG edges are always available.
  2. For a matched call/return tuple

         callsite -> callee_entry   ...   callee_exit -> return_node

     a same-level summary edge

         callsite -> return_node

     is enabled only when callee_entry can reach callee_exit through valid
     same-level paths while avoiding the candidate.
  3. Summary edges are iterated to a least fixed point. This handles recursion
     without imposing an arbitrary call-stack depth.
  4. Root-to-target reachability then uses:

         ordinary CFG edges + enabled summary edges + call edges

     and NEVER traverses raw return edges directly. A call edge represents the
     one active call chain leading toward the target; completed calls are
     represented by matched summary edges.

For each candidate node/basic-block, the candidate is removed and target
reachability is recomputed. If target becomes unreachable, the candidate is a
context-sensitive dominator.

Expected ICFG files
-------------------
Required:
  icfg_nodes.tsv
  icfg_edges.tsv
  icfg_call_edges.tsv
  icfg_return_edges.tsv
  icfg_functions.tsv

Preferred (for exact call/return pairing):
  icfg_phi.tsv

Optional target mapping:
  icfg_bb_mapping.tsv

When icfg_bb_mapping.tsv cannot resolve --target, module.ll is used as a
fallback. If --module-ll is omitted, the script tries:
  <icfg-dir>/module.ll
  <icfg-dir>/../module.ll

Typical usage
-------------
python3 validate_dominator_context_sensitive.py \
    --icfg-dir /benchmark/temp_binutils-2.29/icfg_smlta \
    --target elf.c:8205 \
    -o /benchmark/temp_binutils-2.29/context_sensitive_dominators.txt

This script intentionally performs extraction only. It does NOT read or compare
against dominator_nodes.txt produced by another algorithm.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


VERSION = "1.0"


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def raise_csv_field_limit() -> None:
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
    return s[1:] if s.startswith("@") else s


def norm_bb(value: object) -> str:
    s = norm_text(value).strip('"')
    if s.startswith("%"):
        s = s[1:]
    return s or "entry"


def read_tsv(path: Path, required: bool = True) -> Tuple[List[str], List[Dict[str, str]]]:
    if not path.exists():
        if required:
            raise FileNotFoundError(path)
        return [], []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        if reader.fieldnames is None:
            raise RuntimeError(f"TSV has no header: {path}")
        return list(reader.fieldnames), list(reader)


def require_columns(path: Path, header: Sequence[str], columns: Iterable[str]) -> None:
    missing = [c for c in columns if c not in header]
    if missing:
        raise RuntimeError(
            f"missing required column(s) in {path}: {', '.join(missing)}"
        )


def split_csv_nodes(value: object) -> List[str]:
    return [x.strip() for x in norm_text(value).split(",") if x.strip()]


def parse_target(target: str) -> Tuple[str, int]:
    if ":" not in target:
        raise ValueError("--target must be file:line, e.g. elf.c:8205")
    filename, line_text = target.rsplit(":", 1)
    try:
        line = int(line_text)
    except ValueError as exc:
        raise ValueError(f"invalid target line: {line_text!r}") from exc
    if line <= 0:
        raise ValueError("target line must be > 0")
    return filename, line


def source_file_score(target_file: str, candidate_file: str) -> int:
    """Conservative suffix/basename score for normalized source paths."""
    target_file = norm_text(target_file).replace("\\", "/")
    candidate_file = norm_text(candidate_file).replace("\\", "/")
    if not target_file or not candidate_file:
        return 0
    if target_file == candidate_file:
        return 100
    if candidate_file.endswith("/" + target_file) or target_file.endswith("/" + candidate_file):
        return 90
    tbase = target_file.rsplit("/", 1)[-1]
    cbase = candidate_file.rsplit("/", 1)[-1]
    if tbase == cbase:
        return 80
    if tbase and (candidate_file.endswith(tbase) or cbase.endswith(tbase)):
        return 50
    return 0


# ---------------------------------------------------------------------------
# LLVM debug-location fallback for target file:line -> function/basic block
# ---------------------------------------------------------------------------


DEFINE_RE = re.compile(
    r'^\s*define\b.*@("?[-A-Za-z$._0-9]+"?)\s*\(.*\).*?!dbg\s+!(\d+)\s*\{'
)
DEFINE_ANY_RE = re.compile(r'^\s*define\b.*@("?[-A-Za-z$._0-9]+"?)\s*\(')
MD_RE = re.compile(r'^\s*!(\d+)\s*=\s*(?:distinct\s+)?!([A-Za-z0-9_]+)\((.*)\)\s*$')
KV_RE = re.compile(
    r'([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([^,][^,]*?(?=(?:,\s+[A-Za-z_][A-Za-z0-9_]*\s*:)|$))'
)
BB_NAMED_RE = re.compile(r'^\s*([A-Za-z$._-][A-Za-z$._0-9-]*|\d+):(?:\s*;.*)?$')
BB_OLD_RE = re.compile(r'^\s*;\s*<label>:(\d+):')
DBG_USE_RE = re.compile(r'!dbg\s+!(\d+)')


def md_ref_to_int(value: object) -> Optional[int]:
    m = re.match(r'!(\d+)$', norm_text(value))
    return int(m.group(1)) if m else None


def parse_metadata(lines: Sequence[str]) -> Dict[int, Dict[str, object]]:
    result: Dict[int, Dict[str, object]] = {}
    for line in lines:
        m = MD_RE.match(line)
        if not m:
            continue
        attrs: Dict[str, str] = {}
        for km in KV_RE.finditer(m.group(3)):
            attrs[km.group(1)] = km.group(2).strip()
        result[int(m.group(1))] = {
            "tag": m.group(2),
            "attrs": attrs,
            "raw": m.group(3),
        }
    return result


def function_name_from_scope(
    md: Mapping[int, Mapping[str, object]], scope_id: Optional[int]
) -> Optional[str]:
    seen: Set[int] = set()
    cur = scope_id
    while cur is not None and cur not in seen:
        seen.add(cur)
        node = md.get(cur)
        if not node or not isinstance(node.get("attrs"), dict):
            return None
        attrs = node["attrs"]  # type: ignore[index]
        if node.get("tag") == "DISubprogram":
            name = attrs.get("name") or attrs.get("linkageName")
            return norm_func(name) if name else None
        cur = md_ref_to_int(attrs.get("scope", ""))
    return None


def metadata_file_path(
    md: Mapping[int, Mapping[str, object]], node: Mapping[str, object]
) -> str:
    attrs = node.get("attrs", {}) if isinstance(node.get("attrs"), dict) else {}
    file_ref = md_ref_to_int(attrs.get("file", ""))  # type: ignore[union-attr]
    if file_ref is None:
        # DILocation usually gets the file through its scope.
        scope_ref = md_ref_to_int(attrs.get("scope", ""))  # type: ignore[union-attr]
        seen: Set[int] = set()
        cur = scope_ref
        while cur is not None and cur not in seen:
            seen.add(cur)
            snode = md.get(cur)
            if not snode or not isinstance(snode.get("attrs"), dict):
                break
            sattrs = snode["attrs"]  # type: ignore[index]
            file_ref = md_ref_to_int(sattrs.get("file", ""))
            if file_ref is not None:
                break
            cur = md_ref_to_int(sattrs.get("scope", ""))
    if file_ref is None:
        return ""
    fnode = md.get(file_ref)
    if not fnode or fnode.get("tag") != "DIFile" or not isinstance(fnode.get("attrs"), dict):
        return ""
    fattrs = fnode["attrs"]  # type: ignore[index]
    filename = norm_text(fattrs.get("filename", "")).strip('"')
    directory = norm_text(fattrs.get("directory", "")).strip('"')
    return f"{directory}/{filename}" if directory and filename else filename


def resolve_target_from_module_ll(
    module_ll: Path,
    target: str,
    requested_function: Optional[str] = None,
) -> Tuple[str, Set[str], Dict[str, object]]:
    target_file, target_line = parse_target(target)
    lines = module_ll.read_text(encoding="utf-8", errors="replace").splitlines(True)
    md = parse_metadata(lines)

    wanted_dbg_ids: Set[int] = set()
    candidates: List[Tuple[int, int, str]] = []
    for nid, node in md.items():
        if node.get("tag") != "DILocation" or not isinstance(node.get("attrs"), dict):
            continue
        attrs = node["attrs"]  # type: ignore[index]
        try:
            line_no = int(norm_text(attrs.get("line", "-1")))
        except ValueError:
            continue
        if line_no != target_line:
            continue
        fn = function_name_from_scope(md, md_ref_to_int(attrs.get("scope", "")))
        if not fn:
            continue
        if requested_function and fn != requested_function:
            continue
        score = source_file_score(target_file, metadata_file_path(md, node))
        candidates.append((score, nid, fn))

    if not candidates:
        raise ValueError(f"no DILocation matched {target} in {module_ll}")

    best_score = max(score for score, _, _ in candidates)
    best = [(nid, fn) for score, nid, fn in candidates if score == best_score]
    functions = sorted({fn for _, fn in best})
    if requested_function:
        function = requested_function
    elif len(functions) == 1:
        function = functions[0]
    else:
        raise ValueError(
            f"target {target} maps to multiple functions in module.ll: {', '.join(functions)}; "
            "pass --function"
        )

    wanted_dbg_ids = {nid for nid, fn in best if fn == function}

    bbs: Set[str] = set()
    in_func = False
    current_func: Optional[str] = None
    current_bb = "entry"
    matched_ir: List[Dict[str, object]] = []

    for line_no, line in enumerate(lines, start=1):
        m = DEFINE_ANY_RE.match(line)
        if m:
            current_func = norm_func(m.group(1))
            in_func = current_func == function
            current_bb = "entry"
            continue
        if in_func and re.match(r'^\s*}\s*$', line):
            in_func = False
            current_func = None
            current_bb = "entry"
            continue
        if not in_func:
            continue
        bm = BB_NAMED_RE.match(line)
        if bm:
            current_bb = norm_bb(bm.group(1))
            continue
        om = BB_OLD_RE.match(line)
        if om:
            current_bb = norm_bb(om.group(1))
            continue
        hits = sorted(set(int(x) for x in DBG_USE_RE.findall(line)) & wanted_dbg_ids)
        if hits:
            bbs.add(current_bb)
            matched_ir.append(
                {
                    "ll_line": line_no,
                    "bb": current_bb,
                    "dbg_ids": hits,
                    "ir": line.rstrip("\n"),
                }
            )

    if not bbs:
        raise ValueError(
            f"DILocation matched {target}, but no LLVM basic block could be resolved in function {function}"
        )

    return function, bbs, {
        "mode": "module-ll",
        "module_ll": str(module_ll),
        "target_file": target_file,
        "target_line": target_line,
        "function": function,
        "bbs": sorted(bbs),
        "wanted_dbg_ids": sorted(wanted_dbg_ids),
        "matched_ir": matched_ir,
    }


# ---------------------------------------------------------------------------
# ICFG representation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Node:
    node_id: str
    function: str
    bb: str
    kind: str
    label: str = ""
    source: str = ""


@dataclass(frozen=True)
class CallReturnPair:
    callsite_node: str
    callee_entry_node: str
    callee_exit_node: str
    return_node: str
    callsite_id: str
    caller_func: str
    callee_func: str


class ICFG:
    def __init__(self) -> None:
        self.nodes: Dict[str, Node] = {}
        self.normal_adj: Dict[str, Set[str]] = defaultdict(set)
        self.raw_adj: Dict[str, Set[str]] = defaultdict(set)
        self.raw_rev: Dict[str, Set[str]] = defaultdict(set)
        self.call_edges: Set[Tuple[str, str]] = set()
        self.return_edges: Set[Tuple[str, str]] = set()
        self.pairs: List[CallReturnPair] = []
        self.functions: Dict[str, Dict[str, Set[str]]] = defaultdict(
            lambda: {"entries": set(), "exits": set(), "nodes": set()}
        )
        self.node_to_func: Dict[str, str] = {}

    def add_node(self, node: Node) -> None:
        self.nodes[node.node_id] = node
        self.node_to_func[node.node_id] = node.function
        if node.function:
            self.functions[node.function]["nodes"].add(node.node_id)
            if node.kind.lower() == "entry":
                self.functions[node.function]["entries"].add(node.node_id)
            elif node.kind.lower() == "exit":
                self.functions[node.function]["exits"].add(node.node_id)

    def add_raw_edge(self, src: str, dst: str) -> None:
        self.raw_adj[src].add(dst)
        self.raw_rev[dst].add(src)

    def entry_candidates(self, preferred: str = "main") -> List[str]:
        for fn in (preferred, "main", "_start"):
            entries = sorted(self.functions.get(fn, {}).get("entries", set()))
            if entries:
                return entries
        incoming_nonreturn: Set[str] = set()
        for src, dsts in self.normal_adj.items():
            for dst in dsts:
                incoming_nonreturn.add(dst)
        for _, dst in self.call_edges:
            incoming_nonreturn.add(dst)
        roots = sorted(n for n in self.nodes if n not in incoming_nonreturn)
        if roots:
            return roots
        return [sorted(self.nodes)[0]] if self.nodes else []


def load_icfg(icfg_dir: Path) -> ICFG:
    g = ICFG()

    node_path = icfg_dir / "icfg_nodes.tsv"
    edge_path = icfg_dir / "icfg_edges.tsv"
    call_path = icfg_dir / "icfg_call_edges.tsv"
    ret_path = icfg_dir / "icfg_return_edges.tsv"
    func_path = icfg_dir / "icfg_functions.tsv"
    phi_path = icfg_dir / "icfg_phi.tsv"

    node_h, node_rows = read_tsv(node_path)
    require_columns(node_path, node_h, ["node_id", "function", "kind"])
    for row in node_rows:
        nid = norm_text(row.get("node_id"))
        if not nid:
            continue
        g.add_node(
            Node(
                node_id=nid,
                function=norm_func(row.get("function")),
                bb=norm_bb(row.get("bb")) if norm_text(row.get("bb")) else "",
                kind=norm_text(row.get("kind")) or "unknown",
                label=norm_text(row.get("label")),
                source=norm_text(row.get("source")),
            )
        )

    edge_h, edge_rows = read_tsv(edge_path)
    require_columns(edge_path, edge_h, ["src", "dst", "kind"])
    for row in edge_rows:
        src = norm_text(row.get("src"))
        dst = norm_text(row.get("dst"))
        kind = norm_text(row.get("kind")).lower() or "cfg"
        if not src or not dst:
            continue
        g.add_raw_edge(src, dst)
        if kind == "call":
            g.call_edges.add((src, dst))
        elif kind == "return":
            g.return_edges.add((src, dst))
        else:
            # Normalized ICFG removes callsite->return summary edges before
            # dominator analysis. Therefore all remaining non-call/return
            # edges are treated as ordinary same-level control-flow edges.
            g.normal_adj[src].add(dst)

    call_h, call_rows = read_tsv(call_path)
    require_columns(
        call_path,
        call_h,
        ["callsite_node", "callee_entry_node", "caller_func", "callee_func", "callsite_id"],
    )
    ret_h, ret_rows = read_tsv(ret_path)
    require_columns(
        ret_path,
        ret_h,
        ["callee_exit_node", "return_node", "caller_func", "callee_func", "callsite_id"],
    )

    # Make explicit tables authoritative for call/return presence too.
    calls_by_key: Dict[Tuple[str, str, str], List[Dict[str, str]]] = defaultdict(list)
    returns_by_key: Dict[Tuple[str, str, str], List[Dict[str, str]]] = defaultdict(list)

    for row in call_rows:
        csrc = norm_text(row.get("callsite_node"))
        cdst = norm_text(row.get("callee_entry_node"))
        csid = norm_text(row.get("callsite_id"))
        callee = norm_func(row.get("callee_func"))
        if csrc and cdst:
            g.call_edges.add((csrc, cdst))
            g.add_raw_edge(csrc, cdst)
        if csid and callee:
            calls_by_key[(csid, callee, cdst)].append(row)

    for row in ret_rows:
        rsrc = norm_text(row.get("callee_exit_node"))
        rdst = norm_text(row.get("return_node"))
        csid = norm_text(row.get("callsite_id"))
        callee = norm_func(row.get("callee_func"))
        if rsrc and rdst:
            g.return_edges.add((rsrc, rdst))
            g.add_raw_edge(rsrc, rdst)
        if csid and callee:
            returns_by_key[(csid, callee, rsrc)].append(row)

    # Fill/override function entry/exit metadata.
    func_h, func_rows = read_tsv(func_path)
    require_columns(func_path, func_h, ["function", "entry_nodes", "exit_nodes"])
    for row in func_rows:
        fn = norm_func(row.get("function"))
        if not fn:
            continue
        g.functions[fn]["entries"].update(split_csv_nodes(row.get("entry_nodes")))
        g.functions[fn]["exits"].update(split_csv_nodes(row.get("exit_nodes")))

    # Exact pairing: icfg_phi.tsv is preferred because one row explicitly binds
    # one call edge to one return edge.
    phi_h, phi_rows = read_tsv(phi_path, required=False)
    pair_keys: Set[Tuple[str, str, str, str, str, str, str]] = set()

    if phi_rows:
        require_columns(
            phi_path,
            phi_h,
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
        for row in phi_rows:
            values = (
                norm_text(row.get("call_edge_src")),
                norm_text(row.get("call_edge_dst")),
                norm_text(row.get("return_edge_src")),
                norm_text(row.get("return_edge_dst")),
                norm_text(row.get("callsite_id")),
                norm_func(row.get("caller_func")),
                norm_func(row.get("callee_func")),
            )
            if not all(values[:4]):
                continue
            pair_keys.add(values)
    else:
        # Defensive fallback: pair by (callsite_id, callee_func), never by
        # callsite_id alone. This avoids creating a cross-product between
        # different indirect-call targets.
        calls_group: Dict[Tuple[str, str], List[Dict[str, str]]] = defaultdict(list)
        rets_group: Dict[Tuple[str, str], List[Dict[str, str]]] = defaultdict(list)
        for row in call_rows:
            key = (norm_text(row.get("callsite_id")), norm_func(row.get("callee_func")))
            if key[0] and key[1]:
                calls_group[key].append(row)
        for row in ret_rows:
            key = (norm_text(row.get("callsite_id")), norm_func(row.get("callee_func")))
            if key[0] and key[1]:
                rets_group[key].append(row)
        for key in sorted(set(calls_group) & set(rets_group)):
            for c in calls_group[key]:
                for r in rets_group[key]:
                    pair_keys.add(
                        (
                            norm_text(c.get("callsite_node")),
                            norm_text(c.get("callee_entry_node")),
                            norm_text(r.get("callee_exit_node")),
                            norm_text(r.get("return_node")),
                            key[0],
                            norm_func(c.get("caller_func")),
                            key[1],
                        )
                    )

    for csrc, centry, cexit, rnode, csid, caller, callee in sorted(pair_keys):
        if csrc and centry and cexit and rnode:
            g.pairs.append(
                CallReturnPair(csrc, centry, cexit, rnode, csid, caller, callee)
            )

    return g


# ---------------------------------------------------------------------------
# Target resolution from normalized mapping / module.ll fallback
# ---------------------------------------------------------------------------


def find_nodes_for_function_bbs(g: ICFG, function: str, bbs: Set[str]) -> List[str]:
    bbs_norm = {norm_bb(bb) for bb in bbs}
    result = [
        nid
        for nid, node in g.nodes.items()
        if node.function == function and norm_bb(node.bb) in bbs_norm
    ]
    if not result:
        # Conservative diagnostic fallback: label text can sometimes preserve BB
        # identity when the normalized `bb` field is empty.
        for nid, node in g.nodes.items():
            if node.function != function:
                continue
            for bb in bbs_norm:
                if bb and re.search(rf"\b{re.escape(bb)}\b", node.label or ""):
                    result.append(nid)
                    break
    return sorted(set(result))


def resolve_target_from_bb_mapping(
    icfg_dir: Path,
    g: ICFG,
    target: str,
    requested_function: Optional[str] = None,
) -> Optional[Tuple[str, Set[str], List[str], Dict[str, object]]]:
    path = icfg_dir / "icfg_bb_mapping.tsv"
    if not path.exists():
        return None

    target_file, target_line = parse_target(target)
    header, rows = read_tsv(path)
    require_columns(path, header, ["node_id", "function", "bb", "src_file", "src_line"])

    matches: List[Tuple[int, Dict[str, str]]] = []
    for row in rows:
        try:
            line_no = int(norm_text(row.get("src_line")))
        except ValueError:
            continue
        if line_no != target_line:
            continue
        fn = norm_func(row.get("function"))
        if requested_function and fn != requested_function:
            continue
        score = source_file_score(target_file, norm_text(row.get("src_file")))
        if score > 0:
            matches.append((score, row))

    if not matches:
        return None

    best_score = max(score for score, _ in matches)
    best_rows = [row for score, row in matches if score == best_score]
    functions = sorted({norm_func(row.get("function")) for row in best_rows if norm_func(row.get("function"))})
    if requested_function:
        function = requested_function
    elif len(functions) == 1:
        function = functions[0]
    else:
        raise ValueError(
            f"target {target} maps to multiple functions in icfg_bb_mapping.tsv: "
            f"{', '.join(functions)}; pass --function"
        )

    selected = [row for row in best_rows if norm_func(row.get("function")) == function]
    bbs = {norm_bb(row.get("bb")) for row in selected if norm_text(row.get("bb"))}
    direct_nodes = {norm_text(row.get("node_id")) for row in selected if norm_text(row.get("node_id"))}
    expanded_nodes = set(find_nodes_for_function_bbs(g, function, bbs))
    target_nodes = sorted((direct_nodes | expanded_nodes) & set(g.nodes))

    if not bbs or not target_nodes:
        return None

    return function, bbs, target_nodes, {
        "mode": "icfg-bb-mapping",
        "mapping_file": str(path),
        "target_file": target_file,
        "target_line": target_line,
        "function": function,
        "bbs": sorted(bbs),
        "matched_rows": len(selected),
    }


def find_module_ll(icfg_dir: Path, explicit: Optional[str]) -> Optional[Path]:
    if explicit:
        path = Path(explicit).expanduser().resolve()
        return path if path.is_file() else None
    candidates = [
        icfg_dir / "module.ll",
        icfg_dir.parent / "module.ll",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return None


def resolve_target(
    args: argparse.Namespace,
    icfg_dir: Path,
    g: ICFG,
) -> Tuple[str, Set[str], List[str], Dict[str, object]]:
    mapped = resolve_target_from_bb_mapping(
        icfg_dir, g, args.target, requested_function=args.function
    )
    if mapped is not None:
        return mapped

    module_ll = find_module_ll(icfg_dir, args.module_ll)
    if module_ll is None:
        raise ValueError(
            "target could not be resolved from icfg_bb_mapping.tsv, and module.ll "
            "was not found. Pass --module-ll explicitly."
        )

    function, bbs, info = resolve_target_from_module_ll(
        module_ll, args.target, requested_function=args.function
    )
    target_nodes = find_nodes_for_function_bbs(g, function, bbs)
    if not target_nodes:
        raise ValueError(
            f"target basic block(s) {sorted(bbs)} in function {function} were found in module.ll, "
            "but no matching ICFG node exists"
        )
    info["target_nodes"] = target_nodes
    return function, bbs, target_nodes, info


# ---------------------------------------------------------------------------
# Exact well-nested reachability abstraction by summary fixed point
# ---------------------------------------------------------------------------


@dataclass
class ReachabilityResult:
    reachable_target: bool
    reachable_nodes: Set[str]
    summary_edges: Set[Tuple[str, str]]
    summary_iterations: int
    enabled_pair_count: int


class ContextSensitiveOracle:
    """
    Context-sensitive reachability over a normalized ICFG.

    The summary fixed point is exact for finite, well-nested call/return paths
    represented by the normalized ICFG. Recursive calls are handled by a least
    fixed point instead of stack unrolling.
    """

    def __init__(self, g: ICFG, roots: Sequence[str], target_nodes: Sequence[str]) -> None:
        self.g = g
        self.roots = tuple(r for r in roots if r in g.nodes)
        self.targets = set(t for t in target_nodes if t in g.nodes)

        self.pairs_by_callee: Dict[str, List[CallReturnPair]] = defaultdict(list)
        self.pair_indices_by_callee: Dict[str, List[int]] = defaultdict(list)
        self.pairs_by_caller: Dict[str, List[CallReturnPair]] = defaultdict(list)
        self.callers_of_callee: Dict[str, Set[str]] = defaultdict(set)
        for index, pair in enumerate(g.pairs):
            callee = pair.callee_func or g.node_to_func.get(pair.callee_entry_node, "")
            caller = pair.caller_func or g.node_to_func.get(pair.callsite_node, "")
            self.pairs_by_callee[callee].append(pair)
            self.pair_indices_by_callee[callee].append(index)
            self.pairs_by_caller[caller].append(pair)
            if callee and caller:
                self.callers_of_callee[callee].add(caller)

    @staticmethod
    def _reachable(
        starts: Iterable[str],
        adjacency: Mapping[str, Set[str]],
        forbidden: Set[str],
        stop_nodes: Optional[Set[str]] = None,
        allowed_nodes: Optional[Set[str]] = None,
    ) -> Set[str]:
        seen: Set[str] = set()
        queue: deque[str] = deque()
        for start in starts:
            if (
                start
                and start not in forbidden
                and start not in seen
                and (allowed_nodes is None or start in allowed_nodes)
            ):
                seen.add(start)
                queue.append(start)

        while queue:
            cur = queue.popleft()
            if stop_nodes and cur in stop_nodes:
                # It is still considered reachable, but no need to expand it
                # when the caller only asks whether a target was reached.
                continue
            for nxt in adjacency.get(cur, set()):
                if nxt in forbidden or nxt in seen:
                    continue
                if allowed_nodes is not None and nxt not in allowed_nodes:
                    continue
                seen.add(nxt)
                queue.append(nxt)
        return seen

    def _function_returnable_pairs(
        self,
        function: str,
        adjacency: Mapping[str, Set[str]],
        forbidden: Set[str],
        relevant_pairs: Sequence[CallReturnPair],
    ) -> Set[Tuple[str, str]]:
        """Return (entry, exit) pairs reachable at the same call level."""
        wanted_by_entry: Dict[str, Set[str]] = defaultdict(set)
        for pair in relevant_pairs:
            if (
                pair.callee_entry_node not in forbidden
                and pair.callee_exit_node not in forbidden
            ):
                wanted_by_entry[pair.callee_entry_node].add(pair.callee_exit_node)

        result: Set[Tuple[str, str]] = set()
        allowed_nodes = set(self.g.functions.get(function, {}).get("nodes", set()))
        if not allowed_nodes:
            # Defensive fallback for incomplete function metadata. The normalized
            # ICFG should normally provide function membership for every node.
            allowed_nodes = {
                nid for nid, fn in self.g.node_to_func.items() if fn == function
            }
        for entry, exits in wanted_by_entry.items():
            if not exits:
                continue
            reachable = self._reachable(
                [entry], adjacency, forbidden, allowed_nodes=allowed_nodes or None
            )
            for exit_node in exits:
                if exit_node in reachable:
                    result.add((entry, exit_node))
        return result

    def build_summary_fixed_point(
        self, forbidden: Set[str]
    ) -> Tuple[Set[Tuple[str, str]], int, int]:
        # Same-level adjacency starts with ordinary CFG only.
        adjacency: Dict[str, Set[str]] = defaultdict(set)
        for src, dsts in self.g.normal_adj.items():
            if src in forbidden:
                continue
            for dst in dsts:
                if dst not in forbidden:
                    adjacency[src].add(dst)

        enabled_summary: Set[Tuple[str, str]] = set()
        enabled_pairs: Set[int] = set()

        # Any function whose returnability may enable a caller summary starts in
        # the worklist. Later, only callers of changed functions are revisited.
        work: deque[str] = deque(sorted(self.pairs_by_callee))
        in_work: Set[str] = set(work)
        iterations = 0

        while work:
            callee_func = work.popleft()
            in_work.discard(callee_func)
            iterations += 1

            pairs = self.pairs_by_callee.get(callee_func, [])
            if not pairs:
                continue

            returnable = self._function_returnable_pairs(
                callee_func, adjacency, forbidden, pairs
            )

            changed_callers: Set[str] = set()
            for idx in self.pair_indices_by_callee.get(callee_func, []):
                pair = self.g.pairs[idx]
                if idx in enabled_pairs:
                    continue
                if (
                    pair.callsite_node in forbidden
                    or pair.return_node in forbidden
                    or pair.callee_entry_node in forbidden
                    or pair.callee_exit_node in forbidden
                ):
                    continue
                if (pair.callee_entry_node, pair.callee_exit_node) not in returnable:
                    continue

                enabled_pairs.add(idx)
                summary = (pair.callsite_node, pair.return_node)
                if summary not in enabled_summary:
                    enabled_summary.add(summary)
                    adjacency[pair.callsite_node].add(pair.return_node)
                    caller = pair.caller_func or self.g.node_to_func.get(pair.callsite_node, "")
                    if caller:
                        changed_callers.add(caller)

            # A new summary edge inside caller F can make F's entry->exit path
            # newly returnable, which can enable summaries at F's callers.
            for caller_func in changed_callers:
                if caller_func in self.pairs_by_callee and caller_func not in in_work:
                    work.append(caller_func)
                    in_work.add(caller_func)

        return enabled_summary, iterations, len(enabled_pairs)

    def run(self, forbidden: Optional[Set[str]] = None) -> ReachabilityResult:
        forbidden = set(forbidden or set())
        if any(root in forbidden for root in self.roots) and all(root in forbidden for root in self.roots):
            return ReachabilityResult(False, set(), set(), 0, 0)
        if self.targets and self.targets.issubset(forbidden):
            return ReachabilityResult(False, set(), set(), 0, 0)

        summary_edges, iterations, enabled_pair_count = self.build_summary_fixed_point(forbidden)

        adjacency: Dict[str, Set[str]] = defaultdict(set)
        for src, dsts in self.g.normal_adj.items():
            if src in forbidden:
                continue
            for dst in dsts:
                if dst not in forbidden:
                    adjacency[src].add(dst)
        for src, dst in summary_edges:
            if src not in forbidden and dst not in forbidden:
                adjacency[src].add(dst)
        for src, dst in self.g.call_edges:
            if src not in forbidden and dst not in forbidden:
                adjacency[src].add(dst)

        reachable = self._reachable(self.roots, adjacency, forbidden)
        reached = any(target in reachable for target in self.targets)
        return ReachabilityResult(
            reachable_target=reached,
            reachable_nodes=reachable,
            summary_edges=summary_edges,
            summary_iterations=iterations,
            enabled_pair_count=enabled_pair_count,
        )


# ---------------------------------------------------------------------------
# Candidate units and dominator extraction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Candidate:
    key: str
    function: str
    bb: str
    nodes: Tuple[str, ...]


def raw_reverse_reachable(g: ICFG, targets: Iterable[str]) -> Set[str]:
    seen: Set[str] = set()
    q: deque[str] = deque()
    for target in targets:
        if target in g.nodes and target not in seen:
            seen.add(target)
            q.append(target)
    while q:
        cur = q.popleft()
        for pred in g.raw_rev.get(cur, set()):
            if pred not in seen:
                seen.add(pred)
                q.append(pred)
    return seen


def build_candidates(
    g: ICFG,
    baseline_reachable: Set[str],
    target_nodes: Sequence[str],
    granularity: str,
) -> Tuple[List[Candidate], int]:
    # Safe over-approximation of nodes that may lie on some valid root->target
    # execution: valid-prefix reachable AND raw reverse-reachable to target.
    # Raw reverse reachability may include invalid return combinations, but that
    # only adds candidates; it never removes a true dominator candidate.
    reverse_raw = raw_reverse_reachable(g, target_nodes)
    relevant_nodes = baseline_reachable & reverse_raw

    if granularity == "node":
        candidates = []
        for nid in sorted(relevant_nodes):
            n = g.nodes[nid]
            candidates.append(
                Candidate(
                    key=nid,
                    function=n.function,
                    bb=n.bb,
                    nodes=(nid,),
                )
            )
        return candidates, len(relevant_nodes)

    groups: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    unmapped = 0
    for nid in relevant_nodes:
        n = g.nodes[nid]
        if not n.function or not n.bb:
            unmapped += 1
            continue
        groups[(n.function, norm_bb(n.bb))].add(nid)

    candidates = [
        Candidate(
            key=f"{func}:bb={bb}",
            function=func,
            bb=bb,
            # Removing a BB means removing ALL normalized ICFG nodes mapped to
            # that function/basic-block, not only the nodes in the coarse
            # relevant set.
            nodes=tuple(
                sorted(
                    nid
                    for nid, node in g.nodes.items()
                    if node.function == func and norm_bb(node.bb) == bb
                )
            ),
        )
        for (func, bb) in sorted(groups)
    ]
    return candidates, unmapped


def extract_dominators(
    oracle: ContextSensitiveOracle,
    candidates: Sequence[Candidate],
    strict: bool,
    target_nodes: Set[str],
    progress_every: int,
) -> Tuple[List[Candidate], List[Dict[str, object]]]:
    dominators: List[Candidate] = []
    diagnostics: List[Dict[str, object]] = []
    total = len(candidates)
    start_time = time.time()

    for index, candidate in enumerate(candidates, start=1):
        forbidden = set(candidate.nodes)

        is_target_candidate = bool(forbidden & target_nodes)
        if strict and is_target_candidate:
            diagnostics.append(
                {
                    "candidate": candidate.key,
                    "is_dominator": False,
                    "status": "strict-target-skipped",
                    "node_count": len(candidate.nodes),
                }
            )
            continue

        result = oracle.run(forbidden)
        is_dom = not result.reachable_target
        if is_dom:
            dominators.append(candidate)

        diagnostics.append(
            {
                "candidate": candidate.key,
                "is_dominator": is_dom,
                "status": "dominator" if is_dom else "bypass-exists",
                "node_count": len(candidate.nodes),
                "summary_edges": len(result.summary_edges),
                "summary_iterations": result.summary_iterations,
                "enabled_pairs": result.enabled_pair_count,
                "reachable_nodes": len(result.reachable_nodes),
            }
        )

        if progress_every > 0 and (index % progress_every == 0 or index == total):
            elapsed = time.time() - start_time
            print(
                f"[progress] {index}/{total} candidates, dominators={len(dominators)}, "
                f"elapsed={elapsed:.1f}s",
                file=sys.stderr,
            )

    return dominators, diagnostics


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def write_text_output(
    path: Path,
    args: argparse.Namespace,
    g: ICFG,
    roots: Sequence[str],
    target_function: str,
    target_bbs: Set[str],
    target_nodes: Sequence[str],
    target_info: Mapping[str, object],
    baseline: ReachabilityResult,
    candidates: Sequence[Candidate],
    dominators: Sequence[Candidate],
    unmapped_candidate_nodes: int,
    elapsed: float,
) -> None:
    lines: List[str] = [
        f"version: {VERSION}",
        f"target: {args.target}",
        f"target_function: {target_function}",
        f"target_bbs: {','.join(sorted(target_bbs))}",
        f"target_nodes: {','.join(target_nodes)}",
        f"target_resolution_mode: {target_info.get('mode', '')}",
        f"entry_function: {args.entry_function}",
        f"roots: {','.join(roots)}",
        f"granularity: {args.granularity}",
        f"strict: {str(bool(args.strict)).lower()}",
        "path_semantics: well-nested-context-sensitive-summary-fixed-point",
        "comparison_performed: false",
        "",
        "icfg_summary:",
        f"  nodes: {len(g.nodes)}",
        f"  normal_edges: {sum(len(v) for v in g.normal_adj.values())}",
        f"  call_edges: {len(g.call_edges)}",
        f"  return_edges: {len(g.return_edges)}",
        f"  matched_call_return_pairs: {len(g.pairs)}",
        f"  baseline_summary_edges: {len(baseline.summary_edges)}",
        f"  baseline_enabled_pairs: {baseline.enabled_pair_count}",
        f"  baseline_summary_iterations: {baseline.summary_iterations}",
        f"  baseline_reachable_nodes: {len(baseline.reachable_nodes)}",
        f"  candidate_count: {len(candidates)}",
        f"  unmapped_relevant_nodes_skipped_for_bb_granularity: {unmapped_candidate_nodes}",
        f"  dominator_count: {len(dominators)}",
        f"  extraction_time_sec: {elapsed:.6f}",
        "",
        "context_sensitive_dominators:",
    ]

    if dominators:
        for candidate in dominators:
            lines.append(f"  - {candidate.key}")
    else:
        lines.append("  <none>")

    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def write_json_output(
    path: Path,
    args: argparse.Namespace,
    g: ICFG,
    roots: Sequence[str],
    target_function: str,
    target_bbs: Set[str],
    target_nodes: Sequence[str],
    target_info: Mapping[str, object],
    baseline: ReachabilityResult,
    dominators: Sequence[Candidate],
    diagnostics: Sequence[Mapping[str, object]],
    elapsed: float,
) -> None:
    data = {
        "version": VERSION,
        "target": args.target,
        "target_function": target_function,
        "target_bbs": sorted(target_bbs),
        "target_nodes": list(target_nodes),
        "target_resolution": dict(target_info),
        "entry_function": args.entry_function,
        "roots": list(roots),
        "granularity": args.granularity,
        "strict": bool(args.strict),
        "path_semantics": "well-nested-context-sensitive-summary-fixed-point",
        "comparison_performed": False,
        "icfg": {
            "nodes": len(g.nodes),
            "normal_edges": sum(len(v) for v in g.normal_adj.values()),
            "call_edges": len(g.call_edges),
            "return_edges": len(g.return_edges),
            "matched_call_return_pairs": len(g.pairs),
        },
        "baseline": {
            "reachable_target": baseline.reachable_target,
            "reachable_nodes": len(baseline.reachable_nodes),
            "summary_edges": len(baseline.summary_edges),
            "summary_iterations": baseline.summary_iterations,
            "enabled_pairs": baseline.enabled_pair_count,
        },
        "dominators": [
            {
                "key": d.key,
                "function": d.function,
                "bb": d.bb,
                "nodes": list(d.nodes),
            }
            for d in dominators
        ],
        "candidate_diagnostics": list(diagnostics),
        "extraction_time_sec": elapsed,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=(
            "Extract context-sensitive dominators from a normalized/SMLTA ICFG "
            "using definition-based candidate removal. No comparison is performed."
        )
    )
    ap.add_argument("--icfg-dir", required=True, type=Path)
    ap.add_argument("--target", required=True, help="target source location, e.g. elf.c:8205")
    ap.add_argument("--function", help="optional target function disambiguation")
    ap.add_argument(
        "--module-ll",
        help=(
            "optional module.ll for target mapping fallback; if omitted, "
            "<icfg-dir>/module.ll and <icfg-dir>/../module.ll are tried"
        ),
    )
    ap.add_argument("--entry-function", default="main")
    ap.add_argument(
        "--granularity",
        choices=("bb", "node"),
        default="bb",
        help="dominator unit; default: bb",
    )
    ap.add_argument(
        "--strict",
        action="store_true",
        help="extract strict dominators (exclude the target unit itself)",
    )
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        help="text output path; default: <icfg-dir>/context_sensitive_dominators.txt",
    )
    ap.add_argument(
        "--json-output",
        type=Path,
        help="optional JSON diagnostics output",
    )
    ap.add_argument(
        "--progress-every",
        type=int,
        default=100,
        help="print progress every N candidates to stderr; 0 disables",
    )
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    icfg_dir = args.icfg_dir.expanduser().resolve()
    if not icfg_dir.is_dir():
        print(f"[ERROR] icfg-dir not found: {icfg_dir}", file=sys.stderr)
        return 2

    output = (
        args.output.expanduser().resolve()
        if args.output
        else icfg_dir / "context_sensitive_dominators.txt"
    )

    started = time.time()
    try:
        g = load_icfg(icfg_dir)
        if not g.nodes:
            raise ValueError("ICFG contains no nodes")
        if not g.pairs:
            raise ValueError(
                "no matched call/return pairs were found; icfg_phi.tsv or compatible "
                "call/return metadata is required for context-sensitive extraction"
            )

        target_function, target_bbs, target_nodes, target_info = resolve_target(
            args, icfg_dir, g
        )
        roots = g.entry_candidates(args.entry_function)
        if not roots:
            raise ValueError("failed to resolve program root node(s)")

        oracle = ContextSensitiveOracle(g, roots, target_nodes)
        baseline = oracle.run()
        if not baseline.reachable_target:
            raise ValueError(
                "target is not reachable from the selected root(s) under matched "
                "call/return semantics; dominators are undefined for this target"
            )

        candidates, unmapped = build_candidates(
            g,
            baseline_reachable=baseline.reachable_nodes,
            target_nodes=target_nodes,
            granularity=args.granularity,
        )
        if not candidates:
            raise ValueError("no dominator candidates were produced")

        print(
            f"[INFO] target={args.target} function={target_function} "
            f"bbs={','.join(sorted(target_bbs))}",
            file=sys.stderr,
        )
        print(
            f"[INFO] roots={','.join(roots)} nodes={len(g.nodes)} "
            f"pairs={len(g.pairs)} candidates={len(candidates)}",
            file=sys.stderr,
        )

        dominators, diagnostics = extract_dominators(
            oracle=oracle,
            candidates=candidates,
            strict=args.strict,
            target_nodes=set(target_nodes),
            progress_every=max(0, args.progress_every),
        )

        elapsed = time.time() - started
        write_text_output(
            output,
            args,
            g,
            roots,
            target_function,
            target_bbs,
            target_nodes,
            target_info,
            baseline,
            candidates,
            dominators,
            unmapped,
            elapsed,
        )
        if args.json_output:
            write_json_output(
                args.json_output.expanduser().resolve(),
                args,
                g,
                roots,
                target_function,
                target_bbs,
                target_nodes,
                target_info,
                baseline,
                dominators,
                diagnostics,
                elapsed,
            )

    except (OSError, ValueError, RuntimeError, FileNotFoundError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    print(f"[DONE] dominators: {len(dominators)}", file=sys.stderr)
    print(f"[DONE] output: {output}", file=sys.stderr)
    if args.json_output:
        print(f"[DONE] json: {args.json_output.expanduser().resolve()}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
