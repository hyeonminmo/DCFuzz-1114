#!/usr/bin/env python3
"""
extract_dominator.py

ICFG-based interprocedural dominator extractor inspired by:
  De Sutter, Van Put, De Bosschere, "A Practical Interprocedural Dominance Algorithm".

This script replaces the older per-function domtree + call-chain stitching logic.
It consumes normalized ICFG TSV files produced by normalize_svf_icfg.py and computes
context-sensitive interprocedural dominators over valid ICFG paths using:
  1. ICFG G = (V, E, C, R, r, q, phi, lambda)
  2. context-sensitive depth-first traversal (CSDFT) numbering
  3. a constraint graph C whose ancestors represent dominator sets
  4. iterative constraint refinement using ahead(e) for return edges

Expected normalized inputs in --icfg-dir:
  icfg_nodes.tsv
  icfg_edges.tsv
  icfg_call_edges.tsv
  icfg_return_edges.tsv
  icfg_phi.tsv
  icfg_functions.tsv

Typical usage:
  python3 extract_dominator.py \
      --icfg-dir /benchmark/temp_xxx \
      --module-ll /benchmark/temp_xxx/module.ll \
      --target outputscript.c:1687 \
      --function outputSWF_PROTECT \
      > /benchmark/temp_xxx/dominator_nodes.txt

Compatibility usage is also supported:
  python3 extract_dominator.py module.ll domtree.txt outputscript.c:1687 --function outputSWF_PROTECT --icfg-dir /benchmark/temp_xxx

Output keeps the existing human-readable sections and, most importantly:
  program_dominators:
    - function:bb=<bb>  # line=<line>

Notes:
  * The implementation is intentionally conservative and defensive because SVF DOT
    normalization may vary by version. If exact node-to-BB mapping is unavailable,
    the script reports diagnostics instead of silently inventing dominators.
  * The final transitive reduction step is not required for extracting dom(target):
    after convergence, ancestors in the constraint graph represent dominator sets.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


# ---------------------------------------------------------------------------
# LLVM IR parsing utilities for target line -> function/basic block matching
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


def norm_func(name: str) -> str:
    name = (name or "").strip().strip('"')
    if name.startswith("@"):
        name = name[1:]
    return name


def norm_bb(bb: str) -> str:
    bb = (bb or "").strip().strip('"')
    if bb.startswith("%"):
        bb = bb[1:]
    if bb == "":
        return "entry"
    return bb


def md_ref_to_int(v: str) -> Optional[int]:
    if not v:
        return None
    m = re.match(r'!(\d+)$', v.strip())
    return int(m.group(1)) if m else None


def parse_metadata(lines: Sequence[str]) -> Dict[int, Dict[str, object]]:
    nodes: Dict[int, Dict[str, object]] = {}
    for line in lines:
        m = MD_RE.match(line)
        if not m:
            continue
        nid = int(m.group(1))
        tag = m.group(2)
        body = m.group(3)
        attrs: Dict[str, str] = {}
        for km in KV_RE.finditer(body):
            attrs[km.group(1)] = km.group(2).strip()
        nodes[nid] = {"tag": tag, "attrs": attrs, "raw": body}
    return nodes


def get_target_function_dbg(lines: Sequence[str], target_function: str) -> Optional[int]:
    for line in lines:
        m = DEFINE_RE.match(line)
        if not m:
            continue
        fn = norm_func(m.group(1))
        dbg_id = int(m.group(2))
        if fn == target_function:
            return dbg_id
    return None


def scope_reaches_function(nodes: Dict[int, Dict[str, object]], scope_id: Optional[int], func_dbg_id: int) -> bool:
    visited: Set[int] = set()
    cur = scope_id
    while cur is not None and cur not in visited:
        visited.add(cur)
        if cur == func_dbg_id:
            return True
        node = nodes.get(cur)
        if not node:
            return False
        attrs = node.get("attrs", {})  # type: ignore[assignment]
        nxt = md_ref_to_int(attrs.get("scope", ""))  # type: ignore[union-attr]
        if nxt is not None:
            cur = nxt
            continue
        return False
    return False


def dbg_line_from_id(nodes: Dict[int, Dict[str, object]], dbg_id: int) -> Optional[int]:
    node = nodes.get(dbg_id)
    if not node or node.get("tag") != "DILocation":
        return None
    attrs = node.get("attrs", {})  # type: ignore[assignment]
    line_v = attrs.get("line")  # type: ignore[union-attr]
    try:
        return int(line_v) if line_v is not None else None
    except ValueError:
        return None


def collect_target_dbg_ids(nodes: Dict[int, Dict[str, object]], target_line: int, func_dbg_id: int) -> Set[int]:
    dbg_ids: Set[int] = set()
    for nid, node in nodes.items():
        if node.get("tag") != "DILocation":
            continue
        attrs = node.get("attrs", {})  # type: ignore[assignment]
        line_v = attrs.get("line")  # type: ignore[union-attr]
        try:
            line_num = int(line_v) if line_v is not None else None
        except ValueError:
            continue
        if line_num != target_line:
            continue
        scope_id = md_ref_to_int(attrs.get("scope", ""))  # type: ignore[union-attr]
        if scope_reaches_function(nodes, scope_id, func_dbg_id):
            dbg_ids.add(nid)
    return dbg_ids


def collect_instruction_matches(
    lines: Sequence[str], wanted_dbg_ids: Set[int], target_function: str, nodes: Dict[int, Dict[str, object]]
) -> List[Dict[str, object]]:
    matches: List[Dict[str, object]] = []
    in_func = False
    current_func: Optional[str] = None
    current_bb: Optional[str] = None

    for idx, line in enumerate(lines, start=1):
        m = DEFINE_ANY_RE.match(line)
        if m:
            current_func = norm_func(m.group(1))
            in_func = current_func == target_function
            current_bb = "entry"
            continue

        if in_func and re.match(r'^\s*}\s*$', line):
            in_func = False
            current_func = None
            current_bb = None
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

        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue

        dbg_uses = [int(x) for x in DBG_USE_RE.findall(line)]
        hit = sorted(set(dbg_uses) & wanted_dbg_ids)
        if hit:
            src_lines = sorted(
                x for x in (dbg_line_from_id(nodes, dbg_id) for dbg_id in hit) if x is not None
            )
            matches.append(
                {
                    "function": current_func,
                    "bb": current_bb or "entry",
                    "ll_line": idx,
                    "dbg_hits": hit,
                    "src_lines": src_lines,
                    "src_line": src_lines[0] if src_lines else None,
                    "ir": line.rstrip("\n"),
                }
            )
    return matches


def collect_all_bb_representative_lines(lines: Sequence[str], nodes: Dict[int, Dict[str, object]]) -> Dict[str, Dict[str, int]]:
    rep: Dict[str, Dict[str, int]] = defaultdict(dict)
    current_func: Optional[str] = None
    current_bb: Optional[str] = None

    for line in lines:
        m = DEFINE_ANY_RE.match(line)
        if m:
            current_func = norm_func(m.group(1))
            current_bb = "entry"
            continue

        if current_func is not None and re.match(r'^\s*}\s*$', line):
            current_func = None
            current_bb = None
            continue

        if current_func is None:
            continue

        bm = BB_NAMED_RE.match(line)
        if bm:
            current_bb = norm_bb(bm.group(1))
            continue

        om = BB_OLD_RE.match(line)
        if om:
            current_bb = norm_bb(om.group(1))
            continue

        if current_bb is None:
            continue

        dbg_uses = [int(x) for x in DBG_USE_RE.findall(line)]
        src_lines: List[int] = []
        for dbg_id in dbg_uses:
            src_line = dbg_line_from_id(nodes, dbg_id)
            if src_line is not None:
                src_lines.append(src_line)
        if src_lines:
            cand = min(src_lines)
            old = rep[current_func].get(current_bb)
            if old is None or cand < old:
                rep[current_func][current_bb] = cand
    return rep


# ---------------------------------------------------------------------------
# ICFG model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ICFGNode:
    node_id: str
    function: str
    bb: str
    kind: str
    label: str = ""
    source: str = ""


@dataclass(frozen=True)
class ICFGEdge:
    src: str
    dst: str
    kind: str
    callsite_id: str = ""
    raw_label: str = ""


class ICFG:
    def __init__(self) -> None:
        self.nodes: Dict[str, ICFGNode] = {}
        self.edges: List[ICFGEdge] = []
        self.in_edges: Dict[str, List[ICFGEdge]] = defaultdict(list)
        self.out_edges: Dict[str, List[ICFGEdge]] = defaultdict(list)
        self.call_edges: Dict[Tuple[str, str], ICFGEdge] = {}
        self.return_edges: Dict[Tuple[str, str], ICFGEdge] = {}
        self.phi_call_to_return: Dict[Tuple[str, str], Tuple[str, str]] = {}
        self.phi_return_to_call: Dict[Tuple[str, str], Tuple[str, str]] = {}
        self.functions: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: {"entries": set(), "exits": set(), "nodes": set()})

    def add_node(self, n: ICFGNode) -> None:
        self.nodes[n.node_id] = n
        if n.function:
            self.functions[n.function]["nodes"].add(n.node_id)
            if n.kind == "entry":
                self.functions[n.function]["entries"].add(n.node_id)
            if n.kind == "exit":
                self.functions[n.function]["exits"].add(n.node_id)

    def add_edge(self, e: ICFGEdge) -> None:
        self.edges.append(e)
        self.out_edges[e.src].append(e)
        self.in_edges[e.dst].append(e)
        if e.kind == "call":
            self.call_edges[(e.src, e.dst)] = e
        elif e.kind == "return":
            self.return_edges[(e.src, e.dst)] = e

    def node_func(self, node_id: str) -> str:
        return self.nodes.get(node_id, ICFGNode(node_id, "", "", "")).function

    def node_bb(self, node_id: str) -> str:
        return self.nodes.get(node_id, ICFGNode(node_id, "", "", "")).bb

    def ahead(self, e: ICFGEdge) -> Set[str]:
        """ahead(e) from the paper. For return edges, include callee exit and corresponding callsite."""
        if e.kind != "return":
            return {e.src}
        call_pair = self.phi_return_to_call.get((e.src, e.dst))
        if call_pair is None:
            # Conservative fallback: without phi, return edge head alone is valid but less precise.
            return {e.src}
        call_src, _call_dst = call_pair
        return {e.src, call_src}

    def entry_candidates(self, preferred: str = "main") -> List[str]:
        result: List[str] = []
        if preferred in self.functions:
            entries = sorted(self.functions[preferred]["entries"])
            if entries:
                result.extend(entries)
        if not result:
            for fn in ("main", "_start"):
                entries = sorted(self.functions.get(fn, {}).get("entries", []))
                if entries:
                    result.extend(entries)
        if not result:
            # Nodes with no incoming non-return edges are reasonable roots.
            incoming = {e.dst for e in self.edges if e.kind != "return"}
            roots = [nid for nid in self.nodes if nid not in incoming]
            result.extend(sorted(roots)[:1])
        if not result and self.nodes:
            result.append(sorted(self.nodes)[0])
        return result


def read_tsv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def load_icfg(icfg_dir: Path) -> ICFG:
    g = ICFG()

    node_rows = read_tsv(icfg_dir / "icfg_nodes.tsv")
    for r in node_rows:
        node_id = r.get("node_id", "").strip()
        if not node_id:
            continue
        g.add_node(
            ICFGNode(
                node_id=node_id,
                function=norm_func(r.get("function", "")),
                bb=norm_bb(r.get("bb", "")) if r.get("bb", "") else "",
                kind=(r.get("kind", "") or "unknown").strip(),
                label=r.get("label", ""),
                source=r.get("source", ""),
            )
        )

    edge_rows = read_tsv(icfg_dir / "icfg_edges.tsv")
    for r in edge_rows:
        src = r.get("src", "").strip()
        dst = r.get("dst", "").strip()
        if not src or not dst:
            continue
        kind = (r.get("kind", "") or "cfg").strip()
        e = ICFGEdge(src=src, dst=dst, kind=kind, callsite_id=r.get("callsite_id", ""), raw_label=r.get("raw_label", ""))
        g.add_edge(e)
        if src not in g.nodes:
            g.add_node(ICFGNode(src, "", "", "unknown"))
        if dst not in g.nodes:
            g.add_node(ICFGNode(dst, "", "", "unknown"))

    # Prefer explicit call/return tables if present. They may include cleaner callsite ids.
    for r in read_tsv(icfg_dir / "icfg_call_edges.tsv"):
        src = r.get("callsite_node", "").strip()
        dst = r.get("callee_entry_node", "").strip()
        cs = r.get("callsite_id", "").strip()
        if src and dst and (src, dst) in g.call_edges and cs:
            old = g.call_edges[(src, dst)]
            g.call_edges[(src, dst)] = ICFGEdge(old.src, old.dst, old.kind, cs, old.raw_label)

    for r in read_tsv(icfg_dir / "icfg_return_edges.tsv"):
        src = r.get("callee_exit_node", "").strip()
        dst = r.get("return_node", "").strip()
        cs = r.get("callsite_id", "").strip()
        if src and dst and (src, dst) in g.return_edges and cs:
            old = g.return_edges[(src, dst)]
            g.return_edges[(src, dst)] = ICFGEdge(old.src, old.dst, old.kind, cs, old.raw_label)

    for r in read_tsv(icfg_dir / "icfg_phi.tsv"):
        csrc = r.get("call_edge_src", "").strip()
        cdst = r.get("call_edge_dst", "").strip()
        rsrc = r.get("return_edge_src", "").strip()
        rdst = r.get("return_edge_dst", "").strip()
        if csrc and cdst and rsrc and rdst:
            g.phi_call_to_return[(csrc, cdst)] = (rsrc, rdst)
            g.phi_return_to_call[(rsrc, rdst)] = (csrc, cdst)

    # If phi.tsv is incomplete, match by callsite_id.
    calls_by_id: Dict[str, Tuple[str, str]] = {}
    for pair, e in g.call_edges.items():
        if e.callsite_id:
            calls_by_id[e.callsite_id] = pair
    for pair, e in g.return_edges.items():
        if e.callsite_id and e.callsite_id in calls_by_id and pair not in g.phi_return_to_call:
            cp = calls_by_id[e.callsite_id]
            g.phi_call_to_return[cp] = pair
            g.phi_return_to_call[pair] = cp

    # Fill entry/exit sets from functions TSV if available.
    for r in read_tsv(icfg_dir / "icfg_functions.tsv"):
        fn = norm_func(r.get("function", ""))
        if not fn:
            continue
        for x in r.get("entry_nodes", "").split(","):
            x = x.strip()
            if x:
                g.functions[fn]["entries"].add(x)
        for x in r.get("exit_nodes", "").split(","):
            x = x.strip()
            if x:
                g.functions[fn]["exits"].add(x)

    return g


# ---------------------------------------------------------------------------
# CSDFT numbering
# ---------------------------------------------------------------------------

def csdft_numbering(g: ICFG, roots: Sequence[str]) -> Dict[str, int]:
    """Preorder context-sensitive DFT numbering.

    This follows the spirit of the paper's CSDFT:
      - CFG/call successors can be traversed normally.
      - A return edge tail is scheduled only after both the callee exit and the
        corresponding callsite have been numbered.
      - When visiting a callsite, its matching return node may become schedulable
        if the callee exit has already been numbered.
    """
    dft: Dict[str, int] = {}
    stack: List[str] = list(reversed([r for r in roots if r in g.nodes]))

    def maybe_schedule_return_tail(ret_pair: Tuple[str, str]) -> None:
        rsrc, rdst = ret_pair
        cp = g.phi_return_to_call.get(ret_pair)
        if cp is None:
            if rsrc in dft and rdst not in dft:
                stack.append(rdst)
            return
        csrc, _cdst = cp
        if rsrc in dft and csrc in dft and rdst not in dft:
            stack.append(rdst)

    # Seed disconnected roots if root selection was too narrow.
    all_nodes_sorted = sorted(g.nodes)
    root_seeded = set(stack)
    for n in all_nodes_sorted:
        if n not in root_seeded and not g.in_edges.get(n):
            stack.append(n)
            root_seeded.add(n)

    next_num = 0
    while stack:
        v = stack.pop()
        if v in dft or v not in g.nodes:
            continue
        dft[v] = next_num
        next_num += 1

        # If v is a callsite head, corresponding return nodes may now be valid.
        for e in g.out_edges.get(v, []):
            if e.kind == "call":
                rp = g.phi_call_to_return.get((e.src, e.dst))
                if rp is not None:
                    maybe_schedule_return_tail(rp)

        # If v is a callee exit head, corresponding return nodes may now be valid.
        for e in g.out_edges.get(v, []):
            if e.kind == "return":
                maybe_schedule_return_tail((e.src, e.dst))

        # Normal successors. Return successors are handled only through maybe_schedule_return_tail.
        succs: List[str] = []
        for e in g.out_edges.get(v, []):
            if e.kind == "return":
                continue
            if e.dst not in dft:
                succs.append(e.dst)
        # Deterministic preorder: push reversed sorted successors.
        for dst in reversed(sorted(set(succs))):
            stack.append(dst)

    # Conservative completion: if SVF normalization left disconnected pieces,
    # number them last so algorithm can still report reachable target diagnostics.
    for n in all_nodes_sorted:
        if n not in dft:
            dft[n] = next_num
            next_num += 1
    return dft


# ---------------------------------------------------------------------------
# Constraint graph based dominator computation
# ---------------------------------------------------------------------------

class ConstraintGraph:
    def __init__(self, nodes: Iterable[str]) -> None:
        self.pred: Dict[str, Set[str]] = {n: set() for n in nodes}
        self.succ: Dict[str, Set[str]] = {n: set() for n in nodes}

    def set_pred(self, v: str, new_pred: Set[str]) -> bool:
        new_pred = {p for p in new_pred if p != v}
        old = self.pred.get(v, set())
        if old == new_pred:
            return False
        for p in old:
            self.succ.get(p, set()).discard(v)
        self.pred[v] = set(new_pred)
        self.succ.setdefault(v, set())
        for p in new_pred:
            self.succ.setdefault(p, set()).add(v)
        return True

    def ancestors(self, starts: Iterable[str]) -> Set[str]:
        result: Set[str] = set()
        stack = list(starts)
        while stack:
            x = stack.pop()
            if x in result:
                continue
            result.add(x)
            stack.extend(self.pred.get(x, ()))
        return result

    def descendants(self, starts: Iterable[str]) -> Set[str]:
        result: Set[str] = set()
        stack = list(starts)
        while stack:
            x = stack.pop()
            if x in result:
                continue
            result.add(x)
            stack.extend(self.succ.get(x, ()))
        return result


def initial_constraint_graph(g: ICFG, dft: Dict[str, int], root_nodes: Set[str]) -> ConstraintGraph:
    c = ConstraintGraph(g.nodes.keys())
    inf = 10**18

    for v in g.nodes:
        if v in root_nodes:
            c.set_pred(v, set())
            continue

        incoming = g.in_edges.get(v, [])
        if not incoming:
            c.set_pred(v, set())
            continue

        # Choose incoming edge with minimum max DFT over ahead(e). This is a practical
        # generalization of init(v) that handles normalized ICFGs robustly.
        best_edge: Optional[ICFGEdge] = None
        best_key: Tuple[int, int, str] = (inf, inf, "")
        for e in incoming:
            ah = g.ahead(e)
            if not ah:
                continue
            max_d = max(dft.get(x, inf) for x in ah)
            min_d = min(dft.get(x, inf) for x in ah)
            key = (max_d, min_d, f"{e.src}->{e.dst}:{e.kind}")
            if key < best_key:
                best_key = key
                best_edge = e

        if best_edge is None:
            c.set_pred(v, set())
        else:
            c.set_pred(v, set(g.ahead(best_edge)))
    return c


def independent_intersect(c: ConstraintGraph, s1: Set[str], s2: Set[str], dft: Dict[str, int]) -> Set[str]:
    """Return nodes P such that anc(P) approximates anc(s1) ∩ anc(s2).

    This follows the paper's Intersect idea: mark ancestors of s2, then walk
    upward from s1 until marked nodes are reached. The returned predecessor set
    is independent of the ancestors of returned nodes because traversal stops at
    those nodes.
    """
    if not s1 or not s2:
        return set()

    marked = c.ancestors(s2)
    pred: Set[str] = set()
    to_visit: List[str] = sorted(s1, key=lambda x: dft.get(x, 10**18), reverse=True)
    visited: Set[str] = set()

    while to_visit:
        v = to_visit.pop()
        if v in visited:
            continue
        visited.add(v)
        if v in marked:
            pred.add(v)
            continue
        for p in c.pred.get(v, ()):
            if p not in visited:
                to_visit.append(p)
    return pred


def comp_constraint(g: ICFG, c: ConstraintGraph, v: str, dft: Dict[str, int]) -> Set[str]:
    incoming = g.in_edges.get(v, [])
    if not incoming:
        return set()

    ahead_sets = [g.ahead(e) for e in incoming]
    ahead_sets = [s for s in ahead_sets if s]
    if not ahead_sets:
        return set()

    # Deterministic order: start with the ahead set whose nodes are most local/high-numbered.
    ahead_sets.sort(key=lambda s: (min(dft.get(x, 10**18) for x in s), len(s)))
    cur = set(ahead_sets[0])
    for nxt in ahead_sets[1:]:
        cur = independent_intersect(c, cur, set(nxt), dft)
        if not cur:
            break
    cur.discard(v)
    return cur


def compute_interprocedural_dominators(
    g: ICFG,
    dft: Dict[str, int],
    roots: Sequence[str],
    max_iter: int = 100000,
) -> ConstraintGraph:
    root_set = set(roots)
    c = initial_constraint_graph(g, dft, root_set)

    # Work-list refinement. Nodes with <=1 incoming edge usually already have the
    # strictest constraint, but recomputing them is harmless and simplifies logic.
    order = sorted(g.nodes.keys(), key=lambda n: dft.get(n, 10**18))
    work = deque(order)
    in_work = set(order)
    iterations = 0

    while work:
        v = work.popleft()
        in_work.discard(v)
        iterations += 1
        if iterations > max_iter:
            raise RuntimeError(f"constraint refinement did not converge within {max_iter} steps")
        if v in root_set:
            continue
        new_pred = comp_constraint(g, c, v, dft)
        old_anc = c.ancestors([v])
        changed = c.set_pred(v, new_pred)
        if changed:
            new_anc = c.ancestors([v])
            removed = old_anc - new_anc
            # Conservative scheduling: all ICFG successors and constraint descendants
            # that could be affected are revisited.
            affected: Set[str] = set()
            affected.update(e.dst for e in g.out_edges.get(v, []))
            affected.update(c.descendants([v]))
            for r in removed:
                affected.update(c.descendants([r]))
            for a in affected:
                if a in g.nodes and a not in in_work:
                    work.append(a)
                    in_work.add(a)
    return c


# ---------------------------------------------------------------------------
# Target node mapping and output helpers
# ---------------------------------------------------------------------------

def infer_target_function_from_module_ll(module_ll: Path, target: str) -> Optional[str]:
    """Infer the LLVM IR function containing target file:line using DILocation scope."""
    if ":" not in target:
        return None
    target_file, line_s = target.rsplit(":", 1)
    try:
        target_line = int(line_s)
    except ValueError:
        return None

    lines = module_ll.read_text(encoding="utf-8", errors="replace").splitlines(True)
    md_nodes = parse_metadata(lines)

    def function_name_from_scope(scope_id: Optional[int]) -> Optional[str]:
        seen: Set[int] = set()
        cur = scope_id
        while cur is not None and cur not in seen:
            seen.add(cur)
            node = md_nodes.get(cur)
            if not node:
                return None
            attrs = node.get("attrs", {}) if isinstance(node.get("attrs"), dict) else {}
            if node.get("tag") == "DISubprogram":
                name = attrs.get("name") or attrs.get("linkageName")
                return str(name).strip().strip('"') if name else None
            cur = md_ref_to_int(str(attrs.get("scope", "")))
        return None

    def file_score(node: Dict[str, object]) -> int:
        attrs = node.get("attrs", {}) if isinstance(node.get("attrs"), dict) else {}
        file_ref = md_ref_to_int(str(attrs.get("file", "")))
        if file_ref is None:
            return 0
        fnode = md_nodes.get(file_ref)
        if not fnode or fnode.get("tag") != "DIFile":
            return 0
        fattrs = fnode.get("attrs", {}) if isinstance(fnode.get("attrs"), dict) else {}
        filename = str(fattrs.get("filename", "")).strip().strip('"')
        directory = str(fattrs.get("directory", "")).strip().strip('"')
        full = f"{directory}/{filename}" if directory else filename
        if full and (target_file.endswith(full) or full.endswith(target_file)):
            return 30
        if filename and (target_file.endswith(filename) or filename.endswith(target_file)):
            return 20
        if filename and filename in target_file:
            return 10
        return 0

    candidates: List[Tuple[int, str]] = []
    for _nid, node in md_nodes.items():
        if node.get("tag") != "DILocation":
            continue
        attrs = node.get("attrs", {}) if isinstance(node.get("attrs"), dict) else {}
        try:
            ln = int(str(attrs.get("line", "-1")))
        except ValueError:
            continue
        if ln != target_line:
            continue
        fn = function_name_from_scope(md_ref_to_int(str(attrs.get("scope", ""))))
        if fn:
            candidates.append((file_score(node), fn))

    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


def target_bbs_from_module_ll(module_ll: Path, target: str, function: str) -> Tuple[Optional[int], Set[str], List[Dict[str, object]], Dict[str, Dict[str, int]], List[int], Optional[int]]:
    if ":" not in target:
        raise ValueError("target must be file:line")
    _, line_s = target.rsplit(":", 1)
    target_line = int(line_s)
    lines = module_ll.read_text(encoding="utf-8", errors="replace").splitlines(True)
    md_nodes = parse_metadata(lines)
    func_dbg_id = get_target_function_dbg(lines, function)
    if func_dbg_id is None:
        return target_line, set(), [], collect_all_bb_representative_lines(lines, md_nodes), [], None
    wanted_dbg_ids = collect_target_dbg_ids(md_nodes, target_line, func_dbg_id)
    instr_matches = collect_instruction_matches(lines, wanted_dbg_ids, function, md_nodes)
    bb_set = {norm_bb(str(m["bb"])) for m in instr_matches}
    rep = collect_all_bb_representative_lines(lines, md_nodes)
    return target_line, bb_set, instr_matches, rep, sorted(wanted_dbg_ids), func_dbg_id


def find_icfg_nodes_for_function_bbs(g: ICFG, function: str, bbs: Set[str]) -> List[str]:
    bbs_norm = {norm_bb(b) for b in bbs}
    hits: List[str] = []
    for nid, n in g.nodes.items():
        if n.function != function:
            continue
        if norm_bb(n.bb) in bbs_norm:
            hits.append(nid)
    # Some normalizers represent BB-specific call/return nodes with bb empty but label contains bb.
    if not hits:
        for nid, n in g.nodes.items():
            if n.function != function:
                continue
            label = n.label or ""
            for bb in bbs_norm:
                if re.search(rf'\b{re.escape(bb)}\b', label):
                    hits.append(nid)
    return sorted(set(hits))


def choose_representative_node_per_bb(g: ICFG, nodes: Iterable[str]) -> Dict[Tuple[str, str], str]:
    result: Dict[Tuple[str, str], str] = {}
    priority = {"entry": 0, "intra": 1, "call": 2, "return": 3, "exit": 4, "unknown": 5}
    for nid in nodes:
        n = g.nodes[nid]
        key = (n.function, norm_bb(n.bb))
        if key not in result:
            result[key] = nid
            continue
        old = g.nodes[result[key]]
        if priority.get(n.kind, 9) < priority.get(old.kind, 9):
            result[key] = nid
    return result


def dominator_ancestors_for_targets(c: ConstraintGraph, target_nodes: Sequence[str]) -> Set[str]:
    if not target_nodes:
        return set()
    dom_sets = [c.ancestors([t]) for t in target_nodes]
    common = set(dom_sets[0])
    for ds in dom_sets[1:]:
        common &= ds
    return common


def format_program_dominators(
    g: ICFG,
    dom_nodes: Set[str],
    dft: Dict[str, int],
    bb_rep_lines: Dict[str, Dict[str, int]],
    strict: bool = False,
    target_nodes: Optional[Set[str]] = None,
) -> List[Tuple[str, str, Optional[int], str]]:
    rows: List[Tuple[int, str, str, Optional[int], str]] = []
    target_nodes = target_nodes or set()
    for nid in dom_nodes:
        if strict and nid in target_nodes:
            continue
        n = g.nodes.get(nid)
        if not n or not n.function:
            continue
        bb = norm_bb(n.bb) if n.bb else "entry"
        rep_line = bb_rep_lines.get(n.function, {}).get(bb)
        rows.append((dft.get(nid, 10**18), n.function, bb, rep_line, nid))

    # De-duplicate by function/bb while preserving earliest CSDFT order.
    out: List[Tuple[str, str, Optional[int], str]] = []
    seen: Set[Tuple[str, str]] = set()
    for _num, fn, bb, line, nid in sorted(rows, key=lambda x: (x[0], x[1], x[2], x[4])):
        key = (fn, bb)
        if key in seen:
            continue
        seen.add(key)
        out.append((fn, bb, line, nid))
    return out


def print_diagnostics_header(
    target: str,
    function: str,
    func_dbg_id: Optional[int],
    wanted_dbg_ids: Sequence[int],
    instr_matches: Sequence[Dict[str, object]],
) -> None:
    print(f"target: {target}")
    print(f"target_function: {function}")
    if func_dbg_id is not None:
        print(f"function_dbg_id: !{func_dbg_id}")
    else:
        print("function_dbg_id: <not found>")
    print()

    if wanted_dbg_ids:
        print("matched_dilocations:")
        for x in wanted_dbg_ids:
            print(f"  - !{x}")
        print()
    else:
        print("matched_dilocations: <none>")
        print()

    if instr_matches:
        print("matched_instructions:")
        for m in instr_matches:
            dbg_str = ", ".join(f"!{x}" for x in m.get("dbg_hits", []))
            print(
                f"  - function={m.get('function')} bb={m.get('bb')} "
                f"ll_line={m.get('ll_line')} src_line={m.get('src_line')} dbg={dbg_str}"
            )
            print(f"    ir: {m.get('ir')}")
        print()
    else:
        print("matched_instructions: <none>")
        print()


def infer_icfg_dir(args: argparse.Namespace) -> Path:
    if args.icfg_dir:
        return Path(args.icfg_dir)
    if args.module_ll:
        return Path(args.module_ll).resolve().parent
    if args.positional and len(args.positional) >= 1:
        return Path(args.positional[0]).resolve().parent
    return Path.cwd()


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument("positional", nargs="*", help="compat: <module.ll> <domtree.txt> <target>")
    ap.add_argument("--icfg-dir", help="directory containing normalized icfg_*.tsv files")
    ap.add_argument("--module-ll", help="LLVM IR file used for target debug-line matching")
    ap.add_argument("--target", help="target location, e.g. outputscript.c:1687")
    ap.add_argument("--function", help="target function name; if omitted, infer from target debug location")
    ap.add_argument("--entry-function", default="main", help="program entry function name, default: main")
    ap.add_argument("--strict", action="store_true", help="exclude target node itself from output dominator list")
    ap.add_argument("--max-iter", type=int, default=1000000)
    ap.add_argument("--dump-csdft", action="store_true")
    ap.add_argument("--dump-constraints", action="store_true")
    args = ap.parse_args(argv)

    # Compatibility with old invocation: extract_dominator.py module.ll domtree.txt target --function F
    if not args.module_ll and len(args.positional) >= 1:
        args.module_ll = args.positional[0]
    if not args.target and len(args.positional) >= 3:
        args.target = args.positional[2]

    if not args.module_ll:
        ap.error("--module-ll is required, or provide old positional <module.ll>")
    if not args.target:
        ap.error("--target is required, or provide old positional <target>")
    return args


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    module_ll = Path(args.module_ll)
    icfg_dir = infer_icfg_dir(args)

    if not module_ll.exists():
        print(f"ERROR: module.ll not found: {module_ll}", file=sys.stderr)
        return 2
    if not icfg_dir.exists():
        print(f"ERROR: icfg-dir not found: {icfg_dir}", file=sys.stderr)
        return 2

    if not args.function:
        args.function = infer_target_function_from_module_ll(module_ll, args.target)
        if not args.function:
            print(f"ERROR: failed to infer target function for {args.target}", file=sys.stderr)
            return 2

    try:
        target_line, target_bbs, instr_matches, bb_rep_lines, wanted_dbg_ids, func_dbg_id = target_bbs_from_module_ll(
            module_ll, args.target, args.function
        )
    except Exception as exc:
        print(f"ERROR: failed to map target debug line: {exc}", file=sys.stderr)
        return 2

    print_diagnostics_header(args.target, args.function, func_dbg_id, wanted_dbg_ids, instr_matches)

    if not target_bbs:
        print("status: target basic block not found from debug locations")
        print("program_dominators:")
        print("  <none>")
        return 1

    g = load_icfg(icfg_dir)
    if not g.nodes or not g.edges:
        print("status: normalized ICFG is empty or incomplete")
        print("program_dominators:")
        print("  <none>")
        return 1

    roots = g.entry_candidates(args.entry_function)
    dft = csdft_numbering(g, roots)

    target_nodes = find_icfg_nodes_for_function_bbs(g, args.function, target_bbs)

    print("icfg_summary:")
    print(f"  icfg_dir: {icfg_dir}")
    print(f"  nodes: {len(g.nodes)}")
    print(f"  edges: {len(g.edges)}")
    print(f"  call_edges: {sum(1 for e in g.edges if e.kind == 'call')}")
    print(f"  return_edges: {sum(1 for e in g.edges if e.kind == 'return')}")
    print(f"  phi_pairs: {len(g.phi_call_to_return)}")
    print(f"  roots: {', '.join(roots) if roots else '<none>'}")
    print()

    print("target_basic_blocks:")
    for bb in sorted(target_bbs):
        print(f"  - {args.function}:bb={bb}")
    print()

    print("target_icfg_nodes:")
    if target_nodes:
        for nid in target_nodes:
            n = g.nodes[nid]
            print(f"  - node={nid} function={n.function} bb={n.bb or '?'} kind={n.kind} csdft={dft.get(nid)}")
    else:
        print("  <none>")
    print()

    if not target_nodes:
        print("status: target BB was found in module.ll, but no matching ICFG node was found")
        print("hint: check normalize_svf_icfg.py node function/bb extraction from SVF DOT labels")
        print("program_dominators:")
        print("  <none>")
        return 1

    if args.dump_csdft:
        print("csdft_order:")
        for nid in sorted(g.nodes, key=lambda x: dft.get(x, 10**18)):
            n = g.nodes[nid]
            print(f"  - {dft[nid]}\t{nid}\t{n.function}\t{n.bb}\t{n.kind}")
        print()

    try:
        c = compute_interprocedural_dominators(g, dft, roots, max_iter=args.max_iter)
    except RuntimeError as exc:
        print(f"status: {exc}")
        print("program_dominators:")
        print("  <none>")
        return 1

    if args.dump_constraints:
        print("constraint_graph_pred:")
        for nid in sorted(g.nodes, key=lambda x: dft.get(x, 10**18)):
            preds = sorted(c.pred.get(nid, []), key=lambda x: dft.get(x, 10**18))
            print(f"  - {nid}: {', '.join(preds) if preds else '<root>'}")
        print()

    dom_nodes = dominator_ancestors_for_targets(c, target_nodes)
    rows = format_program_dominators(g, dom_nodes, dft, bb_rep_lines, strict=args.strict, target_nodes=set(target_nodes))

    print("bb_rep_lines:")
    for func_name in sorted(bb_rep_lines):
        for bb, ln in sorted(bb_rep_lines[func_name].items(), key=lambda x: x[0]):
            print(f"  {func_name}:{bb} -> {ln}")
    print()

    print("program_dominators:")
    if not rows:
        print("  <none>")
    else:
        for fn, bb, line, _nid in rows:
            if line is None:
                print(f"  - {fn}:bb={bb}  # line=?")
            else:
                print(f"  - {fn}:bb={bb}  # line={line}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
