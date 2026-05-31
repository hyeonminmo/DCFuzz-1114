#!/usr/bin/env python3
"""
extract_valid_paths.py

Target-oriented valid-path structure summarizer for normalized SVF ICFG TSVs.

This version intentionally does NOT enumerate every concrete valid path.  It:
  1) summarizes the root-to-target relevant ICFG region,
  2) folds ordinary control-flow cycles as LOOP-SCC,
  3) folds recursive call-graph cycles as RECURSION-CYCLE,
  4) emits interprocedural dominator order signatures, i.e., the target
     dominator set ordered by each distinguishable valid signature-state.

It is compatible with the previous build script options such as --max-depth,
--max-paths, --state-repeat-limit, --max-recursion-unroll, and --verbose-paths;
those options are accepted but no longer drive concrete path enumeration.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Deque, Dict, Iterable, List, Optional, Sequence, Set, Tuple

# ---------------------------------------------------------------------------
# TSV / LLVM debug helpers
# ---------------------------------------------------------------------------

DEFINE_RE = re.compile(r'^\s*define\b.*@("?[-A-Za-z$._0-9]+"?)\s*\(.*\).*?!dbg\s+!(\d+)\s*\{')
DEFINE_ANY_RE = re.compile(r'^\s*define\b.*@("?[-A-Za-z$._0-9]+"?)\s*\(')
MD_RE = re.compile(r'^\s*!(\d+)\s*=\s*(?:distinct\s+)?!([A-Za-z0-9_]+)\((.*)\)\s*$')
KV_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([^,][^,]*?(?=(?:,\s+[A-Za-z_][A-Za-z0-9_]*\s*:)|$))')
BB_NAMED_RE = re.compile(r'^\s*([A-Za-z$._-][A-Za-z$._0-9-]*|\d+):(?:\s*;.*)?$')
BB_OLD_RE = re.compile(r'^\s*;\s*<label>:(\d+):')
DBG_USE_RE = re.compile(r'!dbg\s+!(\d+)')


def raise_csv_field_limit() -> None:
    limit = sys.maxsize
    while True:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


raise_csv_field_limit()


def norm_func(name: str) -> str:
    name = (name or '').strip().strip('"')
    return name[1:] if name.startswith('@') else name


def norm_bb(bb: str) -> str:
    bb = (bb or '').strip().strip('"')
    if bb.startswith('%'):
        bb = bb[1:]
    return bb or 'entry'


def read_tsv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open('r', encoding='utf-8', errors='replace', newline='') as f:
        return list(csv.DictReader(f, delimiter='\t'))


def md_ref_to_int(v: str) -> Optional[int]:
    m = re.match(r'!(\d+)$', (v or '').strip())
    return int(m.group(1)) if m else None


def parse_metadata(lines: Sequence[str]) -> Dict[int, Dict[str, object]]:
    out: Dict[int, Dict[str, object]] = {}
    for line in lines:
        m = MD_RE.match(line)
        if not m:
            continue
        attrs: Dict[str, str] = {}
        for km in KV_RE.finditer(m.group(3)):
            attrs[km.group(1)] = km.group(2).strip()
        out[int(m.group(1))] = {'tag': m.group(2), 'attrs': attrs, 'raw': m.group(3)}
    return out


def get_target_function_dbg(lines: Sequence[str], target_function: str) -> Optional[int]:
    for line in lines:
        m = DEFINE_RE.match(line)
        if m and norm_func(m.group(1)) == target_function:
            return int(m.group(2))
    return None


def scope_reaches_function(md: Dict[int, Dict[str, object]], scope_id: Optional[int], func_dbg_id: int) -> bool:
    seen: Set[int] = set()
    cur = scope_id
    while cur is not None and cur not in seen:
        seen.add(cur)
        if cur == func_dbg_id:
            return True
        node = md.get(cur)
        if not node or not isinstance(node.get('attrs'), dict):
            return False
        cur = md_ref_to_int(str(node['attrs'].get('scope', '')))  # type: ignore[index]
    return False


def infer_target_function_from_module_ll(module_ll: Path, target: str) -> Optional[str]:
    if ':' not in target:
        return None
    target_file, line_s = target.rsplit(':', 1)
    try:
        target_line = int(line_s)
    except ValueError:
        return None

    lines = module_ll.read_text(encoding='utf-8', errors='replace').splitlines(True)
    md = parse_metadata(lines)

    def func_from_scope(scope_id: Optional[int]) -> Optional[str]:
        seen: Set[int] = set()
        cur = scope_id
        while cur is not None and cur not in seen:
            seen.add(cur)
            node = md.get(cur)
            if not node or not isinstance(node.get('attrs'), dict):
                return None
            attrs = node['attrs']  # type: ignore[assignment]
            if node.get('tag') == 'DISubprogram':
                name = attrs.get('name') or attrs.get('linkageName')
                return str(name).strip().strip('"') if name else None
            cur = md_ref_to_int(str(attrs.get('scope', '')))
        return None

    def file_score(node: Dict[str, object]) -> int:
        attrs = node.get('attrs', {}) if isinstance(node.get('attrs'), dict) else {}
        file_ref = md_ref_to_int(str(attrs.get('file', '')))
        if file_ref is None:
            return 0
        fnode = md.get(file_ref)
        if not fnode or fnode.get('tag') != 'DIFile' or not isinstance(fnode.get('attrs'), dict):
            return 0
        fattrs = fnode['attrs']  # type: ignore[assignment]
        filename = str(fattrs.get('filename', '')).strip().strip('"')
        directory = str(fattrs.get('directory', '')).strip().strip('"')
        full = f'{directory}/{filename}' if directory else filename
        if full and (target_file.endswith(full) or full.endswith(target_file)):
            return 30
        if filename and (target_file.endswith(filename) or filename.endswith(target_file)):
            return 20
        if filename and filename in target_file:
            return 10
        return 0

    cands: List[Tuple[int, str]] = []
    for node in md.values():
        if node.get('tag') != 'DILocation' or not isinstance(node.get('attrs'), dict):
            continue
        attrs = node['attrs']  # type: ignore[assignment]
        try:
            ln = int(str(attrs.get('line', '-1')))
        except ValueError:
            continue
        if ln != target_line:
            continue
        fn = func_from_scope(md_ref_to_int(str(attrs.get('scope', ''))))
        if fn:
            cands.append((file_score(node), fn))
    if not cands:
        return None
    cands.sort(key=lambda x: x[0], reverse=True)
    return cands[0][1]


def target_bbs_from_module_ll(module_ll: Path, target: str, function: str) -> Tuple[Set[str], List[Dict[str, object]], List[int], Optional[int]]:
    if ':' not in target:
        raise ValueError('target must be file:line')
    _, line_s = target.rsplit(':', 1)
    target_line = int(line_s)
    lines = module_ll.read_text(encoding='utf-8', errors='replace').splitlines(True)
    md = parse_metadata(lines)
    func_dbg_id = get_target_function_dbg(lines, function)
    if func_dbg_id is None:
        return set(), [], [], None

    wanted: Set[int] = set()
    for nid, node in md.items():
        if node.get('tag') != 'DILocation' or not isinstance(node.get('attrs'), dict):
            continue
        attrs = node['attrs']  # type: ignore[assignment]
        try:
            ln = int(str(attrs.get('line', '-1')))
        except ValueError:
            continue
        if ln == target_line and scope_reaches_function(md, md_ref_to_int(str(attrs.get('scope', ''))), func_dbg_id):
            wanted.add(nid)

    matches: List[Dict[str, object]] = []
    in_func = False
    current_func: Optional[str] = None
    current_bb = 'entry'
    for idx, line in enumerate(lines, 1):
        m = DEFINE_ANY_RE.match(line)
        if m:
            current_func = norm_func(m.group(1))
            in_func = current_func == function
            current_bb = 'entry'
            continue
        if in_func and re.match(r'^\s*}\s*$', line):
            in_func = False
            current_func = None
            current_bb = 'entry'
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
        if not line.strip() or line.strip().startswith(';'):
            continue
        hits = sorted(set(int(x) for x in DBG_USE_RE.findall(line)) & wanted)
        if hits:
            matches.append({'function': current_func, 'bb': current_bb, 'll_line': idx, 'dbg_hits': hits, 'ir': line.rstrip('\n')})
    return {norm_bb(str(m['bb'])) for m in matches}, matches, sorted(wanted), func_dbg_id

# ---------------------------------------------------------------------------
# ICFG model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ICFGNode:
    node_id: str
    function: str
    bb: str
    kind: str
    label: str = ''
    source: str = ''


@dataclass(frozen=True)
class ICFGEdge:
    src: str
    dst: str
    kind: str = 'cfg'
    callsite_id: str = ''
    raw_label: str = ''


class ICFG:
    def __init__(self) -> None:
        self.nodes: Dict[str, ICFGNode] = {}
        self.edges: List[ICFGEdge] = []
        self.in_edges: Dict[str, List[ICFGEdge]] = defaultdict(list)
        self.out_edges: Dict[str, List[ICFGEdge]] = defaultdict(list)
        self.functions: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: {'entries': set(), 'exits': set(), 'nodes': set()})
        self.phi_call_to_return: Dict[Tuple[str, str], Tuple[str, str]] = {}
        self.phi_return_to_call: Dict[Tuple[str, str], Tuple[str, str]] = {}

    def add_node(self, n: ICFGNode) -> None:
        self.nodes[n.node_id] = n
        if n.function:
            self.functions[n.function]['nodes'].add(n.node_id)
            if n.kind == 'entry':
                self.functions[n.function]['entries'].add(n.node_id)
            if n.kind == 'exit':
                self.functions[n.function]['exits'].add(n.node_id)

    def add_edge(self, e: ICFGEdge) -> None:
        self.edges.append(e)
        self.out_edges[e.src].append(e)
        self.in_edges[e.dst].append(e)

    def entry_candidates(self, preferred: str = 'main') -> List[str]:
        for fn in (preferred, 'main', '_start'):
            entries = sorted(self.functions.get(fn, {}).get('entries', []))
            if entries:
                return entries
        incoming = {e.dst for e in self.edges if e.kind != 'return'}
        roots = [n for n in self.nodes if n not in incoming]
        return sorted(roots)[:1] if roots else (sorted(self.nodes)[:1] if self.nodes else [])


def load_icfg(icfg_dir: Path) -> ICFG:
    g = ICFG()
    for r in read_tsv(icfg_dir / 'icfg_nodes.tsv'):
        nid = r.get('node_id', '').strip()
        if not nid:
            continue
        g.add_node(ICFGNode(nid, norm_func(r.get('function', '')), norm_bb(r.get('bb', '')) if r.get('bb', '') else '', (r.get('kind', '') or 'unknown').strip(), r.get('label', ''), r.get('source', '')))
    for r in read_tsv(icfg_dir / 'icfg_edges.tsv'):
        src, dst = r.get('src', '').strip(), r.get('dst', '').strip()
        if not src or not dst:
            continue
        e = ICFGEdge(src, dst, (r.get('kind', '') or 'cfg').strip(), r.get('callsite_id', ''), r.get('raw_label', ''))
        g.add_edge(e)
        if src not in g.nodes:
            g.add_node(ICFGNode(src, '', '', 'unknown'))
        if dst not in g.nodes:
            g.add_node(ICFGNode(dst, '', '', 'unknown'))
    for r in read_tsv(icfg_dir / 'icfg_functions.tsv'):
        fn = norm_func(r.get('function', ''))
        if not fn:
            continue
        for x in r.get('entry_nodes', '').split(','):
            if x.strip():
                g.functions[fn]['entries'].add(x.strip())
        for x in r.get('exit_nodes', '').split(','):
            if x.strip():
                g.functions[fn]['exits'].add(x.strip())
    for r in read_tsv(icfg_dir / 'icfg_phi.tsv'):
        csrc, cdst = r.get('call_edge_src', '').strip(), r.get('call_edge_dst', '').strip()
        rsrc, rdst = r.get('return_edge_src', '').strip(), r.get('return_edge_dst', '').strip()
        if csrc and cdst and rsrc and rdst:
            g.phi_call_to_return[(csrc, cdst)] = (rsrc, rdst)
            g.phi_return_to_call[(rsrc, rdst)] = (csrc, cdst)
    calls_by_id: Dict[str, Tuple[str, str]] = {}
    for e in g.edges:
        if e.kind == 'call' and e.callsite_id:
            calls_by_id[e.callsite_id] = (e.src, e.dst)
    for e in g.edges:
        if e.kind == 'return' and e.callsite_id and e.callsite_id in calls_by_id and (e.src, e.dst) not in g.phi_return_to_call:
            cp = calls_by_id[e.callsite_id]
            g.phi_call_to_return[cp] = (e.src, e.dst)
            g.phi_return_to_call[(e.src, e.dst)] = cp
    return g

# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------

def find_icfg_nodes_for_function_bbs(g: ICFG, function: str, bbs: Set[str]) -> List[str]:
    bbs_norm = {norm_bb(b) for b in bbs}
    hits: List[str] = []
    for nid, n in g.nodes.items():
        if n.function == function and norm_bb(n.bb) in bbs_norm:
            hits.append(nid)
    if not hits:
        for nid, n in g.nodes.items():
            if n.function != function:
                continue
            for bb in bbs_norm:
                if re.search(rf'\b{re.escape(bb)}\b', n.label or ''):
                    hits.append(nid)
    return sorted(set(hits))


def resolve_target_nodes(args: argparse.Namespace, g: ICFG) -> Tuple[List[str], Dict[str, object]]:
    info: Dict[str, object] = {'mode': None, 'target_bbs': [], 'target_function': args.function, 'target_node_args': list(args.target_node or []), 'matched_instructions': [], 'wanted_dbg_ids': [], 'function_dbg_id': None}
    if args.target_node:
        info['mode'] = 'target-node'
        return sorted(set(n for n in args.target_node if n in g.nodes)), info
    if args.function and args.bb:
        info['mode'] = 'function-bb'
        info['target_bbs'] = [args.bb]
        return find_icfg_nodes_for_function_bbs(g, args.function, {args.bb}), info
    if args.target:
        if not args.module_ll:
            raise ValueError('--target requires --module-ll unless --function and --bb are provided')
        module_ll = Path(args.module_ll)
        function = args.function or infer_target_function_from_module_ll(module_ll, args.target)
        if not function:
            raise ValueError(f'failed to infer target function for {args.target}; pass --function')
        bbs, instr, wanted, func_dbg = target_bbs_from_module_ll(module_ll, args.target, function)
        info.update({'mode': 'source-target', 'target_function': function, 'target_bbs': sorted(bbs), 'matched_instructions': instr, 'wanted_dbg_ids': wanted, 'function_dbg_id': func_dbg})
        return find_icfg_nodes_for_function_bbs(g, function, bbs), info
    raise ValueError('provide one of: --target-node, --function + --bb, or --target + --module-ll')

# ---------------------------------------------------------------------------
# Summary/signature model
# ---------------------------------------------------------------------------

class _Flag:
    value = False

ARG_ALLOW_PARTIAL_SIGNATURES = _Flag()

@dataclass(frozen=True)
class Frame:
    call_src: str
    call_dst: str
    caller_func: str
    callee_func: str
    callsite_id: str = ''


@dataclass(frozen=True)
class DomKey:
    function: str
    bb: str
    def text(self) -> str:
        return f'{self.function}:bb={self.bb}'


@dataclass
class LoopSCC:
    scc_id: int
    nodes: List[str]
    entry_edges: List[Tuple[str, str, str]]
    exit_edges: List[Tuple[str, str, str]]
    contains_target: bool = False


@dataclass
class RecursionCycle:
    cycle_id: int
    functions: List[str]
    call_edges: List[Tuple[str, str, str, str]]


@dataclass
class SignatureResult:
    signature: Tuple[DomKey, ...]
    target_node: str
    annotations: Tuple[str, ...] = ()


@dataclass
class StructureStats:
    relevant_nodes: int = 0
    relevant_edges: int = 0
    loop_scc_count: int = 0
    recursion_cycle_count: int = 0
    expanded_states: int = 0
    signature_count: int = 0
    summarized_loop_scc_hits: int = 0
    summarized_recursion_hits: int = 0
    skipped_invalid_return: int = 0
    skipped_missing_phi_return: int = 0
    observed_call_edges_without_phi: int = 0


def node_desc(g: ICFG, nid: str, include_node_id: bool = False) -> str:
    n = g.nodes.get(nid)
    if not n:
        return nid if include_node_id else '?'
    bb = norm_bb(n.bb) if n.bb else '?'
    base = f'{n.function or "?"}:bb={bb}({n.kind or "unknown"})'
    return f'{base}[{nid}]' if include_node_id else base


def node_dom_key(g: ICFG, nid: str) -> Optional[DomKey]:
    n = g.nodes.get(nid)
    if not n or not n.function:
        return None
    return DomKey(n.function, norm_bb(n.bb) if n.bb else 'entry')


def call_frame_for_edge(g: ICFG, e: ICFGEdge) -> Frame:
    src, dst = g.nodes.get(e.src), g.nodes.get(e.dst)
    return Frame(e.src, e.dst, src.function if src else '', dst.function if dst else '', e.callsite_id)


def active_functions(stack: Sequence[Frame]) -> Set[str]:
    funcs: Set[str] = set()
    for fr in stack:
        if fr.caller_func:
            funcs.add(fr.caller_func)
        if fr.callee_func:
            funcs.add(fr.callee_func)
    return funcs


def is_recursive_call(frame: Frame, stack: Sequence[Frame]) -> bool:
    return bool(frame.callee_func and ((frame.caller_func == frame.callee_func) or frame.callee_func in active_functions(stack)))


def ahead(g: ICFG, e: ICFGEdge) -> Set[str]:
    if e.kind != 'return':
        return {e.src}
    cp = g.phi_return_to_call.get((e.src, e.dst))
    return {e.src, cp[0]} if cp else {e.src}


def parse_program_dominator_keys(path: Path) -> List[DomKey]:
    if not path.exists():
        return []
    out: List[DomKey] = []
    seen: Set[Tuple[str, str]] = set()
    in_sec = False
    for raw in path.read_text(encoding='utf-8', errors='replace').splitlines():
        s = raw.strip()
        if s == 'program_dominators:':
            in_sec = True
            continue
        if not in_sec:
            continue
        if not s:
            continue
        if s == '<none>':
            break
        if not s.startswith('- '):
            if raw and not raw.startswith((' ', '\t')):
                break
            continue
        item = s[2:].split('#', 1)[0].strip()
        if ':' not in item:
            continue
        fn, tail = item.split(':', 1)
        if not tail.strip().startswith('bb='):
            continue
        dk = DomKey(norm_func(fn), norm_bb(tail.strip()[3:]))
        key = (dk.function, dk.bb)
        if dk.function and key not in seen:
            out.append(dk)
            seen.add(key)
    return out


def compute_dominator_keys_fallback(g: ICFG, roots: Sequence[str], target_nodes: Sequence[str], max_iter: int = 10000) -> List[DomKey]:
    universe = set(g.nodes)
    root_set = {r for r in roots if r in g.nodes}
    dom: Dict[str, Set[str]] = {n: set(universe) for n in g.nodes}
    for r in root_set:
        dom[r] = {r}
    for _ in range(max_iter):
        changed = False
        for v in sorted(g.nodes):
            if v in root_set:
                continue
            incoming = g.in_edges.get(v, [])
            if not incoming:
                new = {v}
            else:
                inter: Optional[Set[str]] = None
                for e in incoming:
                    ah_dom: Set[str] = set()
                    for a in ahead(g, e):
                        ah_dom.update(dom.get(a, set()))
                    inter = set(ah_dom) if inter is None else inter & ah_dom
                new = (inter or set()) | {v}
            if new != dom[v]:
                dom[v] = new
                changed = True
        if not changed:
            break
    if not target_nodes:
        return []
    common = set(dom.get(target_nodes[0], set()))
    for t in target_nodes[1:]:
        common &= dom.get(t, set())
    out: List[DomKey] = []
    seen: Set[Tuple[str, str]] = set()
    for nid in sorted(common):
        dk = node_dom_key(g, nid)
        if dk and (dk.function, dk.bb) not in seen:
            out.append(dk)
            seen.add((dk.function, dk.bb))
    return out


def forward_reachable(g: ICFG, roots: Sequence[str]) -> Set[str]:
    seen: Set[str] = set()
    stack = [r for r in roots if r in g.nodes]
    while stack:
        v = stack.pop()
        if v in seen:
            continue
        seen.add(v)
        stack.extend(e.dst for e in g.out_edges.get(v, []) if e.dst not in seen)
    return seen


def reverse_reachable(g: ICFG, targets: Sequence[str]) -> Set[str]:
    seen: Set[str] = set()
    stack = [t for t in targets if t in g.nodes]
    while stack:
        v = stack.pop()
        if v in seen:
            continue
        seen.add(v)
        for e in g.in_edges.get(v, []):
            if e.src not in seen:
                stack.append(e.src)
            if e.kind == 'return':
                cp = g.phi_return_to_call.get((e.src, e.dst))
                if cp and cp[0] not in seen:
                    stack.append(cp[0])
    return seen


def tarjan_scc(nodes: Iterable[str], succ_fn) -> List[List[str]]:
    """Return strongly connected components without recursive DFS.

    The previous implementation used recursive Tarjan DFS, which can hit
    Python's recursion limit on large ICFGs even though the analysis itself is
    finite. This iterative Kosaraju-style implementation has the same purpose
    for this script: identify SCCs for LOOP-SCC and RECURSION-CYCLE summaries.
    """
    node_set = set(nodes)
    if not node_set:
        return []

    ordered_nodes = sorted(node_set)
    adj: Dict[str, List[str]] = {}
    radj: Dict[str, List[str]] = defaultdict(list)

    for v in ordered_nodes:
        outs = sorted({w for w in succ_fn(v) if w in node_set})
        adj[v] = outs
        for w in outs:
            radj[w].append(v)

    visited: Set[str] = set()
    finish_order: List[str] = []

    for start in ordered_nodes:
        if start in visited:
            continue
        visited.add(start)
        stack: List[Tuple[str, int]] = [(start, 0)]

        while stack:
            v, i = stack[-1]
            outs = adj.get(v, [])
            if i < len(outs):
                w = outs[i]
                stack[-1] = (v, i + 1)
                if w not in visited:
                    visited.add(w)
                    stack.append((w, 0))
            else:
                stack.pop()
                finish_order.append(v)

    comps: List[List[str]] = []
    assigned: Set[str] = set()

    for start in reversed(finish_order):
        if start in assigned:
            continue
        comp: List[str] = []
        stack2 = [start]
        assigned.add(start)

        while stack2:
            v = stack2.pop()
            comp.append(v)
            for w in radj.get(v, []):
                if w not in assigned:
                    assigned.add(w)
                    stack2.append(w)

        comps.append(sorted(comp))

    return comps

def compute_loop_sccs(g: ICFG, relevant: Set[str], target_set: Set[str]) -> Tuple[List[LoopSCC], Dict[str, int]]:
    comps = tarjan_scc(relevant, lambda v: [e.dst for e in g.out_edges.get(v, []) if e.dst in relevant])
    loops: List[LoopSCC] = []
    node_to_loop: Dict[str, int] = {}
    for comp in comps:
        cset = set(comp)
        self_loop = any(e.src == e.dst for n in comp for e in g.out_edges.get(n, []))
        if len(comp) <= 1 and not self_loop:
            continue
        sid = len(loops)
        entries: Set[Tuple[str, str, str]] = set()
        exits: Set[Tuple[str, str, str]] = set()
        for n in comp:
            for e in g.in_edges.get(n, []):
                if e.src in relevant and e.src not in cset:
                    entries.add((e.src, e.dst, e.kind))
            for e in g.out_edges.get(n, []):
                if e.dst in relevant and e.dst not in cset:
                    exits.add((e.src, e.dst, e.kind))
        loops.append(LoopSCC(sid, comp, sorted(entries), sorted(exits), bool(cset & target_set)))
        for n in comp:
            node_to_loop[n] = sid
    return loops, node_to_loop


def compute_recursion_cycles(g: ICFG, relevant: Set[str]) -> List[RecursionCycle]:
    funcs: Set[str] = set()
    cedges: List[Tuple[str, str, str, str]] = []
    for e in g.edges:
        if e.kind != 'call' or e.src not in relevant or e.dst not in relevant:
            continue
        s, d = g.nodes.get(e.src), g.nodes.get(e.dst)
        caller, callee = (s.function if s else ''), (d.function if d else '')
        if caller and callee:
            funcs.update([caller, callee]); cedges.append((caller, callee, e.src, e.dst))
    out: Dict[str, List[str]] = defaultdict(list)
    for a, b, _, _ in cedges:
        out[a].append(b)
    cycles: List[RecursionCycle] = []
    for comp in tarjan_scc(funcs, lambda f: out.get(f, [])):
        cs = set(comp)
        self_call = any(a == b and a in cs for a, b, _, _ in cedges)
        if len(comp) <= 1 and not self_call:
            continue
        edges = sorted(set(x for x in cedges if x[0] in cs and x[1] in cs))
        cycles.append(RecursionCycle(len(cycles), sorted(comp), edges))
    return cycles


def compressed_label(g: ICFG, nid: str, node_to_loop: Dict[str, int], include_node_id: bool = False) -> str:
    return f'LOOP-SCC#{node_to_loop[nid]}' if nid in node_to_loop else node_desc(g, nid, include_node_id)


def compressed_edges(g: ICFG, relevant: Set[str], node_to_loop: Dict[str, int], include_node_id: bool) -> List[Tuple[str, str, str]]:
    rows: Set[Tuple[str, str, str]] = set()
    for e in g.edges:
        if e.src not in relevant or e.dst not in relevant:
            continue
        src, dst = compressed_label(g, e.src, node_to_loop, include_node_id), compressed_label(g, e.dst, node_to_loop, include_node_id)
        if src != dst:
            rows.add((src, dst, e.kind))
    return sorted(rows)


def add_sig_node(g: ICFG, nid: str, dom_keys: Set[DomKey], sig: Tuple[DomKey, ...], seen: Set[DomKey]) -> Tuple[Tuple[DomKey, ...], Set[DomKey]]:
    dk = node_dom_key(g, nid)
    if dk and dk in dom_keys and dk not in seen:
        ns = set(seen); ns.add(dk)
        return sig + (dk,), ns
    return sig, seen


def alpha_name(i: int) -> str:
    chars: List[str] = []
    n = i
    while True:
        chars.append(chr(ord('a') + (n % 26)))
        n = n // 26 - 1
        if n < 0:
            break
    return ''.join(reversed(chars))


def target_short_name(info: Dict[str, object], target_nodes: Sequence[str], g: ICFG) -> str:
    bbs = info.get('target_bbs') or []
    if isinstance(bbs, list) and bbs:
        return str(bbs[0])
    dk = node_dom_key(g, target_nodes[0]) if target_nodes else None
    return dk.bb if dk else 'target'


def signature_text(sig: Sequence[DomKey]) -> str:
    return '[' + ', '.join(d.text() for d in sig) + ']'


def explore_signatures(g: ICFG, roots: Sequence[str], target_nodes: Sequence[str], relevant: Set[str], dom_order: Sequence[DomKey], node_to_loop: Dict[str, int], dfs: bool) -> Tuple[List[SignatureResult], List[str], List[str], StructureStats]:
    target_set = set(target_nodes)
    dom_keys = set(dom_order)
    stats = StructureStats()
    loop_hits: List[str] = []
    rec_hits: List[str] = []
    results: Dict[Tuple[DomKey, ...], SignatureResult] = {}
    WorkItem = Tuple[str, Tuple[Frame, ...], Tuple[DomKey, ...], frozenset, Tuple[str, ...]]
    work: Deque[WorkItem] = deque()
    visited: Set[Tuple[str, Tuple[Frame, ...], Tuple[DomKey, ...], frozenset]] = set()
    for r in roots:
        if r in relevant:
            sig, seen = add_sig_node(g, r, dom_keys, tuple(), set())
            work.append((r, tuple(), sig, frozenset(seen), tuple()))
    while work:
        v, stack, sig, seen_frozen, anns = work.pop() if dfs else work.popleft()
        key = (v, stack, sig, seen_frozen)
        if key in visited:
            if v in node_to_loop:
                ann = f'LOOP-SCC#{node_to_loop[v]}'
                if ann not in loop_hits:
                    loop_hits.append(ann)
                stats.summarized_loop_scc_hits += 1
            continue
        visited.add(key)
        stats.expanded_states += 1
        if v in target_set:
            seen = set(seen_frozen)
            sig, seen = add_sig_node(g, v, dom_keys, sig, seen)
            if (not ARG_ALLOW_PARTIAL_SIGNATURES.value) and dom_keys and set(sig) != dom_keys:
                continue
            results.setdefault(sig, SignatureResult(sig, v, tuple(sorted(set(anns)))))
            continue
        succs = [e for e in g.out_edges.get(v, []) if e.dst in relevant]
        succs.sort(key=lambda e: (e.kind, e.dst, e.src, e.callsite_id))
        if dfs:
            succs.reverse()
        for e in succs:
            nstack = stack
            nanns = set(anns)
            if e.kind == 'call':
                fr = call_frame_for_edge(g, e)
                if (e.src, e.dst) not in g.phi_call_to_return:
                    stats.observed_call_edges_without_phi += 1
                if is_recursive_call(fr, stack):
                    ann = f'RECURSION-CYCLE:{fr.caller_func or "?"}->{fr.callee_func or "?"}'
                    if ann not in rec_hits:
                        rec_hits.append(ann)
                    stats.summarized_recursion_hits += 1
                    continue
                nstack = stack + (fr,)
            elif e.kind == 'return':
                expected = g.phi_return_to_call.get((e.src, e.dst))
                if expected is None:
                    stats.skipped_missing_phi_return += 1
                    continue
                actual = (stack[-1].call_src, stack[-1].call_dst) if stack else None
                if not stack or actual != expected:
                    stats.skipped_invalid_return += 1
                    continue
                nstack = stack[:-1]
            if e.dst in node_to_loop:
                ann = f'LOOP-SCC#{node_to_loop[e.dst]}'
                nanns.add(ann)
                if ann not in loop_hits:
                    loop_hits.append(ann)
                stats.summarized_loop_scc_hits += 1
            nsig, nseen = add_sig_node(g, e.dst, dom_keys, sig, set(seen_frozen))
            work.append((e.dst, nstack, nsig, frozenset(nseen), tuple(sorted(nanns))))
    stats.signature_count = len(results)
    return list(results.values()), loop_hits, rec_hits, stats

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def emit_text(g: ICFG, args: argparse.Namespace, roots: Sequence[str], target_nodes: Sequence[str], info: Dict[str, object], relevant: Set[str], loops: Sequence[LoopSCC], recs: Sequence[RecursionCycle], cedges: Sequence[Tuple[str, str, str]], dom_order: Sequence[DomKey], sigs: Sequence[SignatureResult], loop_hits: Sequence[str], rec_hits: Sequence[str], stats: StructureStats) -> None:
    inc = args.include_node_ids
    print('valid_path_structure_summary:')
    print(f'  icfg_dir: {args.icfg_dir}')
    print(f'  mode: {info.get("mode")}')
    print(f'  roots: {", ".join(node_desc(g, r, inc) for r in roots) if roots else "<none>"}')
    print(f'  target_function: {info.get("target_function") or "<unknown>"}')
    bbs = info.get('target_bbs') or []
    print(f'  target_bbs: {", ".join(bbs) if bbs else "<none/target-node-mode>"}')
    print(f'  target_nodes: {", ".join(node_desc(g, n, inc) for n in target_nodes) if target_nodes else "<none>"}')
    print(f'  graph_nodes: {len(g.nodes)}')
    print(f'  graph_edges: {len(g.edges)}')
    print(f'  phi_pairs: {len(g.phi_call_to_return)}')
    print('  path_model: concrete valid paths are not enumerated; dominator signature states are explored')
    print('  loop_model: LOOP-SCC')
    print('  recursion_model: RECURSION-CYCLE')
    print(f'  relevant_nodes_to_target: {len(relevant)}')
    print(f'  relevant_edges_to_target: {stats.relevant_edges}')
    print(f'  loop_scc_count: {len(loops)}')
    print(f'  recursion_cycle_count: {len(recs)}')
    print(f'  expanded_signature_states: {stats.expanded_states}')
    print(f'  signature_count: {len(sigs)}')
    print(f'  summarized_loop_scc_hits: {stats.summarized_loop_scc_hits}')
    print(f'  summarized_recursion_hits: {stats.summarized_recursion_hits}')
    print(f'  skipped_invalid_return: {stats.skipped_invalid_return}')
    print(f'  skipped_missing_phi_return: {stats.skipped_missing_phi_return}')
    print(f'  observed_call_edges_without_phi: {stats.observed_call_edges_without_phi}')
    print()
    if info.get('function_dbg_id') is not None:
        print(f'function_dbg_id: !{info.get("function_dbg_id")}')
    if info.get('wanted_dbg_ids'):
        print('matched_dilocations:')
        for x in info.get('wanted_dbg_ids', []):
            print(f'  - !{x}')
    if info.get('matched_instructions'):
        print('matched_instructions:')
        for m in info.get('matched_instructions', []):
            dbg = ', '.join(f'!{x}' for x in m.get('dbg_hits', []))
            print(f'  - function={m.get("function")} bb={m.get("bb")} ll_line={m.get("ll_line")} dbg={dbg}')
            print(f'    ir: {m.get("ir")}')
        print()
    print('target_dominator_set:')
    if dom_order:
        for dk in dom_order:
            print(f'  - {dk.text()}')
    else:
        print('  <none>')
    print()
    tname = target_short_name(info, target_nodes, g)
    print('interprocedural_dominator_order_signatures:')
    if sigs:
        for i, res in enumerate(sorted(sigs, key=lambda r: [x.text() for x in r.signature])):
            ann = f'  # {"; ".join(res.annotations)}' if res.annotations else ''
            print(f'  Path_{tname}{alpha_name(i)}: Dom({tname}{alpha_name(i)}) = {signature_text(res.signature)}{ann}')
    else:
        print('  <none>')
    print()
    print('loop_sccs:')
    if not loops:
        print('  <none>')
    for scc in loops[:args.max_sccs]:
        print(f'  LOOP-SCC#{scc.scc_id}:')
        print(f'    contains_target: {str(scc.contains_target).lower()}')
        print('    nodes:')
        for n in scc.nodes[:args.max_scc_nodes]:
            print(f'      - {node_desc(g, n, inc)}')
        if len(scc.nodes) > args.max_scc_nodes:
            print(f'      ... {len(scc.nodes) - args.max_scc_nodes} more')
        print('    entries:')
        if not scc.entry_edges:
            print('      <none>')
        for src, dst, kind in scc.entry_edges[:args.max_scc_edges]:
            print(f'      - {kind}: {node_desc(g, src, inc)} -> {node_desc(g, dst, inc)}')
        print('    exits:')
        if not scc.exit_edges:
            print('      <none>')
        for src, dst, kind in scc.exit_edges[:args.max_scc_edges]:
            print(f'      - {kind}: {node_desc(g, src, inc)} -> {node_desc(g, dst, inc)}')
    if len(loops) > args.max_sccs:
        print(f'  ... {len(loops) - args.max_sccs} more LOOP-SCCs')
    print()
    print('recursion_cycles:')
    if not recs:
        print('  <none>')
    for cyc in recs[:args.max_recursion_cycles]:
        print(f'  RECURSION-CYCLE#{cyc.cycle_id}:')
        print(f'    functions: {" -> ".join(cyc.functions)}')
        print('    call_edges:')
        for caller, callee, csrc, cdst in cyc.call_edges[:args.max_recursion_edges]:
            print(f'      - {caller} -> {callee}: {node_desc(g, csrc, inc)} -> {node_desc(g, cdst, inc)}')
    if len(recs) > args.max_recursion_cycles:
        print(f'  ... {len(recs) - args.max_recursion_cycles} more RECURSION-CYCLEs')
    print()
    print('reachable_valid_path_structure_edges:')
    if cedges:
        for src, dst, kind in cedges[:args.max_structure_edges]:
            print(f'  - {kind}: {src} -> {dst}')
        if len(cedges) > args.max_structure_edges:
            print(f'  ... {len(cedges) - args.max_structure_edges} more compressed edges')
    else:
        print('  <none>')
    print()
    print('summarized_events_seen_during_signature_exploration:')
    print('  loop_scc_hits:')
    print('\n'.join(f'    - {x}' for x in loop_hits) if loop_hits else '    <none>')
    print('  recursion_hits:')
    print('\n'.join(f'    - {x}' for x in rec_hits) if rec_hits else '    <none>')


def emit_json(g: ICFG, args: argparse.Namespace, roots: Sequence[str], target_nodes: Sequence[str], info: Dict[str, object], relevant: Set[str], loops: Sequence[LoopSCC], recs: Sequence[RecursionCycle], cedges: Sequence[Tuple[str, str, str]], dom_order: Sequence[DomKey], sigs: Sequence[SignatureResult], loop_hits: Sequence[str], rec_hits: Sequence[str], stats: StructureStats) -> None:
    tname = target_short_name(info, target_nodes, g)
    data = {
        'summary': {
            'icfg_dir': args.icfg_dir,
            'mode': info.get('mode'),
            'roots': list(roots),
            'target_function': info.get('target_function'),
            'target_bbs': info.get('target_bbs'),
            'target_nodes': list(target_nodes),
            'graph_nodes': len(g.nodes),
            'graph_edges': len(g.edges),
            'phi_pairs': len(g.phi_call_to_return),
            'path_model': 'concrete valid paths are not enumerated; dominator signature states are explored',
            'loop_model': 'LOOP-SCC',
            'recursion_model': 'RECURSION-CYCLE',
            'relevant_nodes_to_target': len(relevant),
            'relevant_edges_to_target': stats.relevant_edges,
        },
        'stats': asdict(stats),
        'target_info': info,
        'target_dominator_set': [d.text() for d in dom_order],
        'interprocedural_dominator_order_signatures': [
            {'name': f'Path_{tname}{alpha_name(i)}', 'target_node': r.target_node, 'signature': [d.text() for d in r.signature], 'annotations': list(r.annotations)}
            for i, r in enumerate(sorted(sigs, key=lambda r: [x.text() for x in r.signature]))
        ],
        'loop_sccs': [{**asdict(x), 'nodes_pretty': [node_desc(g, n, args.include_node_ids) for n in x.nodes]} for x in loops],
        'recursion_cycles': [asdict(x) for x in recs],
        'reachable_valid_path_structure_edges': [{'src': s, 'dst': d, 'kind': k} for s, d, k in cedges],
        'summarized_events_seen_during_signature_exploration': {'loop_scc_hits': list(loop_hits), 'recursion_hits': list(rec_hits)},
    }
    print(json.dumps(data, ensure_ascii=False, indent=2))

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument('--icfg-dir', required=True)
    ap.add_argument('--module-ll')
    ap.add_argument('--target')
    ap.add_argument('--function')
    ap.add_argument('--bb')
    ap.add_argument('--target-node', action='append')
    ap.add_argument('--entry-function', default='main')
    ap.add_argument('--root-node', action='append')
    ap.add_argument('--dominator-nodes', help='default: <icfg-dir>/dominator_nodes.txt')
    ap.add_argument('--no-fallback-dominators', action='store_true')
    ap.add_argument('--max-structure-edges', type=int, default=200)
    ap.add_argument('--max-sccs', type=int, default=30)
    ap.add_argument('--max-scc-nodes', type=int, default=30)
    ap.add_argument('--max-scc-edges', type=int, default=30)
    ap.add_argument('--max-recursion-cycles', type=int, default=30)
    ap.add_argument('--max-recursion-edges', type=int, default=30)
    ap.add_argument('--include-node-ids', action='store_true')
    ap.add_argument('--bfs', action='store_true')
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--allow-partial-signatures', action='store_true', help='also emit signatures that reached target without all target dominators; useful for debugging inconsistent ICFG/dominator inputs')
    # previous script compatibility: accepted as no-op
    ap.add_argument('--max-depth', type=int, default=0, help=argparse.SUPPRESS)
    ap.add_argument('--max-paths', type=int, default=0, help=argparse.SUPPRESS)
    ap.add_argument('--state-repeat-limit', type=int, default=1, help=argparse.SUPPRESS)
    ap.add_argument('--max-recursion-unroll', type=int, default=0, help=argparse.SUPPRESS)
    ap.add_argument('--verbose-paths', action='store_true', help=argparse.SUPPRESS)
    return ap.parse_args(argv)


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    ARG_ALLOW_PARTIAL_SIGNATURES.value = bool(args.allow_partial_signatures)
    icfg_dir = Path(args.icfg_dir)
    if not icfg_dir.exists():
        print(f'ERROR: icfg-dir not found: {icfg_dir}', file=sys.stderr)
        return 2
    g = load_icfg(icfg_dir)
    if not g.nodes or not g.edges:
        print(f'ERROR: normalized ICFG is empty or incomplete in {icfg_dir}', file=sys.stderr)
        return 2
    try:
        target_nodes, info = resolve_target_nodes(args, g)
    except Exception as exc:
        print(f'ERROR: failed to resolve target nodes: {exc}', file=sys.stderr)
        return 2
    if not target_nodes:
        print('ERROR: target node(s) not found in normalized ICFG', file=sys.stderr)
        if not args.json:
            print('target_resolution:')
            print(f'  mode: {info.get("mode")}')
            print(f'  target_function: {info.get("target_function")}')
            print(f'  target_bbs: {info.get("target_bbs")}')
            print(f'  target_node_args: {info.get("target_node_args")}')
        return 1
    roots = args.root_node if args.root_node else g.entry_candidates(args.entry_function)
    roots = [r for r in roots if r in g.nodes]
    if not roots:
        print('ERROR: root node(s) not found in normalized ICFG', file=sys.stderr)
        return 2

    relevant = forward_reachable(g, roots) & reverse_reachable(g, target_nodes)
    relevant_edges = sum(1 for e in g.edges if e.src in relevant and e.dst in relevant)
    loops, node_to_loop = compute_loop_sccs(g, relevant, set(target_nodes))
    recs = compute_recursion_cycles(g, relevant)
    cedges = compressed_edges(g, relevant, node_to_loop, args.include_node_ids)

    dom_path = Path(args.dominator_nodes) if args.dominator_nodes else icfg_dir / 'dominator_nodes.txt'
    dom_order = parse_program_dominator_keys(dom_path)
    if not dom_order and not args.no_fallback_dominators:
        dom_order = compute_dominator_keys_fallback(g, roots, target_nodes)
    if not dom_order:
        print(f'WARNING: no dominator set found. Expected dominator file: {dom_path}', file=sys.stderr)

    sigs, loop_hits, rec_hits, stats = explore_signatures(g, roots, target_nodes, relevant, dom_order, node_to_loop, not args.bfs)
    stats.relevant_nodes = len(relevant)
    stats.relevant_edges = relevant_edges
    stats.loop_scc_count = len(loops)
    stats.recursion_cycle_count = len(recs)

    if args.json:
        emit_json(g, args, roots, target_nodes, info, relevant, loops, recs, cedges, dom_order, sigs, loop_hits, rec_hits, stats)
    else:
        emit_text(g, args, roots, target_nodes, info, relevant, loops, recs, cedges, dom_order, sigs, loop_hits, rec_hits, stats)
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
