#!/usr/bin/env python3
"""
normalize_svf_icfg.py

Normalize SVF ICFG / CallGraph dumps into simple TSV files that can be used by
an interprocedural dominator computation pass.

Expected caller:
  python3 normalize_svf_icfg.py \
    --svf-dir <dir produced by: wpa -dump-icfg -dump-callgraph> \
    --module-bc module.bc \
    --module-ll module.ll \
    --bbnames BBnames.txt \
    --bbcalls BBcalls.txt \
    --targets BBtargets.txt \
    --outdir <tmp dir>

Main outputs:
  icfg_nodes.tsv         node_id, function, bb, kind, label, source
  icfg_edges.tsv         src, dst, kind, callsite_id, raw_label
  icfg_cfg_edges.tsv     src, dst
  icfg_call_edges.tsv    callsite_node, callee_entry_node, caller_func, callee_func, callsite_id
  icfg_return_edges.tsv  callee_exit_node, return_node, caller_func, callee_func, callsite_id
  icfg_phi.tsv           call_edge_src, call_edge_dst, return_edge_src, return_edge_dst, callsite_id, caller_func, callee_func
  icfg_functions.tsv     function, entry_nodes, exit_nodes, node_count
  icfg_summary.txt       human-readable summary

Notes:
  * This script is intentionally defensive because SVF DOT labels differ across
    versions/build options. It first tries to parse SVF DOT files. If no ICFG DOT
    exists, it falls back to a conservative direct-call ICFG extracted from LLVM IR.
  * The fallback is not context-sensitive and does not model indirect calls well;
    it is only a build-unblocking fallback.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


DEFINE_RE = re.compile(r'^\s*define\b.*@("?[-A-Za-z$._0-9]+"?)\s*\(')
BB_NAMED_RE = re.compile(r'^\s*([A-Za-z$._-][A-Za-z$._0-9-]*|\d+):(?:\s*;.*)?$')
CALL_RE = re.compile(r'\b(?:call|invoke)\b.*@("?[-A-Za-z$._0-9]+"?)\s*\(')
BR_UNCOND_RE = re.compile(r'\bbr\s+label\s+%([A-Za-z$._0-9-]+)')
BR_COND_RE = re.compile(r'\bbr\s+i1\s+[^,]+,\s+label\s+%([A-Za-z$._0-9-]+),\s+label\s+%([A-Za-z$._0-9-]+)')
SWITCH_LABEL_RE = re.compile(r'label\s+%([A-Za-z$._0-9-]+)')
RET_RE = re.compile(r'^\s*ret\b')


@dataclass(frozen=True)
class Node:
    node_id: str
    function: str = ""
    bb: str = ""
    kind: str = "unknown"
    label: str = ""
    source: str = "svf"


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    kind: str = "cfg"
    raw_label: str = ""
    callsite_id: str = ""


def norm_func(name: str) -> str:
    name = (name or "").strip().strip('"')
    if name.startswith("@"):
        name = name[1:]
    return name


def norm_bb(bb: str) -> str:
    bb = (bb or "").strip().strip('"')
    if bb.startswith("%"):
        bb = bb[1:]
    return bb


def clean_label(s: str) -> str:
    s = s or ""
    s = s.replace('\\l', '\n').replace('\\n', '\n').replace('\\t', '\t')
    s = s.replace('\\"', '"')
    return s.strip()


def tsv_safe(s: object) -> str:
    return str(s if s is not None else "").replace("\t", " ").replace("\r", " ").replace("\n", "\\n")


def write_tsv(path: Path, header: Sequence[str], rows: Iterable[Sequence[object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(header)
        for row in rows:
            w.writerow([tsv_safe(x) for x in row])


def parse_dot_attrs(attr_text: str) -> Dict[str, str]:
    attrs: Dict[str, str] = {}
    if not attr_text:
        return attrs

    # DOT attributes can contain commas inside quoted labels. Parse a conservative
    # key=value scanner instead of using split(',').
    i = 0
    n = len(attr_text)
    while i < n:
        while i < n and attr_text[i] in " \t\n,[]":
            i += 1
        m = re.match(r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*', attr_text[i:])
        if not m:
            break
        key = m.group(1)
        i += m.end()
        if i < n and attr_text[i] == '"':
            i += 1
            buf = []
            esc = False
            while i < n:
                ch = attr_text[i]
                if esc:
                    buf.append('\\' + ch)
                    esc = False
                elif ch == '\\':
                    esc = True
                elif ch == '"':
                    i += 1
                    break
                else:
                    buf.append(ch)
                i += 1
            attrs[key] = clean_label(''.join(buf))
        else:
            start = i
            while i < n and attr_text[i] not in ",]":
                i += 1
            attrs[key] = clean_label(attr_text[start:i])
    return attrs


def collect_dot_statements(path: Path) -> List[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    stmts: List[str] = []
    buf: List[str] = []
    in_quote = False
    esc = False

    for ch in text:
        buf.append(ch)
        if esc:
            esc = False
            continue
        if ch == '\\':
            esc = True
            continue
        if ch == '"':
            in_quote = not in_quote
            continue
        if ch == ';' and not in_quote:
            stmt = ''.join(buf).strip()
            if stmt:
                stmts.append(stmt)
            buf = []
    rest = ''.join(buf).strip()
    if rest:
        stmts.append(rest)
    return stmts


def unquote_dot_id(s: str) -> str:
    s = s.strip().rstrip(';').strip()
    if s.startswith('"') and s.endswith('"'):
        s = s[1:-1]
    return s.strip()


def split_dot_node_stmt(stmt: str) -> Optional[Tuple[str, str]]:
    if '->' in stmt:
        return None
    if '[' not in stmt or ']' not in stmt:
        return None
    left, rest = stmt.split('[', 1)
    node_id = unquote_dot_id(left)
    if not node_id or node_id in {"digraph", "graph", "node", "edge"}:
        return None
    attrs = rest.rsplit(']', 1)[0]
    return node_id, attrs


def split_dot_edge_stmt(stmt: str) -> Optional[Tuple[str, str, str]]:
    if '->' not in stmt:
        return None
    left, right = stmt.split('->', 1)
    src = unquote_dot_id(left)

    attr_text = ""
    if '[' in right:
        dst_part, rest = right.split('[', 1)
        dst = unquote_dot_id(dst_part)
        attr_text = rest.rsplit(']', 1)[0]
    else:
        dst = unquote_dot_id(right)
    if not src or not dst:
        return None
    return src, dst, attr_text


def choose_dot_file(svf_dir: Path, preferred_keywords: Sequence[str]) -> Optional[Path]:
    dots = sorted(svf_dir.rglob("*.dot"))
    if not dots:
        return None

    def score(p: Path) -> Tuple[int, int, str]:
        name = p.name.lower()
        s = 0
        for kw in preferred_keywords:
            if kw.lower() in name:
                s += 10
        # Avoid selecting callgraph when looking for ICFG if both exist.
        if "callgraph" in name and "icfg" in preferred_keywords:
            s -= 5
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        return (s, size, str(p))

    ranked = sorted(dots, key=score, reverse=True)
    return ranked[0] if score(ranked[0])[0] > 0 else ranked[0]


def infer_kind_from_node_label(label: str) -> str:
    l = label.lower()
    if any(x in l for x in ["funentry", "function entry", "entryicfgnode", "entry"]):
        return "entry"
    if any(x in l for x in ["funexit", "function exit", "exiticfgnode", "exit"]):
        return "exit"
    if any(x in l for x in ["callicfgnode", "call node", " call "]):
        return "call"
    if any(x in l for x in ["reticfgnode", "return node", " ret "]):
        return "return"
    if any(x in l for x in ["intraicfgnode", "intra"]):
        return "intra"
    return "unknown"


def infer_kind_from_edge_label(label: str) -> str:
    l = (label or "").lower()
    if any(x in l for x in ["callcf", "call edge", "call"]):
        return "call"
    if any(x in l for x in ["retcf", "return edge", "return", "ret"]):
        return "return"
    if any(x in l for x in ["intra", "cfg", "control"]):
        return "cfg"
    return "cfg"


def extract_function_from_label(label: str) -> str:
    label = clean_label(label)
    patterns = [
        r'Fun(?:ction)?\s*[:=]\s*([@"A-Za-z0-9_$.-]+)',
        r'func(?:tion)?\s*[:=]\s*([@"A-Za-z0-9_$.-]+)',
        r'\bF\s*[:=]\s*([@"A-Za-z0-9_$.-]+)',
        r'@("?[-A-Za-z$._0-9]+"?)',
        r'\bin\s+function\s+([@"A-Za-z0-9_$.-]+)',
    ]
    for pat in patterns:
        m = re.search(pat, label, flags=re.IGNORECASE)
        if m:
            return norm_func(m.group(1))

    # Often SVF labels contain a source-like token: "{fun: foo}" or "foo\n...".
    for line in label.splitlines():
        m = re.search(r'([A-Za-z_$.-][A-Za-z0-9_$.-]*)\s*\(', line)
        if m and not line.strip().startswith(("call", "invoke", "br", "ret")):
            return norm_func(m.group(1))
    return ""


def extract_bb_from_label(label: str) -> str:
    label = clean_label(label)
    patterns = [
        r'BB\s*[:=]\s*%?([A-Za-z$._0-9-]+)',
        r'BasicBlock\s*[:=]\s*%?([A-Za-z$._0-9-]+)',
        r'\bbb\s*[:=]\s*%?([A-Za-z$._0-9-]+)',
        r'%([0-9]+)\b',
        r'<label>:%?([A-Za-z$._0-9-]+)',
    ]
    for pat in patterns:
        m = re.search(pat, label, flags=re.IGNORECASE)
        if m:
            return norm_bb(m.group(1))
    return ""


def parse_svf_icfg_dot(dot_path: Path) -> Tuple[Dict[str, Node], List[Edge]]:
    nodes: Dict[str, Node] = {}
    edges: List[Edge] = []

    for stmt in collect_dot_statements(dot_path):
        ns = split_dot_node_stmt(stmt)
        if ns:
            node_id, attr_text = ns
            attrs = parse_dot_attrs(attr_text)
            label = attrs.get("label", "")
            function = extract_function_from_label(label)
            bb = extract_bb_from_label(label)
            kind = infer_kind_from_node_label(label)
            nodes[node_id] = Node(node_id=node_id, function=function, bb=bb, kind=kind, label=label, source=str(dot_path.name))
            continue

        es = split_dot_edge_stmt(stmt)
        if es:
            src, dst, attr_text = es
            attrs = parse_dot_attrs(attr_text)
            label = attrs.get("label", "") or attrs.get("color", "") or attr_text
            kind = infer_kind_from_edge_label(label)
            edges.append(Edge(src=src, dst=dst, kind=kind, raw_label=label))
            if src not in nodes:
                nodes[src] = Node(node_id=src, source=str(dot_path.name))
            if dst not in nodes:
                nodes[dst] = Node(node_id=dst, source=str(dot_path.name))

    return nodes, edges


def parse_bbnames(path: Optional[Path]) -> Dict[Tuple[str, str], str]:
    # AFLGo BBnames generally uses file:line:function or file:line style.
    # We keep it as auxiliary source; exact mapping is project-dependent.
    m: Dict[Tuple[str, str], str] = {}
    if not path or not path.exists():
        return m
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split(":")
        if len(parts) >= 3:
            func = parts[-1].strip()
            loc = ":".join(parts[:-1])
            if func:
                m[(func, loc)] = s
    return m


def parse_module_ll_fallback(module_ll: Path) -> Tuple[Dict[str, Node], List[Edge]]:
    lines = module_ll.read_text(encoding="utf-8", errors="replace").splitlines()

    nodes: Dict[str, Node] = {}
    edges: List[Edge] = []
    funcs_bbs: Dict[str, List[str]] = defaultdict(list)
    func_exits: Dict[str, Set[str]] = defaultdict(set)

    current_func = None
    current_bb = None
    block_lines: List[str] = []

    def add_node(func: str, bb: str, kind: str = "intra") -> str:
        node_id = f"{func}:{bb}"
        if node_id not in nodes:
            nodes[node_id] = Node(node_id=node_id, function=func, bb=bb, kind=kind, label=node_id, source="llvm-ir-fallback")
        funcs_bbs[func].append(bb) if bb not in funcs_bbs[func] else None
        return node_id

    def flush_block() -> None:
        nonlocal block_lines, current_func, current_bb
        if current_func is None or current_bb is None:
            block_lines = []
            return
        src = add_node(current_func, current_bb, "entry" if current_bb == "entry" else "intra")
        text = "\n".join(block_lines)

        # direct calls: approximate call edge from current BB to callee entry and return edge back to same BB.
        for cm in CALL_RE.finditer(text):
            callee = norm_func(cm.group(1))
            if not callee or callee.startswith("llvm."):
                continue
            callee_entry = add_node(callee, "entry", "entry")
            callee_exit = add_node(callee, "exit", "exit")
            ret_node = f"{current_func}:{current_bb}:ret"
            nodes[ret_node] = Node(node_id=ret_node, function=current_func, bb=current_bb, kind="return", label=ret_node, source="llvm-ir-fallback")
            edges.append(Edge(src, callee_entry, "call", f"direct call @{callee}"))
            edges.append(Edge(callee_exit, ret_node, "return", f"return @{callee} -> @{current_func}"))

        # CFG successors from terminators.
        last_nonempty = ""
        for l in reversed(block_lines):
            if l.strip():
                last_nonempty = l.strip()
                break
        succs: Set[str] = set()
        m = BR_COND_RE.search(last_nonempty)
        if m:
            succs.update([m.group(1), m.group(2)])
        else:
            m = BR_UNCOND_RE.search(last_nonempty)
            if m:
                succs.add(m.group(1))
            elif last_nonempty.startswith("switch"):
                succs.update(SWITCH_LABEL_RE.findall(last_nonempty))
            elif RET_RE.match(last_nonempty):
                func_exits[current_func].add(current_bb)

        for dst_bb in succs:
            dst = add_node(current_func, norm_bb(dst_bb), "intra")
            edges.append(Edge(src, dst, "cfg", "llvm br/switch"))

        block_lines = []

    for line in lines:
        dm = DEFINE_RE.match(line)
        if dm:
            flush_block()
            current_func = norm_func(dm.group(1))
            current_bb = "entry"
            add_node(current_func, current_bb, "entry")
            block_lines = []
            continue

        if current_func is not None and re.match(r'^\s*}\s*$', line):
            flush_block()
            # Add a synthetic exit if none was found.
            if current_func not in func_exits:
                add_node(current_func, "exit", "exit")
            current_func = None
            current_bb = None
            block_lines = []
            continue

        if current_func is None:
            continue

        bm = BB_NAMED_RE.match(line)
        if bm:
            flush_block()
            current_bb = norm_bb(bm.group(1))
            add_node(current_func, current_bb, "intra")
            continue

        block_lines.append(line)

    flush_block()

    # Connect real return BBs to synthetic function exit nodes.
    for func, exits in func_exits.items():
        exit_node = add_node(func, "exit", "exit")
        for bb in exits:
            src = add_node(func, bb, "intra")
            edges.append(Edge(src, exit_node, "cfg", "synthetic unique exit"))

    return nodes, edges


def enrich_missing_node_info(nodes: Dict[str, Node], edges: List[Edge]) -> Dict[str, Node]:
    # Propagate function names from neighbors when a node label did not contain them.
    changed = True
    out_edges = defaultdict(list)
    in_edges = defaultdict(list)
    for e in edges:
        out_edges[e.src].append(e)
        in_edges[e.dst].append(e)

    nodes_mut = dict(nodes)
    while changed:
        changed = False
        for nid, n in list(nodes_mut.items()):
            if n.function:
                continue
            neigh_funcs = []
            for e in out_edges.get(nid, []):
                f = nodes_mut.get(e.dst, Node(e.dst)).function
                if f:
                    neigh_funcs.append(f)
            for e in in_edges.get(nid, []):
                f = nodes_mut.get(e.src, Node(e.src)).function
                if f:
                    neigh_funcs.append(f)
            if neigh_funcs:
                # Only propagate if all known neighbors agree.
                if len(set(neigh_funcs)) == 1:
                    f = neigh_funcs[0]
                    nodes_mut[nid] = Node(nid, f, n.bb, n.kind, n.label, n.source)
                    changed = True
    return nodes_mut


def assign_callsite_ids(nodes: Dict[str, Node], edges: List[Edge]) -> List[Edge]:
    result: List[Edge] = []
    counter = 0
    for e in edges:
        if e.kind == "call":
            cs = f"cs{counter}"
            counter += 1
            result.append(Edge(e.src, e.dst, e.kind, e.raw_label, cs))
        else:
            result.append(e)
    return result


def build_function_index(nodes: Dict[str, Node]) -> Dict[str, Dict[str, object]]:
    idx: Dict[str, Dict[str, object]] = {}
    for n in nodes.values():
        if not n.function:
            continue
        ent = idx.setdefault(n.function, {"entries": set(), "exits": set(), "nodes": set()})
        ent["nodes"].add(n.node_id)  # type: ignore[index]
        if n.kind == "entry":
            ent["entries"].add(n.node_id)  # type: ignore[index]
        if n.kind == "exit":
            ent["exits"].add(n.node_id)  # type: ignore[index]

    # If entry/exit kinds were not identified from SVF labels, infer rough candidates.
    incoming = defaultdict(int)
    outgoing = defaultdict(int)
    for n in nodes.values():
        incoming[n.node_id] += 0
        outgoing[n.node_id] += 0

    for func, data in idx.items():
        if not data["entries"]:  # type: ignore[index]
            candidates = sorted(data["nodes"])  # type: ignore[index]
            if candidates:
                data["entries"].add(candidates[0])  # type: ignore[index]
        if not data["exits"]:  # type: ignore[index]
            candidates = sorted(data["nodes"])  # type: ignore[index]
            if candidates:
                data["exits"].add(candidates[-1])  # type: ignore[index]
    return idx


def derive_call_return_tables(nodes: Dict[str, Node], edges: List[Edge]) -> Tuple[List[Tuple], List[Tuple], List[Tuple]]:
    call_edges = []
    return_edges = []
    phi_rows = []

    calls_by_pair: Dict[Tuple[str, str], List[Edge]] = defaultdict(list)
    for e in edges:
        if e.kind == "call":
            caller = nodes.get(e.src, Node(e.src)).function
            callee = nodes.get(e.dst, Node(e.dst)).function
            calls_by_pair[(caller, callee)].append(e)
            call_edges.append((e.src, e.dst, caller, callee, e.callsite_id))

    returns_by_pair: Dict[Tuple[str, str], List[Edge]] = defaultdict(list)
    for e in edges:
        if e.kind == "return":
            callee = nodes.get(e.src, Node(e.src)).function
            caller = nodes.get(e.dst, Node(e.dst)).function
            returns_by_pair[(caller, callee)].append(e)

    for (caller, callee), rets in sorted(returns_by_pair.items()):
        calls = calls_by_pair.get((caller, callee), [])
        for r in rets:
            if calls:
                for c in calls:
                    return_edges.append((r.src, r.dst, caller, callee, c.callsite_id))
                    phi_rows.append((c.src, c.dst, r.src, r.dst, c.callsite_id, caller, callee))
            else:
                return_edges.append((r.src, r.dst, caller, callee, ""))
                phi_rows.append(("", "", r.src, r.dst, "", caller, callee))

    return call_edges, return_edges, phi_rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--svf-dir", required=True)
    ap.add_argument("--module-bc")
    ap.add_argument("--module-ll", required=True)
    ap.add_argument("--bbnames")
    ap.add_argument("--bbcalls")
    ap.add_argument("--targets")
    ap.add_argument("--outdir", required=True)
    args = ap.parse_args()

    svf_dir = Path(args.svf_dir)
    module_ll = Path(args.module_ll)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    icfg_dot = choose_dot_file(svf_dir, ["icfg"])
    used_fallback = False

    if icfg_dot and icfg_dot.exists():
        print(f"[normalize-svf-icfg] using ICFG DOT: {icfg_dot}", file=sys.stderr)
        nodes, edges = parse_svf_icfg_dot(icfg_dot)
        if not edges:
            print("[normalize-svf-icfg] WARNING: ICFG DOT had no edges; using LLVM IR fallback", file=sys.stderr)
            nodes, edges = parse_module_ll_fallback(module_ll)
            used_fallback = True
    else:
        print("[normalize-svf-icfg] WARNING: no SVF ICFG DOT found; using LLVM IR fallback", file=sys.stderr)
        nodes, edges = parse_module_ll_fallback(module_ll)
        used_fallback = True

    nodes = enrich_missing_node_info(nodes, edges)
    edges = assign_callsite_ids(nodes, edges)
    func_idx = build_function_index(nodes)
    call_rows, ret_rows, phi_rows = derive_call_return_tables(nodes, edges)

    cfg_edges = [e for e in edges if e.kind == "cfg"]
    call_edges = [e for e in edges if e.kind == "call"]
    return_edges = [e for e in edges if e.kind == "return"]

    write_tsv(
        outdir / "icfg_nodes.tsv",
        ["node_id", "function", "bb", "kind", "label", "source"],
        ((n.node_id, n.function, n.bb, n.kind, n.label, n.source) for n in sorted(nodes.values(), key=lambda x: x.node_id)),
    )
    write_tsv(
        outdir / "icfg_edges.tsv",
        ["src", "dst", "kind", "callsite_id", "raw_label"],
        ((e.src, e.dst, e.kind, e.callsite_id, e.raw_label) for e in edges),
    )
    write_tsv(outdir / "icfg_cfg_edges.tsv", ["src", "dst"], ((e.src, e.dst) for e in cfg_edges))
    write_tsv(
        outdir / "icfg_call_edges.tsv",
        ["callsite_node", "callee_entry_node", "caller_func", "callee_func", "callsite_id"],
        call_rows,
    )
    write_tsv(
        outdir / "icfg_return_edges.tsv",
        ["callee_exit_node", "return_node", "caller_func", "callee_func", "callsite_id"],
        ret_rows,
    )
    write_tsv(
        outdir / "icfg_phi.tsv",
        ["call_edge_src", "call_edge_dst", "return_edge_src", "return_edge_dst", "callsite_id", "caller_func", "callee_func"],
        phi_rows,
    )
    write_tsv(
        outdir / "icfg_functions.tsv",
        ["function", "entry_nodes", "exit_nodes", "node_count"],
        (
            (
                func,
                ",".join(sorted(data["entries"])),
                ",".join(sorted(data["exits"])),
                len(data["nodes"]),
            )
            for func, data in sorted(func_idx.items())
        ),
    )

    target_lines = []
    if args.targets and Path(args.targets).exists():
        target_lines = [x.strip() for x in Path(args.targets).read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()]

    with (outdir / "icfg_summary.txt").open("w", encoding="utf-8") as f:
        f.write("SVF ICFG normalization summary\n")
        f.write("==============================\n")
        f.write(f"mode: {'llvm-ir-fallback' if used_fallback else 'svf-dot'}\n")
        f.write(f"svf_dir: {svf_dir}\n")
        f.write(f"icfg_dot: {icfg_dot or '<none>'}\n")
        f.write(f"module_ll: {module_ll}\n")
        f.write(f"nodes: {len(nodes)}\n")
        f.write(f"edges: {len(edges)}\n")
        f.write(f"cfg_edges: {len(cfg_edges)}\n")
        f.write(f"call_edges: {len(call_edges)}\n")
        f.write(f"return_edges: {len(return_edges)}\n")
        f.write(f"phi_rows: {len(phi_rows)}\n")
        f.write(f"functions: {len(func_idx)}\n")
        if target_lines:
            f.write("targets:\n")
            for t in target_lines:
                f.write(f"  - {t}\n")
        if used_fallback:
            f.write("\nWARNING: Used LLVM IR fallback. This is an approximate direct-call ICFG, not SVF's full ICFG.\n")
        if not call_edges:
            f.write("\nWARNING: No call edges were classified. Check SVF DOT labels and parser heuristics.\n")
        if not return_edges:
            f.write("\nWARNING: No return edges were classified. Check SVF DOT labels and parser heuristics.\n")

    print(f"[normalize-svf-icfg] wrote outputs to: {outdir}", file=sys.stderr)
    print(f"[normalize-svf-icfg] nodes={len(nodes)} edges={len(edges)} cfg={len(cfg_edges)} call={len(call_edges)} ret={len(return_edges)} phi={len(phi_rows)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
