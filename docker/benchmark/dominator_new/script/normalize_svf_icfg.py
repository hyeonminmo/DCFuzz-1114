#!/usr/bin/env python3
"""
normalize_svf_icfg_phase6_v4.py - Phase 6 v4

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
  icfg_bb_mapping.tsv    node_id, function, kind, bb, method, dbg_ids, src_file,
                         src_line, src_col, svf_ir
  icfg_edges.tsv         src, dst, kind, callsite_id, raw_label
  icfg_cfg_edges.tsv     src, dst
  icfg_call_edges.tsv    callsite_node, callee_entry_node, caller_func, callee_func, callsite_id
  icfg_return_edges.tsv  callee_exit_node, return_node, caller_func, callee_func, callsite_id
  icfg_phi.tsv           call_edge_src, call_edge_dst, return_edge_src, return_edge_dst, callsite_id, caller_func, callee_func
  icfg_callsite_pairs.tsv callsite_id, callsite_node, return_node, caller_func, signature
  icfg_cross_product.tsv caller_func, callee_func, call_edges, return_edges,
                         legacy_generated_pairs, exact_pairs, excess_pairs
  icfg_callsites.tsv     callsite_id, callsite_node, return_node, caller_func, bb,
                         call_kind, direct_callee, src_file, src_line, src_col,
                         call_ordinal, func_indirect_ordinal, ir
  icfg_functions.tsv     function, entry_nodes, exit_nodes, node_count
  icfg_removed_summary_edges.tsv
                         CallBlockNode -> RetBlockNode summary CFG edges
                         removed from the dominator-analysis graph
  icfg_summary.txt       human-readable summary

Notes:
  * This script is intentionally defensive because SVF DOT labels differ across
    versions/build options. It first tries to parse SVF DOT files. If no ICFG DOT
    exists, it falls back to a conservative direct-call ICFG extracted from LLVM IR.
  * Phase 6 v4 never treats an arbitrary numeric SSA value such as %3 as a
    basic-block identity.  For SVF DOT input, each non-virtual ICFG node is
    mapped back to the actual containing basic block in module.ll using, in
    order, explicit BB metadata, !dbg identity, exact IR, canonical IR, and
    source location.
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

CALL_INST_RE = re.compile(r'\b(?:call|invoke)\b')

DIRECT_CALLEE_RE = re.compile(
    r'@("?[-A-Za-z$._0-9]+"?)\s*\('
)
INDIRECT_CALLEE_RE = re.compile(
    r'%("?[-A-Za-z$._0-9]+"?)\s*\('
)
BITCAST_DIRECT_CALLEE_RE = re.compile(
    r'\bbitcast\s*\(.*?@("?[-A-Za-z$._0-9]+"?).*?\)\s*\('
)

DBG_USE_RE = re.compile(r'!dbg\s+!(\d+)')
MD_RE = re.compile(
    r'^\s*!(\d+)\s*=\s*(?:distinct\s+)?!([A-Za-z0-9_]+)\((.*)\)\s*$'
)
KV_RE = re.compile(
    r'([A-Za-z_][A-Za-z0-9_]*)\s*:\s*'
    r'([^,][^,]*?(?=(?:,\s+[A-Za-z_][A-Za-z0-9_]*\s*:)|$))'
)

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

def strip_dot_port(node_id: str) -> str:
    """
    SVF DOT record edge는 다음처럼 port를 붙일 수 있음:
      Node0x555557738bb0:s1 -> Node0x555556888da0

    그런데 node 정의는:
      Node0x555557738bb0 [...]
    형태이므로, :s1을 제거해야 nodes[src] 매칭이 가능함.
    """
    node_id = unquote_dot_id(node_id)

    if ":" in node_id and node_id.startswith("Node"):
        node_id = node_id.split(":", 1)[0]

    return node_id


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
    src = strip_dot_port(left)

    attr_text = ""
    if '[' in right:
        dst_part, rest = right.split('[', 1)
        dst = strip_dot_port(dst_part)
        attr_text = rest.rsplit(']', 1)[0]
    else:
        dst = strip_dot_port(right)

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
    l = (label or "").lower()

    # SVF 2.x DOT label examples:
    #   FunEntryBlockNode
    #   FunExitBlockNode
    #   CallBlockNode
    #   RetBlockNode
    if "funentryblocknode" in l or "entryicfgnode" in l or "function entry" in l:
        return "entry"

    if "funexitblocknode" in l or "exiticfgnode" in l or "function exit" in l:
        return "exit"

    if "callblocknode" in l or "callicfgnode" in l or "call node" in l:
        return "call"

    if "retblocknode" in l or "returnblocknode" in l or "reticfgnode" in l or "return node" in l:
        return "return"

    if "intraicfgnode" in l or "intra" in l:
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

def infer_kind_from_svf_edge(
    attrs: Dict[str, str],
    src_node: Optional[Node],
    dst_node: Optional[Node],
) -> str:
    """Classify SVF ICFG edges by their explicit/structural semantics.

    Phase 0 v5 intentionally does NOT require ``src_func != dst_func``.

    A recursive call is still an interprocedural call:

        CallBlockNode(foo) -> FunEntryBlockNode(foo)

    and its corresponding return is still:

        FunExitBlockNode(foo) -> RetBlockNode(foo)

    Therefore function-name inequality is not a valid criterion for deciding
    whether an edge is call/return.

    Classification priority:
      1. explicit SVF edge label, when present;
      2. node-kind structure;
      3. DOT color as supporting evidence;
      4. otherwise CFG.
    """
    label = (attrs.get("label", "") or "").lower()
    color = (attrs.get("color", "") or "").lower()

    src_kind = src_node.kind if src_node else ""
    dst_kind = dst_node.kind if dst_node else ""

    ####
    # 1. Explicit SVF edge labels.
    ####
    if "callcf" in label or "call edge" in label:
        return "call"

    if "retcf" in label or "return edge" in label or "ret edge" in label:
        return "return"

    ####
    # 2. Structural SVF ICFG relation.
    #
    # CallCFGEdge:
    #   CallBlockNode -> FunEntryBlockNode
    #
    # This also correctly handles self-recursive calls because caller and
    # callee function names are allowed to be identical.
    ####
    if src_kind == "call" and dst_kind == "entry":
        return "call"

    ####
    # 3. Structural SVF return relation.
    #
    # RetCFGEdge:
    #   FunExitBlockNode -> RetBlockNode
    #
    # This also correctly handles recursive returns.
    ####
    if src_kind == "exit" and dst_kind == "return":
        return "return"

    ####
    # 4. Conservative color fallback.
    #
    # In the SVF DOT printer CallCFGEdge is typically red and RetCFGEdge
    # blue.  We still require the expected node kinds to avoid treating
    # unrelated red/blue graph edges as interprocedural edges.
    ####
    if color == "red" and src_kind == "call" and dst_kind == "entry":
        return "call"

    if color == "blue" and src_kind == "exit" and dst_kind == "return":
        return "return"

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
    """Extract only an *explicit* basic-block identity from an SVF label.

    Phase 6 v3 contained the fallback::

        r'%([0-9]+)\\b'

    That pattern is unsafe because ordinary LLVM SSA operands/results such as
    ``%3 = alloca ...`` or ``store i32 %0, i32* %4`` are not basic-block
    labels.  Treating them as BB numbers corrupted ``icfg_nodes.tsv``.

    Phase 6 v4 therefore accepts only text that explicitly identifies a BB.
    Most SVF instruction nodes will initially have ``bb == \"\"`` and are
    subsequently mapped to their real containing BB in ``module.ll`` by
    ``map_svf_nodes_to_module_bbs``.
    """
    label = clean_label(label)
    patterns = [
        r'BB\s*[:=]\s*%?([A-Za-z$._0-9-]+)',
        r'BasicBlock\s*[:=]\s*%?([A-Za-z$._0-9-]+)',
        r'\bbb\s*[:=]\s*%?([A-Za-z$._0-9-]+)',
        r'<label>:%?([A-Za-z$._0-9-]+)',
    ]
    for pat in patterns:
        m = re.search(pat, label, flags=re.IGNORECASE)
        if m:
            return norm_bb(m.group(1))
    return ""


# ---------------------------------------------------------------------------
# Phase 6 v4: SVF ICFG node -> real module.ll containing-basic-block mapping
# ---------------------------------------------------------------------------

LLVM_OPCODE_RE = re.compile(
    r'^(?:%[-A-Za-z$._0-9]+\s*=\s*)?'
    r'(?:alloca|load|store|getelementptr|call|invoke|ret|br|switch|indirectbr|'
    r'resume|unreachable|phi|select|icmp|fcmp|add|fadd|sub|fsub|mul|fmul|udiv|'
    r'sdiv|fdiv|urem|srem|frem|shl|lshr|ashr|and|or|xor|trunc|zext|sext|'
    r'fptrunc|fpext|fptoui|fptosi|uitofp|sitofp|ptrtoint|inttoptr|bitcast|'
    r'addrspacecast|extractelement|insertelement|shufflevector|extractvalue|'
    r'insertvalue|landingpad|catchpad|cleanuppad|catchswitch|catchret|cleanupret|'
    r'va_arg|freeze|atomicrmw|cmpxchg|fence)\b',
    flags=re.IGNORECASE,
)

SVF_NODE_PREFIX_RE = re.compile(
    r'^\s*(?:IntraBlockNode|CallBlockNode|RetBlockNode|CallICFGNode|RetICFGNode)'
    r'(?:\s+ID)?\s*:\s*\d+\s*',
    flags=re.IGNORECASE,
)

SVF_LOC_RE = re.compile(
    r'\{\s*ln:\s*(?P<line>\d+)'
    r'(?:\s+cl:\s*(?P<col>\d+))?'
    r'\s+fl:\s*(?P<file>[^}]+?)\s*\}',
    flags=re.IGNORECASE,
)

SVF_ENTRY_LOC_RE = re.compile(
    r'\{\s*in\s+line:\s*(?P<line>\d+)'
    r'\s+file:\s*(?P<file>[^}]+?)\s*\}',
    flags=re.IGNORECASE,
)


def normalize_ir_for_bb_matching(text: str) -> str:
    """Normalize one LLVM IR instruction fragment for cross-printer matching."""
    s = clean_label(text)
    if not s:
        return ""

    s = s.replace("\\{", "{").replace("\\}", "}")

    # SVF sometimes emits an empty diagnostic brace pair after an instruction.
    s = re.sub(r'\s*\{\s*\}', ' ', s)

    # Remove SVF's diagnostic source/function annotations, not LLVM IR itself.
    s = re.sub(r'\s*\{\s*ln:\s*\d+.*?\}', '', s, flags=re.IGNORECASE)
    s = re.sub(r'\s*\{\s*in\s+line:\s*\d+.*?\}', '', s, flags=re.IGNORECASE)
    s = re.sub(r'\s*\{\s*fun:\s*[^}]*\}', '', s, flags=re.IGNORECASE)

    # Debug/analysis metadata can be printed differently by SVF vs llvm-dis.
    # It is not needed to identify the containing BB because !dbg is indexed
    # separately as a stronger mapping key. Strip from the first ordinary
    # metadata attachment onward (e.g. !dbg, !tbaa, !range, !prof).
    s = re.sub(
        r',\s*![A-Za-z0-9_.-]+\s+!\d+.*$',
        '',
        s,
    )

    # Avoid comments being part of an otherwise identical instruction.
    s = re.sub(r'\s+;.*$', '', s)

    return re.sub(r'\s+', ' ', s).strip()


def canonicalize_ir_for_bb_matching(text: str) -> str:
    """SSA-number-insensitive fallback used only after exact IR matching."""
    s = normalize_ir_for_bb_matching(text)
    if not s:
        return ""
    s = re.sub(r'%[0-9]+\b', '%SSA', s)
    return re.sub(r'\s+', ' ', s).strip()


def extract_svf_instruction_ir(label: str) -> str:
    """Extract the LLVM instruction fragment printed inside an SVF node label.

    The first instruction-looking logical line is sufficient for BB recovery.
    For multi-line instructions such as ``switch``, the first line normally
    contains enough IR to match the first module.ll line; !dbg/source-location
    matching remains available when it does not.
    """
    s = clean_label(label)
    if not s:
        return ""

    for raw_line in s.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Normalize SVF's escaped diagnostic braces before stripping them.
        line = line.replace("\\{", "{").replace("\\}", "}")

        # Remove the graph/node header when the IR begins on the same line.
        line = SVF_NODE_PREFIX_RE.sub('', line).strip()

        # Remove a leading SVF pointer-analysis annotation if one occupies the
        # line.  Normally the actual instruction is printed on the next line.
        if re.match(
            r'^(?:AddrPE|LoadPE|StorePE|NormalGepPE|VariantGepPE|CopyPE|CallPE|RetPE)\s*:',
            line,
            flags=re.IGNORECASE,
        ):
            continue

        line = re.sub(r'\s*\{\s*ln:\s*\d+.*$', '', line, flags=re.IGNORECASE)
        line = re.sub(r'\s*\{\s*in\s+line:\s*\d+.*$', '', line, flags=re.IGNORECASE)
        line = re.sub(r'\s*\{\s*fun:\s*[^}]*\}.*$', '', line, flags=re.IGNORECASE)
        line = line.strip()

        if LLVM_OPCODE_RE.match(line):
            return normalize_ir_for_bb_matching(line)

    return ""


def extract_svf_source_location(label: str) -> Tuple[str, str, str]:
    """Extract SVF's human-readable ``fl/ln/cl`` annotation when present."""
    s = clean_label(label)
    s = s.replace("\\{", "{").replace("\\}", "}")
    m = SVF_LOC_RE.search(s)
    if m:
        return (
            norm_src_file(m.group('file').strip()),
            m.group('line') or '',
            m.group('col') or '',
        )

    m = SVF_ENTRY_LOC_RE.search(s)
    if m:
        return (
            norm_src_file(m.group('file').strip()),
            m.group('line') or '',
            '',
        )

    return '', '', ''


def build_module_bb_mapping_index(module_ll: Path) -> Dict[str, object]:
    """Index module.ll instructions/debug locations by their containing BB."""
    lines = module_ll.read_text(encoding='utf-8', errors='replace').splitlines()
    metadata = parse_llvm_metadata(lines)

    function_bbs: Dict[str, Set[str]] = defaultdict(set)
    dbg_index: Dict[Tuple[str, int], Set[str]] = defaultdict(set)
    exact_ir_index: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    canonical_ir_index: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    source_loc_index: Dict[Tuple[str, str, str, str], Set[str]] = defaultdict(set)
    source_line_index: Dict[Tuple[str, str, str], Set[str]] = defaultdict(set)

    current_func: Optional[str] = None
    current_bb: Optional[str] = None

    for raw in lines:
        dm = DEFINE_RE.match(raw)
        if dm:
            current_func = norm_func(dm.group(1))
            current_bb = 'entry'
            function_bbs[current_func].add(current_bb)
            continue

        if current_func is not None and re.match(r'^\s*}\s*$', raw):
            current_func = None
            current_bb = None
            continue

        if current_func is None or current_bb is None:
            continue

        bm = BB_NAMED_RE.match(raw)
        if bm:
            current_bb = norm_bb(bm.group(1))
            function_bbs[current_func].add(current_bb)
            continue

        stripped = raw.strip()
        if not stripped or stripped.startswith(';'):
            continue

        exact = normalize_ir_for_bb_matching(stripped)
        if exact:
            exact_ir_index[(current_func, exact)].add(current_bb)
            canonical = canonicalize_ir_for_bb_matching(exact)
            if canonical:
                canonical_ir_index[(current_func, canonical)].add(current_bb)

        # A !dbg attachment is an excellent identity when SVF and module.ll
        # were produced from the same bitcode. Multiple instructions may share
        # a DILocation, so we accept it only when all occurrences lie in one BB.
        for dbg_text in DBG_USE_RE.findall(raw):
            dbg_id = int(dbg_text)
            dbg_index[(current_func, dbg_id)].add(current_bb)

            src_file, src_line, src_col = resolve_debug_location(metadata, dbg_id)
            src_file = norm_src_file(src_file)
            if src_line:
                source_loc_index[
                    (current_func, src_file, src_line, src_col)
                ].add(current_bb)
                source_line_index[
                    (current_func, src_file, src_line)
                ].add(current_bb)

    return {
        'function_bbs': function_bbs,
        'dbg_index': dbg_index,
        'exact_ir_index': exact_ir_index,
        'canonical_ir_index': canonical_ir_index,
        'source_loc_index': source_loc_index,
        'source_line_index': source_line_index,
    }


def _unique_bb(candidates: Optional[Set[str]]) -> str:
    if not candidates or len(candidates) != 1:
        return ''
    return next(iter(candidates))


def map_svf_nodes_to_module_bbs(
    nodes: Dict[str, Node],
    module_ll: Path,
) -> Tuple[Dict[str, Node], List[Tuple], Dict[str, int]]:
    """Map each real SVF instruction node to its actual module.ll BB.

    Mapping priority:
      1. function entry -> ``entry``;
      2. explicit BB metadata, but only if that BB exists in module.ll;
      3. unique ``!dbg`` identity within the function;
      4. unique exact normalized instruction IR;
      5. unique numeric-SSA-canonicalized instruction IR;
      6. unique source file/line/column (then file/line) location.

    A function-exit SVF node is virtual and has no real containing LLVM BB, so
    its BB is deliberately left empty instead of fabricating ``entry`` or a
    numeric value.
    """
    index = build_module_bb_mapping_index(module_ll)
    function_bbs = index['function_bbs']
    dbg_index = index['dbg_index']
    exact_ir_index = index['exact_ir_index']
    canonical_ir_index = index['canonical_ir_index']
    source_loc_index = index['source_loc_index']
    source_line_index = index['source_line_index']

    mapped: Dict[str, Node] = {}
    diagnostics: List[Tuple] = []
    stats: Dict[str, int] = defaultdict(int)

    for node_id, node in nodes.items():
        func = node.function
        old_bb = node.bb
        new_bb = ''
        method = 'unresolved'

        svf_ir = extract_svf_instruction_ir(node.label)
        dbg_ids = [int(x) for x in DBG_USE_RE.findall(node.label)]
        src_file, src_line, src_col = extract_svf_source_location(node.label)

        if node.kind == 'entry' and func:
            if 'entry' in function_bbs.get(func, set()):
                new_bb = 'entry'
                method = 'function-entry'

        elif node.kind == 'exit':
            # SVF's FunExitBlockNode is a virtual unique-exit node, not an LLVM
            # BasicBlock. Keep it unmapped rather than inventing a BB identity.
            method = 'virtual-function-exit'

        elif func:
            # Explicit BB metadata is trusted only after validation against the
            # actual module.ll function.
            if old_bb and old_bb in function_bbs.get(func, set()):
                new_bb = old_bb
                method = 'explicit-bb'

            if not new_bb and dbg_ids:
                candidates: Set[str] = set()
                for dbg_id in dbg_ids:
                    candidates.update(dbg_index.get((func, dbg_id), set()))
                bb = _unique_bb(candidates)
                if bb:
                    new_bb = bb
                    method = 'dbg-id'

            if not new_bb and svf_ir:
                bb = _unique_bb(exact_ir_index.get((func, svf_ir), set()))
                if bb:
                    new_bb = bb
                    method = 'exact-ir'

            if not new_bb and svf_ir:
                canonical = canonicalize_ir_for_bb_matching(svf_ir)
                if canonical:
                    bb = _unique_bb(
                        canonical_ir_index.get((func, canonical), set())
                    )
                    if bb:
                        new_bb = bb
                        method = 'canonical-ir'

            if not new_bb and src_line:
                bb = ''
                if src_col:
                    bb = _unique_bb(
                        source_loc_index.get(
                            (func, src_file, src_line, src_col), set()
                        )
                    )
                if not bb:
                    bb = _unique_bb(
                        source_line_index.get(
                            (func, src_file, src_line), set()
                        )
                    )
                if bb:
                    new_bb = bb
                    method = 'source-location'

        stats[method] += 1

        mapped[node_id] = Node(
            node_id=node.node_id,
            function=node.function,
            bb=new_bb,
            kind=node.kind,
            label=node.label,
            source=node.source,
        )

        diagnostics.append(
            (
                node.node_id,
                node.function,
                node.kind,
                old_bb,
                new_bb,
                method,
                ','.join(str(x) for x in dbg_ids),
                src_file,
                src_line,
                src_col,
                svf_ir,
            )
        )

    return mapped, diagnostics, dict(stats)


def parse_svf_icfg_dot(dot_path: Path) -> Tuple[Dict[str, Node], List[Edge]]:
    nodes: Dict[str, Node] = {}
    edges: List[Edge] = []

    stmts = collect_dot_statements(dot_path)

    ####
    # 1st pass: node 정의를 먼저 모두 수집
    ####
    for stmt in stmts:
        ns = split_dot_node_stmt(stmt)
        if not ns:
            continue

        node_id, attr_text = ns
        node_id = strip_dot_port(node_id)

        attrs = parse_dot_attrs(attr_text)
        label = attrs.get("label", "")

        function = extract_function_from_label(label)
        bb = extract_bb_from_label(label)
        kind = infer_kind_from_node_label(label)

        nodes[node_id] = Node(
            node_id=node_id,
            function=function,
            bb=bb,
            kind=kind,
            label=label,
            source=str(dot_path.name),
        )

    ####
    # 2nd pass: edge를 node kind/color 기반으로 분류
    ####
    for stmt in stmts:
        es = split_dot_edge_stmt(stmt)
        if not es:
            continue

        src, dst, attr_text = es
        src = strip_dot_port(src)
        dst = strip_dot_port(dst)

        attrs = parse_dot_attrs(attr_text)

        src_node = nodes.get(src)
        dst_node = nodes.get(dst)

        kind = infer_kind_from_svf_edge(attrs, src_node, dst_node)

        raw_label = attrs.get("label", "") or attrs.get("color", "") or attr_text

        edges.append(
            Edge(
                src=src,
                dst=dst,
                kind=kind,
                raw_label=raw_label,
            )
        )

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
    """Assign one ID per callsite node, not per call edge.

    An indirect callsite may have multiple candidate callees, hence multiple
    call edges with the same source node.  All of those edges must share the
    same callsite ID.
    """
    result: List[Edge] = []
    callsite_ids: Dict[str, str] = {}
    counter = 0

    for e in edges:
        if e.kind != "call":
            result.append(e)
            continue

        if e.src not in callsite_ids:
            callsite_ids[e.src] = f"cs{counter}"
            counter += 1

        result.append(
            Edge(
                src=e.src,
                dst=e.dst,
                kind=e.kind,
                raw_label=e.raw_label,
                callsite_id=callsite_ids[e.src],
            )
        )

    return result


SVF_NODE_ID_RE = re.compile(
    r"\bNodeID\s*:\s*(\d+)\b",
    flags=re.IGNORECASE,
)


def extract_svf_node_id(label: str) -> Optional[int]:
    """Extract the numeric SVF ICFG NodeID from a DOT node label.

    SVF-2.2 DOT labels begin with a generic node identifier such as:

      {NodeID: 34428 CallBlockNode ID: 34428 ...}
      {NodeID: 34429 RetBlockNode ID: 34429 ...}

    The DOT graph node name (e.g. Node0x...) is not used because it is a
    process-local pointer-like identifier.  The numeric NodeID is the stable
    identifier assigned by SVF's ICFG.
    """
    s = clean_label(label)
    if not s:
        return None

    m = SVF_NODE_ID_RE.search(s)
    if not m:
        return None

    return int(m.group(1))


def extract_svf_callsite_signature(label: str) -> str:
    """Return a normalized callsite string for diagnostics only.

    Phase 0 v5 does not use this string as the primary CallBlockNode <->
    RetBlockNode pairing key.  Distinct LLVM call instructions may have the
    same textual instruction and the same debug location, which made the v2
    signature-based pairing ambiguous.

    The signature is retained only for:
      * icfg_callsite_pairs.tsv diagnostics
      * validating the structural SVF CallBlockNode/RetBlockNode pairing
    """
    s = clean_label(label)
    if not s:
        return ""

    s = re.sub(r"^\s*\{\s*", "", s, count=1)

    s = re.sub(
        r"^\s*NodeID\s*:\s*\d+\s*",
        "",
        s,
        count=1,
        flags=re.IGNORECASE,
    )

    s = re.sub(
        r"^\s*(?:CallBlockNode|RetBlockNode|CallICFGNode|RetICFGNode)"
        r"(?:\s+ID)?\s*:?\s*\d*\s*",
        "",
        s,
        count=1,
        flags=re.IGNORECASE,
    )

    s = re.sub(
        r"\|\{\|<s\d+>0x[0-9A-Fa-f]+\}\}\s*$",
        "",
        s,
        count=1,
    )

    # DOT record labels can leave one or more unescaped closing braces after
    # the actual SVF text.  Remove only those graph-syntax braces; keep '\}'
    # because it belongs to the escaped "{fun: ...}" diagnostic fragment.
    while re.search(r"(?<!\\)\}\s*$", s):
        s = re.sub(r"(?<!\\)\}\s*$", "", s, count=1)

    return re.sub(r"\s+", " ", s).strip()

def normalize_call_ir(text: str) -> str:
    s = clean_label(text)

    if not s:
        return ""
    s = s.replace("\\{", "{").replace("\\}", "}")
    s = re.sub(r'\s*\{fun:\s*[^}]*\}.*$', '', s)

    m = CALL_INST_RE.search(s)
    if not m:
        return ""

    s = s[m.start():]

    s = re.sub(r',\s*!dbg\s*!\d+.*$', '', s)

    return re.sub(r'\s+', ' ', s).strip()




def canonicalize_call_ir_for_matching(text: str) -> str:
    """Canonicalize a call instruction for SVF -> module.ll matching.

    SVF DOT labels and LLVM IR re-printing can assign different numbers to
    unnamed SSA values even when they describe the same physical call:

        call void %86(%union.SWF_ACTION* %87)
        call void %91(%union.SWF_ACTION* %92)

    ``normalize_call_ir`` already removes result assignments and trailing
    debug metadata. Here we additionally canonicalize only numeric SSA
    operands. Named values and named struct types are preserved.

    This helper is only a local SVF -> module.ll matching aid. It is not used
    as the final cross-tool callsite identity.
    """
    s = normalize_call_ir(text)
    if not s:
        return ""

    s = re.sub(r'%[0-9]+\b', '%SSA', s)
    return re.sub(r'\s+', ' ', s).strip()


def classify_call_instruction(ir: str) -> Tuple[str, str]:
    s = normalize_call_ir(ir)

    if not s:
        return "unknown", ""

    # Direct call:   call void @foo()
    m = DIRECT_CALLEE_RE.search(s)
    if m:
        return "direct", norm_func(m.group(1))
    
    m = BITCAST_DIRECT_CALLEE_RE.search(s)

    if m:
        return "direct", norm_func(m.group(1))

    # Indirect call:
    #   call void %fp()
    #   %1 = call i32 %17(...) 
    m = INDIRECT_CALLEE_RE.search(s)
    if m:
        return "indirect", ""
    
    

    return "unknown", ""

def md_ref_to_int(v: str) -> Optional[int]:
    if not v:
        return None
    m = re.match(r'!(\d+)$', v.strip())
    return int(m.group(1)) if m else None


def strip_md_string(v: str) -> str:
    v = (v or "").strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        v = v[1:-1]
    return v


def norm_src_file(path: str) -> str:
    """Normalize debug-info filenames for SVF <-> DeepType matching."""
    s = (path or "").strip().replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    return s


def parse_llvm_metadata(
    lines: Sequence[str],
) -> Dict[int, Dict[str, object]]:
    metadata: Dict[int, Dict[str, object]] = {}
    for line in lines:
        m = MD_RE.match(line)
        if not m:
            continue
        md_id = int(m.group(1))
        tag = m.group(2)
        body = m.group(3)
        attrs: Dict[str, str] = {}
        for km in KV_RE.finditer(body):
            attrs[km.group(1)] = km.group(2).strip()
        metadata[md_id] = {"tag": tag, "attrs": attrs}
    return metadata


def resolve_debug_location(
    metadata: Dict[int, Dict[str, object]],
    dbg_id: Optional[int],
) -> Tuple[str, str, str]:
    """Resolve !DILocation to filename, line and column.

    The scope chain is followed until a node with a ``file`` reference is
    found. Missing or ambiguous debug metadata is kept empty rather than
    guessed because icfg_callsites.tsv is used as an SMLTA/DeepType join key.
    """
    if dbg_id is None:
        return "", "", ""

    loc = metadata.get(dbg_id)
    if not loc or loc.get("tag") != "DILocation":
        return "", "", ""

    attrs = loc.get("attrs", {})
    if not isinstance(attrs, dict):
        return "", "", ""

    src_line = str(attrs.get("line", ""))
    src_col = str(attrs.get("column", ""))
    scope_id = md_ref_to_int(str(attrs.get("scope", "")))

    src_file = ""
    visited: Set[int] = set()
    cur = scope_id

    while cur is not None and cur not in visited:
        visited.add(cur)
        scope = metadata.get(cur)
        if not scope:
            break
        scope_attrs = scope.get("attrs", {})
        if not isinstance(scope_attrs, dict):
            break

        file_id = md_ref_to_int(str(scope_attrs.get("file", "")))
        if file_id is not None:
            file_node = metadata.get(file_id)
            if file_node and file_node.get("tag") == "DIFile":
                file_attrs = file_node.get("attrs", {})
                if isinstance(file_attrs, dict):
                    src_file = strip_md_string(str(file_attrs.get("filename", "")))
                break

        cur = md_ref_to_int(str(scope_attrs.get("scope", "")))

    return src_file, src_line, src_col


def parse_module_ll_callsites(
    module_ll: Path,
) -> Tuple[
    Dict[str, List[Dict[str, str]]],
    Dict[int, Dict[str, object]],
]:
    """Parse LLVM calls in deterministic IR order.

    call_ordinal:
      zero-based among indirect calls sharing
      caller_func + src_file + src_line + src_col

    func_indirect_ordinal:
      zero-based among all indirect calls in the caller function.

    The first value remains the production cross-tool stable-key component.
    The second value is diagnostic and lets Phase 6 compare the same
    function-wide indirect-call position even when source locations disagree.
    """
    result: Dict[str, List[Dict[str, str]]] = defaultdict(list)

    lines = module_ll.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines()
    metadata = parse_llvm_metadata(lines)

    current_func: Optional[str] = None
    current_bb: Optional[str] = None
    current_call_index = 0
    current_indirect_index = 0

    indirect_location_counts: Dict[
        Tuple[str, str, str, str], int
    ] = defaultdict(int)

    for raw in lines:
        dm = DEFINE_RE.match(raw)
        if dm:
            current_func = norm_func(dm.group(1))
            current_bb = "entry"
            current_call_index = 0
            current_indirect_index = 0
            continue

        if current_func is not None and re.match(r'^\s*}\s*$', raw):
            current_func = None
            current_bb = None
            current_call_index = 0
            current_indirect_index = 0
            continue

        if current_func is None:
            continue

        bm = BB_NAMED_RE.match(raw)
        if bm:
            current_bb = norm_bb(bm.group(1))
            continue

        if not CALL_INST_RE.search(raw):
            continue

        normalized_ir = normalize_call_ir(raw)
        if not normalized_ir:
            continue

        call_kind, direct_callee = classify_call_instruction(normalized_ir)

        dbg_ids = DBG_USE_RE.findall(raw)
        dbg_id: Optional[int] = int(dbg_ids[0]) if len(dbg_ids) == 1 else None
        src_file, src_line, src_col = resolve_debug_location(metadata, dbg_id)
        src_file = norm_src_file(src_file)

        call_ordinal = ""
        func_indirect_ordinal = ""

        if call_kind == "indirect":
            stable_base = (current_func, src_file, src_line, src_col)
            call_ordinal = str(indirect_location_counts[stable_base])
            indirect_location_counts[stable_base] += 1

            func_indirect_ordinal = str(current_indirect_index)
            current_indirect_index += 1

        result[current_func].append(
            {
                "bb": current_bb or "",
                "ir": raw.strip(),
                "normalized_ir": normalized_ir,
                "call_kind": call_kind,
                "direct_callee": direct_callee,
                "dbg_id": str(dbg_id) if dbg_id is not None else "",
                "src_file": src_file,
                "src_line": src_line,
                "src_col": src_col,
                "call_index": str(current_call_index),
                "call_ordinal": call_ordinal,
                "func_indirect_ordinal": func_indirect_ordinal,
            }
        )
        current_call_index += 1

    return result, metadata

def build_callsite_return_node_map(
    nodes: Dict[str, Node],
    edges: List[Edge],
) -> Tuple[Dict[str, str], Dict[str, str]]:

    call_nodes = sorted({
        e.src
        for e in edges
        if e.kind == "call"
    })

    call_to_ret: Dict[str, str] = {}
    signature_by_call: Dict[str, str] = {}

   
    # 1. Index exact structural CFG edges:
    #       CallBlockNode --cfg/IntraCFGEdge--> RetBlockNode
    ret_candidates: Dict[str, Set[str]] = defaultdict(set)

    for e in edges:
        if e.kind != "cfg":
            continue

        src = nodes.get(e.src)
        dst = nodes.get(e.dst)

        if src is None or dst is None:
            continue

        if src.kind != "call" or dst.kind != "return":
            continue

        ret_candidates[e.src].add(e.dst)

    
    # 2. Resolve one continuation node for each interprocedural callsite.
    errors: List[str] = []
    missing_pairs = 0

    for call_node in call_nodes:
        call = nodes.get(call_node, Node(call_node))

        signature_by_call[call_node] = (
            call_node
            if call.source == "llvm-ir-fallback"
            else extract_svf_callsite_signature(call.label)
        )
        # LLVM-IR fallback
        if call.source == "llvm-ir-fallback":
            synthetic_ret = f"{call_node}:ret"
            ret = nodes.get(synthetic_ret)

            if ret is None or ret.kind != "return":
                errors.append(
                    "missing synthetic LLVM-IR fallback return node: "
                    f"callsite_node={call_node}"
                )
                continue

            call_to_ret[call_node] = synthetic_ret
            continue

        # SVF structural pairing
        candidates = sorted(ret_candidates.get(call_node, set()))

        if len(candidates) == 0:
            missing_pairs += 1
            print(
                "[normalize-svf-icfg] WARNING: "
                "no structural CallBlockNode->RetBlockNode CFG edge; "
                "leaving callsite without a phi relation: "
                f"callsite_node={call_node}, "
                f"function={call.function!r}, "
                f"signature={signature_by_call[call_node]!r}",
                file=sys.stderr,
            )
            continue

        if len(candidates) > 1:
            errors.append(
                "multiple structural RetBlockNodes for one CallBlockNode: "
                f"callsite_node={call_node}, "
                f"function={call.function!r}, "
                f"return_nodes={candidates}"
            )
            continue

        ret_node = candidates[0]
        ret = nodes.get(ret_node, Node(ret_node))

        if ret.kind != "return":
            errors.append(
                "structural continuation candidate is not a RetBlockNode: "
                f"callsite_node={call_node}, "
                f"return_node={ret_node}, "
                f"return_kind={ret.kind!r}"
            )
            continue

        if (
            call.function
            and ret.function
            and call.function != ret.function
        ):
            errors.append(
                "CallBlockNode/RetBlockNode caller mismatch: "
                f"callsite_node={call_node}, "
                f"call_function={call.function!r}, "
                f"return_node={ret_node}, "
                f"return_function={ret.function!r}"
            )
            continue

        call_to_ret[call_node] = ret_node
        call_sig = signature_by_call[call_node]
        ret_sig = extract_svf_callsite_signature(ret.label)
        if call_sig and ret_sig and call_sig != ret_sig:
            print(
                "[normalize-svf-icfg] WARNING: "
                "Call/Ret diagnostic signatures differ for a structural pair: "
                f"call={call_node}, ret={ret_node}, "
                f"call_signature={call_sig!r}, "
                f"ret_signature={ret_sig!r}",
                file=sys.stderr,
            )

    # 3. A RetBlockNode must not be paired with multiple callsites.
    calls_by_ret: Dict[str, List[str]] = defaultdict(list)
    for call_node, ret_node in call_to_ret.items():
        calls_by_ret[ret_node].append(call_node)

    for ret_node, calls in sorted(calls_by_ret.items()):
        if len(calls) > 1:
            errors.append(
                "RetBlockNode paired with multiple CallBlockNodes: "
                f"return_node={ret_node}, callsites={sorted(calls)}"
            )

    if errors:
        raise RuntimeError(
            "failed to recover exact SVF CallBlockNode/RetBlockNode "
            "structural pairing:\n  "
            + "\n  ".join(errors)
        )

    print(
        "[normalize-svf-icfg] "
        f"structurally paired {len(call_to_ret)} / {len(call_nodes)} "
        f"interprocedural callsites"
        + (f" ({missing_pairs} without modeled structural return node)"
           if missing_pairs else ""),
        file=sys.stderr,
    )

    return call_to_ret, signature_by_call



def assign_return_callsite_ids(
    edges: List[Edge],
    call_to_ret_node: Dict[str, str],
) -> List[Edge]:
    """Propagate each callsite ID to return edges targeting its RetBlockNode."""
    cs_by_call_node: Dict[str, str] = {}
    for e in edges:
        if e.kind != "call" or not e.callsite_id:
            continue
        old = cs_by_call_node.get(e.src)
        if old is not None and old != e.callsite_id:
            raise RuntimeError(
                f"callsite node has multiple IDs: {e.src}: {old}, {e.callsite_id}"
            )
        cs_by_call_node[e.src] = e.callsite_id

    cs_by_ret_node: Dict[str, str] = {}
    for call_node, ret_node in call_to_ret_node.items():
        cs = cs_by_call_node.get(call_node, "")
        if not cs:
            continue
        old = cs_by_ret_node.get(ret_node)
        if old is not None and old != cs:
            raise RuntimeError(
                f"return node maps to multiple callsite IDs: {ret_node}: {old}, {cs}"
            )
        cs_by_ret_node[ret_node] = cs

    result: List[Edge] = []
    for e in edges:
        if e.kind == "return":
            result.append(
                Edge(
                    src=e.src,
                    dst=e.dst,
                    kind=e.kind,
                    raw_label=e.raw_label,
                    callsite_id=cs_by_ret_node.get(e.dst, e.callsite_id),
                )
            )
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


def derive_call_return_tables(
    nodes: Dict[str, Node],
    edges: List[Edge],
    call_to_ret_node: Dict[str, str],
) -> Tuple[List[Tuple], List[Tuple], List[Tuple]]:
    """Build call, return and phi tables without caller/callee cross-products.

    For every call edge c = CallNode -> CalleeEntry, first identify the unique
    RetBlockNode paired with CallNode.  Then select only the return edge
    CalleeExit -> that RetBlockNode.  This distinguishes multiple callsites in
    the same caller that invoke the same callee.
    """
    call_rows: List[Tuple] = []
    return_rows: List[Tuple] = []
    phi_rows: List[Tuple] = []

    # Index unique physical return edges by (callee function, return node).
    returns_by_callee_ret: Dict[Tuple[str, str], Dict[Tuple[str, str], Edge]] = defaultdict(dict)
    for e in edges:
        if e.kind != "return":
            continue
        callee = nodes.get(e.src, Node(e.src)).function
        returns_by_callee_ret[(callee, e.dst)][(e.src, e.dst)] = e

    used_return_edges: Set[Tuple[str, str]] = set()

    for c in edges:
        if c.kind != "call":
            continue

        caller = nodes.get(c.src, Node(c.src)).function
        callee = nodes.get(c.dst, Node(c.dst)).function
        cs = c.callsite_id

        call_rows.append((c.src, c.dst, caller, callee, cs))

        ret_node = call_to_ret_node.get(c.src)
        if not ret_node:
            # No structural continuation node was recovered for this callsite.
            # Keep the call edge, but never invent a return edge or phi pair.
            #
            # If a physical return edge actually exists, the unmatched-return
            # validation below will still fail, preventing silent corruption.
            continue

        candidates = list(returns_by_callee_ret.get((callee, ret_node), {}).values())

        # A call to a non-returning function can legitimately have no return edge.
        if not candidates:
            continue

        if len(candidates) != 1:
            raise RuntimeError(
                "expected exactly one physical return edge for callsite/callee: "
                f"callsite_node={c.src}, callee={callee}, return_node={ret_node}, "
                f"matches={[(e.src, e.dst) for e in candidates]}"
            )

        r = candidates[0]
        r_caller = nodes.get(r.dst, Node(r.dst)).function
        if caller and r_caller and caller != r_caller:
            raise RuntimeError(
                "call/return caller mismatch: "
                f"callsite_node={c.src}, call_caller={caller}, "
                f"return_node={r.dst}, return_caller={r_caller}"
            )

        used_return_edges.add((r.src, r.dst))
        return_rows.append((r.src, r.dst, caller, callee, cs))
        phi_rows.append((c.src, c.dst, r.src, r.dst, cs, caller, callee))

    # Every physical return edge should correspond to some call edge.
    all_return_edges = {
        (e.src, e.dst)
        for e in edges
        if e.kind == "return"
    }
    unmatched = sorted(all_return_edges - used_return_edges)
    if unmatched:
        raise RuntimeError(
            "return edge(s) could not be matched to an exact callsite: "
            + ", ".join(f"{src}->{dst}" for src, dst in unmatched)
        )

    return call_rows, return_rows, phi_rows


def derive_cross_product_diagnostics(
    nodes: Dict[str, Node],
    edges: List[Edge],
    phi_rows: Sequence[Tuple],
) -> List[Tuple]:
    calls_by_pair: Dict[Tuple[str, str], int] = defaultdict(int)
    returns_by_pair: Dict[Tuple[str, str], int] = defaultdict(int)
    exact_by_pair: Dict[Tuple[str, str], int] = defaultdict(int)

    for e in edges:
        if e.kind == "call":
            caller = nodes.get(e.src, Node(e.src)).function
            callee = nodes.get(e.dst, Node(e.dst)).function
            calls_by_pair[(caller, callee)] += 1
        elif e.kind == "return":
            callee = nodes.get(e.src, Node(e.src)).function
            caller = nodes.get(e.dst, Node(e.dst)).function
            returns_by_pair[(caller, callee)] += 1

    for row in phi_rows:
        if len(row) < 7:
            continue
        caller = str(row[5])
        callee = str(row[6])
        exact_by_pair[(caller, callee)] += 1

    rows: List[Tuple] = []
    for caller, callee in sorted(set(calls_by_pair) | set(returns_by_pair)):
        call_count = calls_by_pair.get((caller, callee), 0)
        return_count = returns_by_pair.get((caller, callee), 0)
        legacy_generated = call_count * return_count
        exact_pairs = exact_by_pair.get((caller, callee), 0)
        excess_pairs = max(0, legacy_generated - exact_pairs)

        if excess_pairs == 0:
            continue

        rows.append(
            (
                caller,
                callee,
                call_count,
                return_count,
                legacy_generated,
                exact_pairs,
                excess_pairs,
            )
        )

    return rows



def remove_fully_modeled_call_summary_edges(
    nodes: Dict[str, Node],
    edges: List[Edge],
    call_to_ret_node: Dict[str, str],
    phi_rows: Sequence[Tuple],
) -> Tuple[List[Edge], List[Tuple]]:

    call_edges_by_node: Dict[str, Set[Tuple[str, str]]] = defaultdict(set)
    callsite_id_by_node: Dict[str, str] = {}

    for e in edges:
        if e.kind != "call":
            continue

        call_edges_by_node[e.src].add((e.src, e.dst))

        if e.callsite_id:
            old = callsite_id_by_node.get(e.src)
            if old is not None and old != e.callsite_id:
                raise RuntimeError(
                    "callsite node has multiple callsite IDs while filtering "
                    f"summary edges: {e.src}: {old}, {e.callsite_id}"
                )
            callsite_id_by_node[e.src] = e.callsite_id

    phi_call_edges: Set[Tuple[str, str]] = set()
    for row in phi_rows:
        if len(row) < 2:
            continue
        phi_call_edges.add((str(row[0]), str(row[1])))

    removable_pairs: Set[Tuple[str, str]] = set()

    for call_node, ret_node in call_to_ret_node.items():
        call_pairs = call_edges_by_node.get(call_node, set())

        # No interprocedural call edge -> do not alter the local CFG.
        if not call_pairs:
            continue

        # Remove the summary edge only when every target has an explicit,
        # successfully matched return edge / phi relation.
        if call_pairs.issubset(phi_call_edges):
            removable_pairs.add((call_node, ret_node))

    filtered: List[Edge] = []
    removed_rows: List[Tuple] = []

    for e in edges:
        if (
            e.kind == "cfg"
            and (e.src, e.dst) in removable_pairs
        ):
            caller = nodes.get(e.src, Node(e.src)).function
            removed_rows.append(
                (
                    e.src,
                    e.dst,
                    callsite_id_by_node.get(e.src, ""),
                    caller,
                    "all-interprocedural-targets-have-explicit-return-edges",
                    e.raw_label,
                )
            )
            continue

        filtered.append(e)

    print(
        "[normalize-svf-icfg] "
        f"removed {len(removed_rows)} fully modeled "
        "CallBlockNode->RetBlockNode summary CFG edge(s)",
        file=sys.stderr,
    )

    kept_summary = 0
    for call_node, ret_node in call_to_ret_node.items():
        if (call_node, ret_node) in removable_pairs:
            continue
        if any(
            e.kind == "cfg" and e.src == call_node and e.dst == ret_node
            for e in edges
        ):
            kept_summary += 1

    if kept_summary:
        print(
            "[normalize-svf-icfg] "
            f"kept {kept_summary} CallBlockNode->RetBlockNode summary CFG "
            "edge(s) because at least one target lacked an explicit return "
            "relation",
            file=sys.stderr,
        )

    return filtered, removed_rows



def derive_callsite_pair_rows(
    nodes: Dict[str, Node],
    edges: List[Edge],
    call_to_ret_node: Dict[str, str],
    signature_by_call: Dict[str, str],
) -> List[Tuple]:
    cs_by_call_node: Dict[str, str] = {}
    for e in edges:
        if e.kind == "call" and e.callsite_id:
            cs_by_call_node[e.src] = e.callsite_id

    rows: List[Tuple] = []
    for call_node, ret_node in sorted(
        call_to_ret_node.items(),
        key=lambda item: (cs_by_call_node.get(item[0], ""), item[0], item[1]),
    ):
        caller = nodes.get(call_node, Node(call_node)).function
        rows.append(
            (
                cs_by_call_node.get(call_node, ""),
                call_node,
                ret_node,
                caller,
                signature_by_call.get(call_node, ""),
            )
        )
    return rows

def derive_callsite_rows(
    nodes: Dict[str, Node],
    edges: List[Edge],
    call_to_ret_node: Dict[str, str],
    signature_by_call: Dict[str, str],
    module_calls: Dict[str, List[Dict[str, str]]],
    llvm_metadata: Dict[int, Dict[str, object]],
) -> List[Tuple]:
    """Create the Phase-6-v4 SMLTA/DeepType bridge table.

    ``call_ordinal`` and ``func_indirect_ordinal`` are copied from the exact
    LLVM instruction when a deterministic SVF -> LLVM instruction match can
    be established.  Missing/ambiguous values remain empty rather than being
    guessed.
    """
    cs_by_call_node: Dict[str, str] = {}

    for e in edges:
        if e.kind != "call" or not e.callsite_id:
            continue
        old = cs_by_call_node.get(e.src)
        if old is not None and old != e.callsite_id:
            raise RuntimeError(
                f"callsite node has multiple IDs: {e.src}: {old}, {e.callsite_id}"
            )
        cs_by_call_node[e.src] = e.callsite_id

    def cs_num(cs: str) -> int:
        m = re.match(r"cs(\d+)$", cs or "")
        return int(m.group(1)) if m else 10**18

    def call_node_order(call_node: str) -> Tuple[int, int, str]:
        n = nodes.get(call_node, Node(call_node))
        svf_id = extract_svf_node_id(n.label)
        return (
            svf_id if svf_id is not None else 10**18,
            cs_num(cs_by_call_node.get(call_node, "")),
            call_node,
        )

    consumed_module_calls: Set[Tuple[str, str]] = set()
    rows: List[Tuple] = []

    for call_node in sorted(cs_by_call_node, key=call_node_order):
        callsite_id = cs_by_call_node[call_node]
        node = nodes.get(call_node, Node(call_node))
        caller = node.function
        bb = norm_bb(node.bb) if node.bb else ""
        return_node = call_to_ret_node.get(call_node, "")

        signature = signature_by_call.get(call_node, "")
        svf_ir = normalize_call_ir(signature)

        src_file = ""
        src_line = ""
        src_col = ""

        # Prefer the exact debug metadata printed in the SVF callsite label.
        signature_dbg_ids = DBG_USE_RE.findall(signature)
        if len(signature_dbg_ids) == 1:
            src_file, src_line, src_col = resolve_debug_location(
                llvm_metadata, int(signature_dbg_ids[0])
            )
            src_file = norm_src_file(src_file)

        # Recover the physical LLVM instruction.
        #
        # First try the exact normalized IR. If that fails, use an
        # SSA-number-insensitive form so "%86(...%87)" can match
        # "%91(...%92)" when unnamed LLVM values were renumbered.
        module_call_rows = module_calls.get(caller, [])

        exact_ir_matched: List[Dict[str, str]] = [
            info
            for info in module_call_rows
            if info.get("normalized_ir", "") == svf_ir
        ]

        svf_canonical_ir = canonicalize_call_ir_for_matching(svf_ir)
        canonical_ir_matched: List[Dict[str, str]] = []

        if not exact_ir_matched and svf_canonical_ir:
            canonical_ir_matched = [
                info
                for info in module_call_rows
                if canonicalize_call_ir_for_matching(
                    info.get("normalized_ir", "")
                ) == svf_canonical_ir
            ]

        ir_matched = (
            exact_ir_matched
            if exact_ir_matched
            else canonical_ir_matched
        )

        # Prefer the same basic block when SVF recovered BB metadata.
        # BB is a stronger discriminator than source location because source
        # location is exactly what Phase 6 v3 is trying to canonicalize.
        bb_matched = [
            info
            for info in ir_matched
            if bb
            and info.get("bb", "")
            and norm_bb(info.get("bb", "")) == bb
        ]
        matched = bb_matched if bb_matched else ir_matched

        # SVF's source metadata is only a tie-breaker. Do not make it a hard
        # requirement: the same physical call can be reported at a different
        # source line by the SVF-label path and module.ll/DeepType path.
        if src_line and len(matched) > 1:
            loc_matched = [
                info
                for info in matched
                if norm_src_file(info.get("src_file", "")) == src_file
                and info.get("src_line", "") == src_line
                and info.get("src_col", "") == src_col
            ]
            if loc_matched:
                matched = loc_matched

        call_kind = "unknown"
        direct_callee = ""

        if matched:
            kinds = {info.get("call_kind", "unknown") for info in matched}
            if len(kinds) == 1:
                call_kind = next(iter(kinds))
                if call_kind == "direct":
                    callees = {
                        info.get("direct_callee", "")
                        for info in matched
                        if info.get("direct_callee", "")
                    }
                    if len(callees) == 1:
                        direct_callee = next(iter(callees))

        if call_kind == "unknown" and svf_ir:
            call_kind, direct_callee = classify_call_instruction(svf_ir)

        # Before a deterministic candidate is selected, an LLVM-side
        # location may be used as a fallback when every candidate agrees.
        # If a specific instruction is selected below, v3 prefers that
        # instruction's DebugLoc over the SVF DOT-label location.
        if not src_line and matched:
            locations = {
                (
                    norm_src_file(info.get("src_file", "")),
                    info.get("src_line", ""),
                    info.get("src_col", ""),
                )
                for info in matched
                if info.get("src_line", "")
            }
            if len(locations) == 1:
                src_file, src_line, src_col = next(iter(locations))

        call_ordinal = ""
        func_indirect_ordinal = ""

        if call_kind == "indirect":
            candidates = [
                info
                for info in matched
                if info.get("call_kind", "") == "indirect"
            ]

            if src_line:
                exact_loc = [
                    info
                    for info in candidates
                    if norm_src_file(info.get("src_file", "")) == src_file
                    and info.get("src_line", "") == src_line
                    and info.get("src_col", "") == src_col
                ]
                if exact_loc:
                    candidates = exact_loc

            # Repeated identical IR strings are consumed in deterministic
            # module-call order, reproducing Phase 6's safe one-to-one policy.
            selected: Optional[Dict[str, str]] = None
            for info in candidates:
                module_key = (caller, info.get("call_index", ""))
                if module_key in consumed_module_calls:
                    continue
                selected = info
                break

            if selected is not None:
                module_key = (caller, selected.get("call_index", ""))
                consumed_module_calls.add(module_key)

                call_ordinal = selected.get("call_ordinal", "")
                func_indirect_ordinal = selected.get(
                    "func_indirect_ordinal", ""
                )

                # Phase 6 v4 canonical source-location policy:
                # once a deterministic physical module.ll call instruction is
                # recovered, use that instruction's DebugLoc for src_*.
                # SVF DOT-label DebugLoc remains only a fallback.
                selected_file = norm_src_file(
                    selected.get("src_file", "")
                )
                selected_line = selected.get("src_line", "")
                selected_col = selected.get("src_col", "")

                if selected_line:
                    src_file = selected_file
                    src_line = selected_line
                    src_col = selected_col

        rows.append(
            (
                callsite_id,
                call_node,
                return_node,
                caller,
                bb,
                call_kind,
                direct_callee,
                src_file,
                src_line,
                src_col,
                call_ordinal,
                func_indirect_ordinal,
                svf_ir,
            )
        )

    rows.sort(key=lambda row: (cs_num(str(row[0])), str(row[0])))
    return rows

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

    bb_mapping_rows: List[Tuple] = []
    bb_mapping_stats: Dict[str, int] = {}

    if not used_fallback:
        nodes, bb_mapping_rows, bb_mapping_stats = map_svf_nodes_to_module_bbs(
            nodes, module_ll
        )

        mapped_real = sum(
            count
            for method, count in bb_mapping_stats.items()
            if method not in {"unresolved", "virtual-function-exit"}
        )
        unresolved_real = bb_mapping_stats.get("unresolved", 0)
        print(
            "[normalize-svf-icfg] Phase 6 v4 BB mapping: "
            f"mapped={mapped_real} unresolved={unresolved_real} "
            f"virtual_exit={bb_mapping_stats.get('virtual-function-exit', 0)}",
            file=sys.stderr,
        )

    nodes = enrich_missing_node_info(nodes, edges)

    edges = assign_callsite_ids(nodes, edges)
    call_to_ret_node, signature_by_call = build_callsite_return_node_map(nodes, edges)
    edges = assign_return_callsite_ids(edges, call_to_ret_node)

    func_idx = build_function_index(nodes)
    call_rows, ret_rows, phi_rows = derive_call_return_tables(
        nodes, edges, call_to_ret_node
    )
    cross_product_rows = derive_cross_product_diagnostics(
        nodes, edges, phi_rows
    )
    legacy_cross_product_generated_pairs = sum(row[4] for row in cross_product_rows)
    cross_product_excess_pairs = sum(row[6] for row in cross_product_rows)
    callsite_pair_rows = derive_callsite_pair_rows(
        nodes, edges, call_to_ret_node, signature_by_call
    )

    module_calls, llvm_metadata = parse_module_ll_callsites(module_ll)

    callsite_rows = derive_callsite_rows(
        nodes,
        edges,
        call_to_ret_node,
        signature_by_call,
        module_calls,
        llvm_metadata,
    )

    edges, removed_summary_rows = remove_fully_modeled_call_summary_edges(
        nodes, edges, call_to_ret_node, phi_rows
    )

    cfg_edges = [e for e in edges if e.kind == "cfg"]
    call_edges = [e for e in edges if e.kind == "call"]
    return_edges = [e for e in edges if e.kind == "return"]

    # Diagnostics for the V5 recursive-edge fix.
    recursive_call_edges = [
        e for e in call_edges
        if nodes.get(e.src, Node(e.src)).function
        and nodes.get(e.dst, Node(e.dst)).function
        and nodes.get(e.src, Node(e.src)).function
            == nodes.get(e.dst, Node(e.dst)).function
    ]
    recursive_return_edges = [
        e for e in return_edges
        if nodes.get(e.src, Node(e.src)).function
        and nodes.get(e.dst, Node(e.dst)).function
        and nodes.get(e.src, Node(e.src)).function
            == nodes.get(e.dst, Node(e.dst)).function
    ]

    if not used_fallback:
        write_tsv(
            outdir / "icfg_bb_mapping.tsv",
            [
                "node_id",
                "function",
                "kind",
                "explicit_bb",
                "mapped_bb",
                "method",
                "dbg_ids",
                "src_file",
                "src_line",
                "src_col",
                "svf_ir",
            ],
            bb_mapping_rows,
        )

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
        outdir / "icfg_callsite_pairs.tsv",
        ["callsite_id", "callsite_node", "return_node", "caller_func", "signature"],
        callsite_pair_rows,
    )
    write_tsv(
        outdir / "icfg_callsites.tsv",
        ["callsite_id", "callsite_node", "return_node", "caller_func", "bb", "call_kind", "direct_callee", "src_file", "src_line", "src_col", "call_ordinal", "func_indirect_ordinal", "ir"],
        callsite_rows,
    )
    write_tsv(
        outdir / "icfg_cross_product.tsv",
        ["caller_func", "callee_func", "call_edges", "return_edges", "legacy_generated_pairs", "exact_pairs", "excess_pairs"],
        cross_product_rows,
    )
    write_tsv(
        outdir / "icfg_removed_summary_edges.tsv",
        ["src", "dst", "callsite_id", "caller_func", "reason", "raw_label"],
        removed_summary_rows,
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
    
    direct_callsites = [
        row
        for row in callsite_rows
        if row[5] == "direct"
    ]

    indirect_callsites = [
        row
        for row in callsite_rows
        if row[5] == "indirect"
    ]

    unknown_callsites = [
        row
        for row in callsite_rows
        if row[5] == "unknown"
    ]

    if len(callsite_rows) != (
        len(direct_callsites)
        + len(indirect_callsites)
        + len(unknown_callsites)
    ):
        raise RuntimeError(
            "Phase 6 v4 callsite classification count mismatch"
        )

    source_located_callsites = [
        row for row in callsite_rows if row[7] and row[8]
    ]
    source_unresolved_callsites = [
        row for row in callsite_rows if not row[7] or not row[8]
    ]

    with (outdir / "icfg_summary.txt").open("w", encoding="utf-8") as f:
        f.write("SVF ICFG normalization summary\n")
        f.write("==============================\n")
        f.write(f"mode: {'llvm-ir-fallback' if used_fallback else 'svf-dot'}\n")
        f.write(f"svf_dir: {svf_dir}\n")
        f.write(f"icfg_dot: {icfg_dot or '<none>'}\n")
        f.write(f"module_ll: {module_ll}\n")
        if not used_fallback:
            f.write("bb_identity_policy: module-ll-containing-basic-block; never-arbitrary-numeric-ssa\n")
            for method in (
                "function-entry",
                "explicit-bb",
                "dbg-id",
                "exact-ir",
                "canonical-ir",
                "source-location",
                "virtual-function-exit",
                "unresolved",
            ):
                f.write(
                    f"bb_mapping_{method.replace('-', '_')}: "
                    f"{bb_mapping_stats.get(method, 0)}\n"
                )
        f.write(f"nodes: {len(nodes)}\n")
        f.write(f"edges: {len(edges)}\n")
        f.write(f"cfg_edges: {len(cfg_edges)}\n")
        f.write(f"call_edges: {len(call_edges)}\n")
        f.write(f"paired_callsites: {len(callsite_pair_rows)}\n") # Phase 0: exact CallBlockNode <-> RetBlockNode pairing
        f.write("callsite_pairing: svf-structural-call-to-ret-cfg-edge\n")
        f.write(f"callsites: {len(callsite_rows)}\n") # Phase 6 v4: real-BB mapping + module.ll-canonical source location + diagnostic ordinals
        f.write(f"direct_callsites: {len(direct_callsites)}\n")
        f.write(f"indirect_callsites: {len(indirect_callsites)}\n")
        f.write(f"unknown_callsites: {len(unknown_callsites)}\n")
        f.write(f"source_located_callsites: {len(source_located_callsites)}\n")
        f.write(f"source_unresolved_callsites: {len(source_unresolved_callsites)}\n")
        f.write("source_location_policy: selected-module-ll-call-debugloc-first; svf-dot-debugloc-fallback\n")
        f.write("svf_module_call_matching: exact-normalized-ir-then-numeric-ssa-canonical-ir\n")
        func_ordinal_resolved = sum(
            1 for row in indirect_callsites if len(row) > 11 and row[11] != ""
        )
        func_ordinal_unresolved = len(indirect_callsites) - func_ordinal_resolved
        f.write(f"func_indirect_ordinal_resolved_callsites: {func_ordinal_resolved}\n")
        f.write(f"func_indirect_ordinal_unresolved_callsites: {func_ordinal_unresolved}\n")
        f.write(f"removed_call_ret_summary_edges: {len(removed_summary_rows)}\n")
        f.write(f"return_edges: {len(return_edges)}\n")
        f.write(f"recursive_call_edges: {len(recursive_call_edges)}\n")
        f.write(f"recursive_return_edges: {len(recursive_return_edges)}\n")
        f.write(f"phi_rows: {len(phi_rows)}\n")
        f.write(f"cross_product_groups: {len(cross_product_rows)}\n")
        # Compatibility with the Phase-0 diagnostic names: this is the number
        # the legacy caller/callee grouping would generate, not rows emitted
        # into v5's exact icfg_phi.tsv.
        f.write(
            "cross_product_generated_pairs: "
            f"{legacy_cross_product_generated_pairs}\n"
        )
        f.write("cross_product_pairs_emitted_by_v5: 0\n")
        f.write(
            "legacy_cross_product_generated_pairs: "
            f"{legacy_cross_product_generated_pairs}\n"
        )
        f.write(f"cross_product_excess_pairs: {cross_product_excess_pairs}\n")
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
    print(
        f"[normalize-svf-icfg] nodes={len(nodes)} edges={len(edges)} "
        f"cfg={len(cfg_edges)} call={len(call_edges)} "
        f"callsites={len(callsite_rows)} "
        f"paired_callsites={len(callsite_pair_rows)} "
        f"direct={len(direct_callsites)} "
        f"indirect={len(indirect_callsites)} "
        f"unknown={len(unknown_callsites)} "
        f"ret={len(return_edges)} "
        f"recursive_call={len(recursive_call_edges)} "
        f"recursive_ret={len(recursive_return_edges)} "
        f"phi={len(phi_rows)}",
        file=sys.stderr,
    )
    if not used_fallback:
        print(
            "[normalize-svf-icfg] BB mapping methods: "
            + ", ".join(
                f"{k}={bb_mapping_stats[k]}"
                for k in sorted(bb_mapping_stats)
            ),
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
