#!/usr/bin/env python3
import argparse
import re
import sys
from collections import defaultdict, deque

DEFINE_RE = re.compile(
    r'^\s*define\b.*@("?[-A-Za-z$._0-9]+"?)\s*\(.*\).*?!dbg\s+!(\d+)\s*\{'
)
MD_RE = re.compile(
    r'^\s*!(\d+)\s*=\s*(?:distinct\s+)?!([A-Za-z0-9_]+)\((.*)\)\s*$'
)
KV_RE = re.compile(
    r'([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([^,][^,]*?(?=(?:,\s+[A-Za-z_][A-Za-z0-9_]*\s*:)|$))'
)
BB_NAMED_RE = re.compile(r'^\s*([A-Za-z$._-][A-Za-z$._0-9-]*|\d+):(?:\s*;.*)?$')
BB_OLD_RE = re.compile(r'^\s*;\s*<label>:(\d+):')
DBG_USE_RE = re.compile(r'!dbg\s+!(\d+)')
FUNC_DOM_RE = re.compile(
    r"Printing analysis 'Dominator Tree Construction' for function '([^']+)':"
)
DOM_NODE_RE = re.compile(r'^(?P<indent>\s*)\[\d+\]\s+(?P<bb>%[-A-Za-z$._0-9]+)\s+\{')

CALL_INST_RE = re.compile(r'call\b.*@("?[-A-Za-z$._0-9]+"?)\s*\(')
INVOKE_INST_RE = re.compile(r'invoke\b.*@("?[-A-Za-z$._0-9]+"?)\s*\(')


def md_ref_to_int(v: str):
    if not v:
        return None
    m = re.match(r'!(\d+)$', v.strip())
    return int(m.group(1)) if m else None


def normalize_bb(bb: str) -> str:
    bb = bb.strip()
    if bb.startswith("%"):
        bb = bb[1:]
    return bb


def parse_metadata(lines):
    nodes = {}
    for line in lines:
        m = MD_RE.match(line)
        if not m:
            continue
        nid = int(m.group(1))
        tag = m.group(2)
        body = m.group(3)
        attrs = {}
        for km in KV_RE.finditer(body):
            attrs[km.group(1)] = km.group(2).strip()
        nodes[nid] = {
            "tag": tag,
            "attrs": attrs,
            "raw": body,
        }
    return nodes


def get_target_function_dbg(lines, target_function):
    for line in lines:
        m = DEFINE_RE.match(line)
        if not m:
            continue
        fn = m.group(1).strip('"')
        dbg_id = int(m.group(2))
        if fn == target_function:
            return dbg_id
    return None


def scope_reaches_function(nodes, scope_id, func_dbg_id):
    visited = set()
    cur = scope_id
    while cur is not None and cur not in visited:
        visited.add(cur)
        if cur == func_dbg_id:
            return True
        node = nodes.get(cur)
        if not node:
            return False

        attrs = node["attrs"]

        nxt = md_ref_to_int(attrs.get("scope", ""))
        if nxt is not None:
            cur = nxt
            continue

        return False
    return False


def dbg_line_from_id(nodes, dbg_id):
    node = nodes.get(dbg_id)
    if not node or node["tag"] != "DILocation":
        return None

    line_v = node["attrs"].get("line")
    try:
        return int(line_v) if line_v is not None else None
    except ValueError:
        return None


def collect_all_bb_representative_lines(lines, nodes):
    """
    Return:
      rep[function][bb] = minimum source line seen in that BB
    """
    rep = defaultdict(dict)

    current_func = None
    current_bb = None

    for line in lines:
        m = DEFINE_RE.match(line)
        if m:
            current_func = m.group(1).strip('"')
            current_bb = "entry"
            continue

        if current_func is not None and re.match(r'^\s*\}\s*$', line):
            current_func = None
            current_bb = None
            continue

        if current_func is None:
            continue

        bm = BB_NAMED_RE.match(line)
        if bm:
            current_bb = normalize_bb(bm.group(1))
            continue

        om = BB_OLD_RE.match(line)
        if om:
            current_bb = normalize_bb(om.group(1))
            continue

        if current_bb is None:
            continue

        dbg_uses = [int(x) for x in DBG_USE_RE.findall(line)]
        src_lines = []
        for dbg_id in dbg_uses:
            node = nodes.get(dbg_id)
            if not node or node["tag"] != "DILocation":
                continue
            line_v = node["attrs"].get("line")
            try:
                src_line = int(line_v) if line_v is not None else None
            except ValueError:
                src_line = None
            if src_line is not None:
                src_lines.append(src_line)

        if src_lines:
            cand = min(src_lines)
            old = rep[current_func].get(current_bb)
            if old is None or cand < old:
                rep[current_func][current_bb] = cand

    return rep


def collect_target_dbg_ids(nodes, target_line, func_dbg_id):
    """
    Collect !DILocation IDs such that:
      - line == target_line
      - its scope chain reaches func_dbg_id
    """
    dbg_ids = set()

    for nid, node in nodes.items():
        if node["tag"] != "DILocation":
            continue
        attrs = node["attrs"]
        line_v = attrs.get("line")
        try:
            line_num = int(line_v) if line_v is not None else None
        except ValueError:
            continue
        if line_num != target_line:
            continue

        scope_id = md_ref_to_int(attrs.get("scope", ""))
        if scope_reaches_function(nodes, scope_id, func_dbg_id):
            dbg_ids.add(nid)

    return dbg_ids


def collect_instruction_matches(lines, wanted_dbg_ids, target_function, nodes):
    """
    Return instruction matches with BB info inside target_function only.
    """
    matches = []

    in_func = False
    current_func = None
    current_bb = None

    for idx, line in enumerate(lines, start=1):
        m = DEFINE_RE.match(line)
        if m:
            current_func = m.group(1).strip('"')
            in_func = (current_func == target_function)
            current_bb = "entry"
            continue

        if in_func and re.match(r'^\s*\}\s*$', line):
            in_func = False
            current_func = None
            current_bb = None
            continue

        if not in_func:
            continue

        bm = BB_NAMED_RE.match(line)
        if bm:
            current_bb = normalize_bb(bm.group(1))
            continue

        om = BB_OLD_RE.match(line)
        if om:
            current_bb = normalize_bb(om.group(1))
            continue

        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue

        dbg_uses = [int(x) for x in DBG_USE_RE.findall(line)]
        hit = sorted(set(dbg_uses) & wanted_dbg_ids)
        if hit:
            src_lines = sorted(
                x for x in (dbg_line_from_id(nodes, dbg_id) for dbg_id in hit)
                if x is not None
            )

            matches.append({
                "function": current_func,
                "bb": current_bb or "entry",
                "ll_line": idx,
                "dbg_hits": hit,
                "src_lines": src_lines,
                "src_line": src_lines[0] if src_lines else None,
                "ir": line.rstrip("\n"),
            })

    return matches


def parse_domtree(domtree_path):
    parent_map = defaultdict(dict)
    current_func = None
    stack = []

    with open(domtree_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            fm = FUNC_DOM_RE.search(line)
            if fm:
                current_func = fm.group(1)
                stack = []
                continue

            if current_func is None:
                continue

            nm = DOM_NODE_RE.match(line)
            if not nm:
                continue

            indent = len(nm.group("indent"))
            bb = normalize_bb(nm.group("bb"))

            while stack and stack[-1][0] >= indent:
                stack.pop()

            parent = stack[-1][1] if stack else None
            parent_map[current_func][bb] = parent
            stack.append((indent, bb))

    return parent_map


def dominator_chain(parent_map_for_func, bb):
    chain = []
    cur = normalize_bb(bb)
    seen = set()

    while cur is not None and cur not in seen:
        seen.add(cur)
        chain.append(cur)
        cur = parent_map_for_func.get(cur)

    return list(reversed(chain))


def get_entry_bb_name(parent_map_for_func):
    roots = [bb for bb, parent in parent_map_for_func.items() if parent is None]
    if not roots:
        return None
    if len(roots) == 1:
        return roots[0]
    if "entry" in roots:
        return "entry"
    return roots[0]


def collect_callsites(lines):
    """
    Return:
      callsites[caller_func] = [
          {
              "callee": callee_name,
              "bb": bb_name,
              "ll_line": idx,
              "ir": stripped_ir
          },
          ...
      ]
    """
    callsites = defaultdict(list)

    current_func = None
    current_bb = None

    for idx, line in enumerate(lines, start=1):
        m = DEFINE_RE.match(line)
        if m:
            current_func = m.group(1).strip('"')
            current_bb = "entry"
            continue

        if current_func is not None and re.match(r'^\s*\}\s*$', line):
            current_func = None
            current_bb = None
            continue

        if current_func is None:
            continue

        bm = BB_NAMED_RE.match(line)
        if bm:
            current_bb = normalize_bb(bm.group(1))
            continue

        om = BB_OLD_RE.match(line)
        if om:
            current_bb = normalize_bb(om.group(1))
            continue

        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue

        cm = CALL_INST_RE.search(stripped)
        if not cm:
            cm = INVOKE_INST_RE.search(stripped)
        if not cm:
            continue

        callee = cm.group(1).strip('"')
        callsites[current_func].append({
            "callee": callee,
            "bb": current_bb or "entry",
            "ll_line": idx,
            "ir": stripped,
        })

    return callsites


def build_reverse_callgraph(callsites):
    """
    reverse_cg[callee] = [caller1, caller2, ...]
    """
    reverse_cg = defaultdict(set)
    for caller, items in callsites.items():
        for item in items:
            callee = item["callee"]
            reverse_cg[callee].add(caller)

    return {k: sorted(v) for k, v in reverse_cg.items()}


def find_call_chain_to_target(reverse_cg, target_func, preferred_roots=None):
    """
    Find one caller chain from a preferred root (e.g. main) to target_func.
    If no preferred root is found, still return the longest discovered caller chain.
    Returns list of functions: [root_or_topmost, ..., target_func]
    """
    if preferred_roots is None:
        preferred_roots = ["main"]

    q = deque([target_func])
    prev = {target_func: None}
    depth = {target_func: 0}

    found_root = None
    farthest = target_func

    while q:
        cur = q.popleft()

        if cur in preferred_roots:
            found_root = cur
            break

        for caller in reverse_cg.get(cur, []):
            if caller not in prev:
                prev[caller] = cur
                depth[caller] = depth[cur] + 1
                q.append(caller)

                if depth[caller] > depth[farthest]:
                    farthest = caller

    def rebuild_chain(start):
        chain = [start]
        cur = start
        while cur != target_func:
            cur = prev[cur]
            chain.append(cur)
        return chain

    if found_root is not None:
        return rebuild_chain(found_root)

    if farthest != target_func:
        return rebuild_chain(farthest)

    return [target_func]


def choose_callsite_for_edge(callsites, caller_func, callee_func, parent_map):
    """
    Choose one callsite BB in caller_func that calls callee_func.
    Prefer the deepest BB in caller's dominator tree.
    """
    cand = [x for x in callsites.get(caller_func, []) if x["callee"] == callee_func]
    if not cand:
        return None

    func_parent = parent_map.get(caller_func, {})

    def depth(bb):
        d = 0
        cur = bb
        seen = set()
        while cur is not None and cur not in seen:
            seen.add(cur)
            cur = func_parent.get(cur)
            d += 1
        return d

    cand.sort(key=lambda x: (depth(x["bb"]), x["ll_line"]), reverse=True)
    return cand[0]


def stitch_program_dominators(func_chain, callsites, parent_map, strict=False):
    """
    Build whole-program dominator path as list of (func, bb).
    Example:
      main:entry -> ... -> caller:callsite_bb -> callee:entry -> ... -> target_func:target_bb
    """
    result = []
    seen = set()

    for i in range(len(func_chain) - 1):
        caller = func_chain[i]
        callee = func_chain[i + 1]

        cs = choose_callsite_for_edge(callsites, caller, callee, parent_map)
        if cs is None:
            continue

        caller_parent = parent_map.get(caller, {})
        caller_chain = dominator_chain(caller_parent, cs["bb"])
        if strict and caller_chain:
            caller_chain = caller_chain[:-1]

        for bb in caller_chain:
            key = (caller, bb)
            if key not in seen:
                seen.add(key)
                result.append(key)

        key = (caller, cs["bb"])
        if key not in seen:
            seen.add(key)
            result.append(key)

        callee_parent = parent_map.get(callee, {})
        callee_entry = get_entry_bb_name(callee_parent)
        if callee_entry is not None:
            key = (callee, callee_entry)
            if key not in seen:
                seen.add(key)
                result.append(key)

    return result


def build_target_local_chain(target_func, target_bbs, parent_map, strict=False):
    """
    target_bbs: list of BBs containing target instruction(s)
    Return common dominators inside target function as ordered list of (func, bb)
    """
    func_parent = parent_map.get(target_func)
    if not func_parent:
        return []

    dom_sets = []
    ordered_base = None

    for bb in target_bbs:
        chain = dominator_chain(func_parent, bb)
        if not chain:
            continue
        if strict:
            chain = chain[:-1]
        if ordered_base is None:
            ordered_base = chain
        dom_sets.append(chain)

    if not dom_sets or ordered_base is None:
        return []

    common = set(dom_sets[0])
    for ds in dom_sets[1:]:
        common &= set(ds)

    return [(target_func, bb) for bb in ordered_base if bb in common]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("module_ll")
    ap.add_argument("domtree_txt")
    ap.add_argument("target", help="e.g. decompile.c:1699")
    ap.add_argument("--function", required=True, help="e.g. decompileSETMEMBER")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()

    if ":" not in args.target:
        print("ERROR: target must be file:line", file=sys.stderr)
        sys.exit(2)

    _, line_s = args.target.rsplit(":", 1)
    try:
        target_line = int(line_s)
    except ValueError:
        print("ERROR: line must be integer", file=sys.stderr)
        sys.exit(2)
    
    with open(args.module_ll, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    nodes = parse_metadata(lines)

    # find debug locations that correspond to the target line in the target function.
    func_dbg_id = get_target_function_dbg(lines, args.function)
    if func_dbg_id is None:
        print(f"target: {args.target}")
        print(f"target_function: {args.function}")
        print("status: target function not found in module.ll")
        sys.exit(1)

    wanted_dbg_ids = collect_target_dbg_ids(nodes, target_line, func_dbg_id)

    print(f"target: {args.target}")
    print(f"target_function: {args.function}")
    print(f"function_dbg_id: !{func_dbg_id}")
    print()

    if not wanted_dbg_ids:
        print("status: no DILocation(line=target_line) whose scope reaches target function")
        sys.exit(1)

    print("matched_dilocations:")
    for x in sorted(wanted_dbg_ids):
        print(f"  - !{x}")
    print()

    # Find instructions and basic blocks that contain the target.
    instr_matches = collect_instruction_matches(lines, wanted_dbg_ids, args.function, nodes)
    if not instr_matches:
        print("status: matching DILocation exists, but no instruction uses !dbg !<id> in target function")
        sys.exit(1)

    print("matched_instructions:")
    for m in instr_matches:
        dbg_str = ", ".join(f"!{x}" for x in m["dbg_hits"])
        print(
            f"  - function={m['function']} bb={m['bb']} "
            f"ll_line={m['ll_line']} src_line={m['src_line']} dbg={dbg_str}"
        )
        print(f"    ir: {m['ir']}")
    print()

    all_bb_rep_lines = collect_all_bb_representative_lines(lines, nodes)

    # Parse per-function dominator trees.
    parent_map = parse_domtree(args.domtree_txt)

    if args.function not in parent_map:
        print("status: target function not found in domtree.txt")
        sys.exit(1)

    bb_set = []
    seen_bbs = set()
    for m in instr_matches:
        bb = normalize_bb(m["bb"])
        if bb not in seen_bbs:
            seen_bbs.add(bb)
            bb_set.append(bb)

    callsites = collect_callsites(lines)
    reverse_cg = build_reverse_callgraph(callsites)
    func_chain = find_call_chain_to_target(reverse_cg, args.function, preferred_roots=["main"])

    print("program_call_chain:")
    for fn in func_chain:
        print(f"  - {fn}")
    print()

    program_prefix = stitch_program_dominators(
        func_chain,
        callsites,
        parent_map,
        strict=args.strict,
    )

    local_common = build_target_local_chain(
        args.function,
        bb_set,
        parent_map,
        strict=args.strict,
    )

    print("dominator_chains:")
    for bb in bb_set:
        chain = dominator_chain(parent_map[args.function], bb)
        if not chain:
            print(f"  - bb={bb}: <not found in domtree>")
            continue
        if args.strict:
            chain = chain[:-1]
        print(f"  - bb={bb}")
        for d in chain:
            print(f"      {args.function}:{d}")
    print()

    print("bb_rep_lines:")
    for func_name in sorted(all_bb_rep_lines):
        for bb, ln in sorted(all_bb_rep_lines[func_name].items(), key=lambda x: x[0]):
            print(f"  {func_name}:{bb} -> {ln}")
    print()

    merged = []
    seen_pairs = set()

    for pair in program_prefix + local_common:
        if pair not in seen_pairs:
            seen_pairs.add(pair)
            merged.append(pair)

    print("program_dominators:")
    if not merged:
        print("  <none>")
    else:
        for func_name, bb in merged:
            rep_line = all_bb_rep_lines.get(func_name, {}).get(bb)
            if rep_line is None:
                print(f"  - {func_name}:bb={bb}  # line=?")
            else:
                print(f"  - {func_name}:bb={bb}  # line={rep_line}")


if __name__ == "__main__":
    main()