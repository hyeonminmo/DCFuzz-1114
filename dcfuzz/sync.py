import glob
import hashlib
import logging
import os
import pathlib
import re
import sqlite3
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

from . import config as Config
from . import watcher
from .common import nested_dict



config = Config.CONFIG

logger = logging.getLogger('dcfuzz.sync')

index = nested_dict()

hashmap: Dict[str, str] = dict()
time_for_hash: float = 0


SYNC_PAIR: Dict[str, Dict[str, Dict[watcher.Watcher, int]]] = {}

SYNC_PROVENANCE = {}

SEED_TABLE_BY_FUZZER = {
    "aflgo": "aflgoseed",
    "windranger": "windrangerseed",
    "dafl": "daflseed",
}

SYNC_TOP_K = config.get("scheduler", {}).get("sync_top_k", 10)

LAST_INDEX: Dict[watcher.Watcher, int] = {}

global_processed_checksum = set()

processed_checksum = nested_dict()

def checksum(filename: str) -> str:
    BUF_SIZE = 65536
    if filename in hashmap:
        return hashmap[filename]
    t = time.time()
    md5 = hashlib.md5()
    with open(filename, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
    global time_for_hash
    time_for_hash += time.time() - t
    ret = md5.hexdigest()
    hashmap[filename] = ret
    return ret

class TestCase(object):
    def __init__(self, filename: Path, src_fuzzer:str=None):
        self.filename = filename
        self.__checksum = None
        self.src_fuzzer =src_fuzzer

    @property
    def checksum(self):
        if not self.__checksum:
            self.__checksum = checksum(str(self.filename))
        return self.__checksum

def seed_id_num(name: str) -> int:
    """
    id:000123 또는 dafl_id:000123 같은 이름에서 숫자 123 추출.
    tie-break에서 id가 높은 seed를 우선 선택하기 위함.
    """
    m = re.search(r"id:(\d+)", name)
    if not m:
        return -1
    return int(m.group(1))

def safe_int(v, default=-1):
    return int(v) if v is not None else default

def load_seed_scores_from_db(
        target: str,
        host_root_dir: Path,
        src_fuzzer: str,
        seed_ids: List[str],
    ) -> Dict[str, Dict[str, int]]:
    """
    evaluator가 저장한 score DB에서 seed별 prox_score / dom_covered를 읽는다.

    DB path:
      {host_root_dir}/{target}/score/{src_fuzzer}.sqlite
    """
    seed_ids = sorted(set(seed_ids))
    if not seed_ids:
        return {}

    db_path = host_root_dir / target / "score" / f"{src_fuzzer}.sqlite"
    if not db_path.exists():
        logger.info(
            f"sync 700 - score DB not found: src_fuzzer={src_fuzzer}, db={db_path}"
        )
        return {}

    table = SEED_TABLE_BY_FUZZER.get(src_fuzzer)
    if table is None:
        logger.info(f"sync 701 - unknown fuzzer table: {src_fuzzer}")
        return {}
    
    placeholders = ",".join("?" for _ in seed_ids)
    query = (
        f"SELECT name, prox_score, dom_covered "
        f"FROM {table} "
        f"WHERE name IN ({placeholders})"
    )

    ret = {}

    try:
        with sqlite3.connect(str(db_path)) as conn:
            cur = conn.cursor()
            for name, prox_score, dom_covered in cur.execute(query, seed_ids):
                ret[name] = {
                    "prox_score": safe_int(prox_score),
                    "dom_covered": safe_int(dom_covered),
                }
    except sqlite3.Error as e:
        logger.info(
            f"sync 702 - failed to read score DB: "
            f"src_fuzzer={src_fuzzer}, db={db_path}, error={e}"
        )
        return {}

    return ret

def select_top_sync_test_cases(
        target: str,
        host_root_dir: Path,
        test_cases: List[TestCase],
        limit: int = SYNC_TOP_K
    ) -> List[TestCase]:
    grouped = defaultdict(list)

    for tc in test_cases:
        grouped[tc.src_fuzzer].append(tc)

    selected_by_checksum = {}

    for src_fuzzer, cases in grouped.items():
        seed_ids = []

        for tc in cases:
            try:
                seed_ids.append(normalize_afl_seed_id(tc.filename.name))
            except ValueError:
                logger.info(f"sync 703 - skip invalid seed name: {tc.filename.name}")
        
        score_map = load_seed_scores_from_db(
            target=target,
            host_root_dir=host_root_dir,
            src_fuzzer=src_fuzzer,
            seed_ids=seed_ids,
        )

        scored = []
        for tc in cases:
            try:
                seed_id = normalize_afl_seed_id(tc.filename.name)
            except ValueError:
                continue

            score = score_map.get(seed_id)
            if score is None:
                logger.info(
                    f"sync 704 - skip seed without score: "
                    f"src_fuzzer={src_fuzzer}, seed={seed_id}"
                )
                continue

            scored.append({
                "test_case": tc,
                "seed_id": seed_id,
                "seed_num": seed_id_num(seed_id),
                "prox_score": safe_int(score.get("prox_score")),
                "dom_covered": safe_int(score.get("dom_covered")),
            })

        top_dom = sorted(
            scored,
            key=lambda x: (x["dom_covered"], x["seed_num"]),
            reverse=True,
        )[:limit]

        top_dafl = sorted(
            scored,
            key=lambda x: (x["prox_score"], x["seed_num"]),
            reverse=True,
        )[:limit]

        for row in top_dom + top_dafl:
            tc = row["test_case"]
            selected_by_checksum[tc.checksum] = tc

        logger.info(
            f"sync 705 - selected top seeds: "
            f"src_fuzzer={src_fuzzer}, "
            f"new={len(cases)}, scored={len(scored)}, "
            f"top_dom={len(top_dom)}, top_dafl={len(top_dafl)}, "
            f"selected_union={len({r['test_case'].checksum for r in top_dom + top_dafl})}"
        )

        logger.info(
            "sync 706 - top dom seeds: "
            + ", ".join(
                f"{r['seed_id']}:dom={r['dom_covered']},score={r['prox_score']}"
                for r in top_dom
            )
        )

        logger.info(
            "sync 707 - top dafl seeds: "
            + ", ".join(
                f"{r['seed_id']}:score={r['prox_score']},dom={r['dom_covered']}"
                for r in top_dafl
            )
        )

    return list(selected_by_checksum.values())

# 해당 함수에서 경로 설정이 이루어짐.
def init_dir(dcfuzz_dir: Path) -> None:
    '''
    create afl-compatible directory structure
    '''
    os.makedirs(dcfuzz_dir, exist_ok=True)
    crash_dir = os.path.join(dcfuzz_dir, 'crashes')
    hang_dir = os.path.join(dcfuzz_dir, 'hangs')
    queue_dir = os.path.join(dcfuzz_dir, 'queue')
    for d in [crash_dir, hang_dir, queue_dir]:
        os.makedirs(d, exist_ok=True)

def init(target: str, fuzzers: List[str], host_root_dir: Path) -> None:
    # logging.info(f'sync 002 - start init XXX')
    for fuzzer in fuzzers:
        if fuzzer not in processed_checksum:
            processed_checksum[fuzzer] = set()
        fuzzer_root_dir = host_root_dir / target / fuzzer
        dcfuzz_dir = fuzzer_root_dir / 'dcfuzz'
        init_dir(dcfuzz_dir)

def new_afl_filename(fuzzer, dcfuzzer):
    global index
    new_index = None
    if fuzzer not in index:
        index[fuzzer] = 0
    new_index = index[fuzzer]
    index[fuzzer] += 1
    return f'{dcfuzzer}_id:{new_index:06d}'

def normalize_afl_seed_id(name: str) -> str:
    import re
    base = os.path.basename(name)
    m = re.search(r"((?:[a-zA-Z0-9]+_)?id:\d+)", base)
    if not m:
        raise ValueError(f"Invalid AFL seed name: {name}")
    return m.group(1)

# 이전 sync_test_case 함수로 각 퍼저 내에 dcfuzz 폴더를 생성하고 새로운 test case 를 추가함.
def sync_test_case(target, fuzzer, host_root_dir, testcase):
    fuzzer_config = config['fuzzer'][fuzzer]
    fuzzer_root_dir = os.path.join(host_root_dir, target, fuzzer)
    dcfuzz_dir = os.path.join(fuzzer_root_dir, 'dcfuzz')
    queue_dir = os.path.join(dcfuzz_dir, 'queue')
    new_name = new_afl_filename(fuzzer, testcase.src_fuzzer)
    new_filename = os.path.join(queue_dir, new_name)

    rel_path = os.path.relpath(testcase.filename,
                               os.path.dirname(new_filename))
    logger.info(f"sync 666 - [sync] copy {fuzzer} <- {testcase.src_fuzzer} : {new_name} <- {str(testcase.filename)}")

    os.symlink(rel_path, new_filename)

    # provenance 기록
    src_seed_id = normalize_afl_seed_id(testcase.filename.name)
    SYNC_PROVENANCE[testcase.checksum] = {
        "src_fuzzer": testcase.src_fuzzer,
        "src_seed_id": src_seed_id,
        "dst_fuzzer": fuzzer,
        "sync_name": new_name,
    }

    logger.info(
        f"sync 667 - provenance checksum={testcase.checksum}, "
        f"src={testcase.src_fuzzer}:{src_seed_id}, "
        f"dst={fuzzer}:{new_name}"
    )

    

def sync2(target: str, fuzzers: List[str], host_root_dir: Path):
    global LAST_INDEX
    global WATCHERS
    # init observer
    # scan all before observer init or make sure observer init first

    logging.info(f'sync 001 - start sync')

    init(target, fuzzers, host_root_dir)
    target_config = config['target'][target]

    # logging.info(f'sync 004 - target_config : {target_config} XXX')

    global_new_test_cases = []
    new_test_cases = nested_dict()

    # handle seeds
    # 1. update global queue
    for fuzzer in fuzzers:
        fuzzer_config = config['fuzzer'][fuzzer]
        fuzzer_root_dir = host_root_dir / target / fuzzer
        new_test_cases[fuzzer] = []
        
        # NOTE: scan subdir is not as expensive as scan testcases
        # can be optmized when we make sure all the things are setup frist (not scale up)
        watcher.init_watcher(fuzzer, fuzzer_root_dir)

        # not ready
        if fuzzer not in watcher.WATCHERS:
            return

        watchers = watcher.WATCHERS[fuzzer]

        # NOTE: will also synced crashes, which sometimes will also have more coverage
        # read queued testcases
        for w in watchers:
            # prevent iterating while changing
            last_index = LAST_INDEX.get(w, -1)
            queue_len = len(w.test_case_queue)
            for i in range(last_index + 1, queue_len):
                test_case_path = w.test_case_queue[i]
                if w._ignore_test_case(test_case_path):
                    continue
                test_case = TestCase(test_case_path, src_fuzzer=fuzzer)
                processed_checksum[fuzzer].add(test_case.checksum)
                if test_case.checksum not in global_processed_checksum:
                    global_new_test_cases.append(test_case)
                    global_processed_checksum.add(test_case.checksum)
            LAST_INDEX[w] = queue_len
    
    # logging.info(f'sync 006 - update global queue XXX')
    
    # 1.5. select only top-k seeds per src fuzzer
    selected_test_cases = select_top_sync_test_cases(
        target=target,
        host_root_dir=host_root_dir,
        test_cases=global_new_test_cases,
        limit=SYNC_TOP_K
    )

    logger.info(
        f"sync 708 - global new seeds={len(global_new_test_cases)}, "
        f"selected for sync={len(selected_test_cases)}"
    )

    sync_count_by_dst = defaultdict(int)

    # 2. sync to each fuzzer
    for fuzzer in fuzzers:
        # handle new test cases only
        for test_case in selected_test_cases:
            if test_case.checksum not in processed_checksum[fuzzer]:
                processed_checksum[fuzzer].add(test_case.checksum)
                # do sync!
                sync_test_case(target, fuzzer, host_root_dir, test_case)
                sync_count_by_dst[fuzzer] += 1

    # logging.info(f'sync 007 - sync each fuzzer XXX')
    logger.info(
        "sync 709 - actual synced by dst: "
        + ", ".join(f"{f}={c}" for f, c in sync_count_by_dst.items())
    )

    del global_new_test_cases
    del new_test_cases
    # wait some file system writing, doesn't affect our symbolic link but for fuzzers
    time.sleep(0.1)
    # logging.info(f'sync 008 - sync end XXX')
