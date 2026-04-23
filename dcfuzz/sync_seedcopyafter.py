#!/usr/bin/env python3

import glob
import hashlib
import logging
import os
import pathlib
import time

import re
import shutil

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

LAST_INDEX: Dict[watcher.Watcher, int] = {}

global_processed_checksum = set()

processed_checksum = nested_dict()

_id_re = re.compile(r"^(?:[A-Za-z0-9]+_)?id:(\d{6})")

def next_id_in_dir(queue_dir: str, fuzzer) -> str:
    max_id = -1
    try:
        for name in os.listdir(queue_dir):
            m = _id_re.match(name)
            if not m:
                continue
            n = int(m.group(1))
            if n > max_id:
                max_id = n
    except FileNotFoundError:
        os.makedirs(queue_dir, exist_ok=True)
    return f"{fuzzer}_id:{max_id+1:06d}"


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
    logging.info(f'sync 003 - crash_dir : {crash_dir}, hang_dir :{hang_dir}, queue_dir:{queue_dir} XXX')

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

def sync_test_case(target, fuzzer, host_root_dir, testcase):
    fuzzer_root_dir = os.path.join(host_root_dir, target, fuzzer)

    # (A) dcfuzz/queue 
    dcfuzz_dir = os.path.join(fuzzer_root_dir, 'dcfuzz')
    dcfuzz_queue_dir = os.path.join(dcfuzz_dir, 'queue')
    os.makedirs(dcfuzz_queue_dir, exist_ok=True)

    new_name = new_afl_filename(fuzzer, testcase.src_fuzzer)
    new_filename = os.path.join(dcfuzz_queue_dir, new_name)

    rel_path = os.path.relpath(testcase.filename, os.path.dirname(new_filename))

    os.symlink(rel_path, new_filename)

    real_queue_dir = os.path.join(fuzzer_root_dir, 'queue')

    real_name = next_id_in_dir(real_queue_dir, testcase.src_fuzzer)
    real_dst = os.path.join(real_queue_dir, real_name)

    # testcase.filename 이 symlink일 수도 있으니 realpath로 실제 파일 복사
    src = os.path.realpath(str(testcase.filename))

    try:
        shutil.copy2(src, real_dst)
        logger.info(f"sync 66666_2 - [sync] copy {fuzzer} <- {testcase.src_fuzzer} : {real_name} <- {str(testcase.filename)}")
    except Exception as e:
        logger.info(f"sync 66666_3 -  failed: {fuzzer} dst={real_dst} src={src} err={e}")
        

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

    # 2. sync to each fuzzer
    for fuzzer in fuzzers:
        # handle new test cases only
        for test_case in global_new_test_cases:
            if test_case.checksum not in processed_checksum[fuzzer]:
                processed_checksum[fuzzer].add(test_case.checksum)
                # do sync!
                sync_test_case(target, fuzzer, host_root_dir, test_case)

    # logging.info(f'sync 007 - sync each fuzzer XXX')

    del global_new_test_cases
    del new_test_cases
    # wait some file system writing, doesn't affect our symbolic link but for fuzzers
    time.sleep(0.1)
    # logging.info(f'sync 008 - sync end XXX')
