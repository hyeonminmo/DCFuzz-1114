import json
import logging
import os
import re
from typing import Dict, Optional

import filelock

from . import config as Config


# crash mode and empty_seed 는 필요 없음.

# coverage 도 필요가 없을 것 같은데


config = Config.CONFIG

logger = logging.getLogger('dcfuzz.coverage')

EVALUTOR_THREAD = None

def gen_evaluator_args(target,
                       fuzzers,
                       output_dir,
                       timeout,
                       input_dir=None,
                       input_only=False):

    target_config = config['target'][target]
    
    evaluator_config: Dict[str, str] = config['evaluator']

    assert target_config

    group: str = target_config['group']
    target_default_args: str = target_config['args']['default']
    target_args = target_config['args'].get('evaluator', target_default_args)

    assert target_args is not None

    seed = None

    if input_dir:
        seed = input_dir
    else:
        seed = target_config['seed']

    assert seed

    binary = os.path.join(evaluator_config['binary_root'], group, target,
                          target)
    binary_crash = os.path.join(evaluator_config['binary_crash_root'], group,
                                target, target)

    assert os.path.exists(seed)
    assert os.path.exists(binary)
    assert os.path.exists(binary_crash)

    evaluator_args = [
        '-o', output_dir, '-t', target, '-f', *fuzzers, '-q', 'queue', '-c',
        'crashes', '-T', timeout, '--input', seed, '--binary', binary,
        '--binary_crash', binary_crash, f'--args={target_args}', '--mode',
        crash_mode, '--live', '--sleep', 10
    ]
    if input_only:
        evaluator_args.append('--input-only')

    return list(map(str, evaluator_args))


def run_evaluator(target, fuzzers, output_dir, timeout, input_dir, input_only):

    evaluator_args = gen_evaluator_args(target, fuzzers, output_dir, timeout,
                                        input_dir, input_only)

    thread_evaluator = evaluator.main(evaluator_args)
    return thread_evaluator


def thread_run_evaluator(target, fuzzers, output_dir, timeout, input_dir, input_only):
    global EVALUTOR_THREAD
    if EVALUTOR_THREAD: return
    thread_evaluator = run_evaluator(target, fuzzers, output_dir, timeout,
                                     input_dir, input_only)

    EVALUTOR_THREAD = thread_evaluator


def thread_run_fuzzer(target,
                      fuzzer,
                      fuzzers,
                      output_dir,
                      fuzzer_timeout='24h',
                      timeout='10s',
                      input_dir=None,
                      input_only=False) -> Optional[Dict]:

    thread_run_evaluator(target, fuzzers, output_dir, timeout, input_dir, input_only)

    bitmap = get_bitmap_fuzzer(target, fuzzer, output_dir)

    unique_bugs = get_unique_bugs_fuzzer(target, fuzzer, output_dir)
    
    if bitmap:
        bitmap_count = bitmap.count()
        logger.debug(
            f'{target}, {fuzzer}, bitmap: {bitmap_count}, bugs: {unique_bugs}')
        return {
            # FIXME
            'coverage': {
                "line": 0,
                "line_coverage": 0
            },
            'bitmap': bitmap,
            'unique_bugs': unique_bugs
        }

    else:
        if not bitmap:
            logger.critical(f'{fuzzer} bitmap is None')
        return None


