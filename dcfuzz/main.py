import os
import sys
import logging
import pathlib
import subprocess
import threading
import time
import signal
import atexit
import datetime

import math
import random
import traceback

from pathlib import Path
from typing import Dict, List, Optional


from . import cli
from . import config as Config
from . import fuzzer_driver # , sync, fuzzing
from .common import nested_dict

# set log file

logger = logging.getLogger('DCFuzz.main')
logging.basicConfig(level=logging.INFO, filename='logDCFuzz.log',filemode='w', format='%(asctime)s - %(filename)s - %(funcName)s - %(lineno)s - %(message)s')

LOG = nested_dict()

# Global variable
START_TIME: float = 0.0
config: Dict = Config.CONFIG
OUTPUT: Path
INPUT: Optional[Path]

TIMEOUT: int
PREP_TIME: int
FOCUS_TIME: int
START_TIME:float = 0.0

SLEEP_GRANULARITY: int = 60

FUZZERS: List[str]= []
TARGET: str
CPU_ASSIGN: Dict[str, float] = {}
CGROUP_ROOT = ''

ARGS: cli.ArgsParser


def gen_fuzzer_driver_args(fuzzer: str,
                           jobs=1,
                           input_dir=None,
                           ) -> dict:
    global ARGS, CGROUP_ROOT
    fuzzer_config = config['fuzzer'][fuzzer]
    target_config = config['target'][TARGET]
    seed = None
    if input_dir:
        seed = input_dir
    else:
        seed = target_config['seed']
    group = target_config['group']
    target_args = target_config['args'].get(fuzzer, target_config['args']['default'])
    logging.info(f'main 007 - target_args : {target_args}')
    root_dir = os.path.realpath(ARGS.output)
    output = os.path.join(root_dir, TARGET, fuzzer)
    #cgroup_path = os.path.join(CGROUP_ROOT, fuzzer)
    kw = {
        'fuzzer': fuzzer,
        'seed': seed,
        'output': output,
        'group': group,
        'program': TARGET,
        'argument': target_args,
        'thread': jobs
        #'cgroup_path': cgroup_path
    }
    return kw

def start(fuzzer: str, output_dir, timeout, input_dir=None):
    global FUZZERS,ARGS

    fuzzer_config = config['fuzzer'][fuzzer]

    logger.info(f'main 004 - fuzzer_config : {fuzzer_config}')

    create_output_dir = fuzzer_config.get('create_output_dir',True)

    if create_output_dir:
        host_output_dir = f'{output_dir}/{ARGS.target}/{fuzzer}'
        logger.info(f'main 005 - create_output_dir : {create_output_dir}  host_output_dir : {host_output_dir}')
        os.makedirs(host_output_dir, exist_ok=True)
    else:
        host_output_dir = f'{output_dir}/{ARGS.target}'
        if os.path.exists(f'{output_dir}/{ARGS.target}/{fuzzer}'):
            logger.error(f'Please remove {output_dir}/{ARGS.target}/{fuzzer}')
            terminate_rcfuzz()
        os.makedirs(host_output_dir, exist_ok=True)
        logger.info(f'main 005 - create_output_dir : {create_output_dir}  host_output_dir : {host_output_dir}')
    
    kw = gen_fuzzer_driver_args(fuzzer=fuzzer, input_dir=input_dir)

    kw['command'] = 'start'

    logger.info(f'main 008 - kw : {kw}')

    fuzzer_driver.main(**kw)






def cleanup(exit_code=0):
    global ARGS
    logger.info('main 006 - cleanup')
    LOG['end_time'] = time.time()
    #write_log()
    #for fuzzer in FUZZERS:
    #    stop(fuzzer)
    #if exit_code == 0 and ARGS.tar:
    #    save_tar()
    os._exit(exit_code)


def cleanup_exception(etype, value, tb):
    #traceback.print_exception(etype, value, tb)
    cleanup(1)


def init():
    global START_TIME, LOG
    signal.signal(signal.SIGTERM, lambda x, frame: sys.exit(0))
    signal.signal(signal.SIGINT, lambda x, frame: sys.exit(0))
    atexit.register(cleanup)
    sys.excepthook = cleanup_exception
    health_check_path = os.path.realpath(os.path.join(ARGS.output, 'health'))
    pathlib.Path(health_check_path).touch(mode=0o666, exist_ok=True)
    LOG['log'] = []
    LOG['round'] = []
    logger.info(f'main 004.5 - init end')

# we create init_cgroup



def main():
    global ARGS, TARGET, FUZZERS, OUTPUT, INPUT
    global TIMEOUT, PREP_TIME, FOCUS_TIME, START_TIME
    global CPU_ASSIGN


    ARGS = cli.ArgsParser().parse_args()

    logger.info(f'main 001 - ARG(user set option) : {ARGS}\n')

    # option parsing
    TARGET = ARGS.target
    FUZZERS = ARGS.fuzzer
    OUTPUT = ARGS.output.resolve()
    TIMEOUT = ARGS.timeout
    PREP_TIME = ARGS.prep
    FOCUS_TIME = ARGS.focus

    if ARGS.input:
        INPUT = ARGS.input.resolve()
    else:
        INPUT = None

    logger.info(f'main 002 - check ARG : target : {TARGET}, fuzzer : {FUZZERS}, output : {OUTPUT}, timeout : {TIMEOUT}, prep_time : {PREP_TIME}, focus_time :{FOCUS_TIME}')

    # create output directory
    try:
        os.makedirs(OUTPUT, exist_ok=False)
    except FileExistsError:
        logger.error(f'remove {OUTPUT}')
        exit(1)
    
    current_time = time.time()
    init()
    LOG['dcfuzz_args'] = ARGS.as_dict()  # remove Namespace
    LOG['dcfuzz_config'] = config
    LOG['start_time'] = current_time
    LOG['algorithm'] = None

    # setup each fuzzer
    for fuzzer in FUZZERS:
        logger.info(f'main 003 - warm up {fuzzer}')
        CPU_ASSIGN[fuzzer] = 0
        logger.info(f'main 003.5 - start before')
        start(fuzzer=fuzzer, output_dir = OUTPUT,timeout=TIMEOUT,input_dir=INPUT)
        logger.info(f'main 004 - start after')

        # start each fuzzer in process












    
    


if __name__ == '__main__':
    main()
