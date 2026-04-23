import os
import pathlib
import sys
import time
import logging

import peewee
import psutil

from dcfuzz import config as Config
from .controller import Controller
from .db import AFLGoModel, ControllerModel, db_proxy
from .fuzzer import PSFuzzer, FuzzerDriverException

logger = logging.getLogger('dcfuzz.fuzzer_driver.aflgo')

CONFIG = Config.CONFIG
FUZZER_CONFIG = CONFIG['fuzzer']

def parse_fuzzer_stats(fuzzer_stats_file):
    ret = {}
    if not os.path.exists(fuzzer_stats_file):
        return None
    with open(fuzzer_stats_file) as f:
        for l in f:
            arr = l.split(":")
            key = arr[0].strip()
            value = arr[1].strip()
            ret[key] = value
    assert ret
    return ret


class AFLGoBase(PSFuzzer):
    def __init__(self,seed,output,group,program,argument,cgroup_path='',pid=None):
        super().__init__(pid)
        self.seed = seed
        self.output = output
        self.group = group
        self.program = program
        self.argument = argument
        self.cgroup_path = cgroup_path
        self.__fuzzer_stats = None
        self.__proc = None

    @property
    def aflgo_command(self):
        global FUZZER_CONFIG
        return FUZZER_CONFIG['aflgo']['command']

    def update_fuzzer_stats(self):
        fuzzer_stats_file = f'{self.output}/fuzzer_stats'
        self.__fuzzer_stats = parse_fuzzer_stats(fuzzer_stats_file)

    @property
    def fuzzer_stats(self):
        if self.__fuzzer_stats is None:
            self.update_fuzzer_stats()
        return self.__fuzzer_stats

    @property
    def is_active(self):
        return self.proc.status() != psutil.STATUS_STOPPED

    @property
    def is_inactive(self):
        return self.proc.status() == psutil.STATUS_STOPPED

    @property
    def is_ready(self):
        queue_dir = f'{self.output}/{self.name}/queue'
        return os.path.exists(queue_dir)

    @property
    def target(self):
        global FUZZER_CONFIG
        target_root = FUZZER_CONFIG['aflgo']['target_root']
        return os.path.join(target_root, self.program)
    
    def gen_cwd(self):
        return os.path.dirname(self.target)

    def gen_env(self):
        env = {
                'AFL_NO_UI': '1',
                'AFL_SKIP_CPUFREQ': '1',
                'AFL_NO_AFFINITY': '1',
                'AFL_SKIP_CRASHES': '1',
                'AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES': '1',
                'UBSAN_OPTIONS': 'print_stacktrace=1:halt_on_error=1'
                }
        env.pop('ASAN_OPTIONS', None)
        return env

    def check(self):
        ret = True
        ret &= os.path.exists(self.target)
        if not ret:
            raise FuzzerDriverException
    
    def gen_run_args(self):
        self.check()
        args = []
        if self.cgroup_path:
            args += ['cgexec', '-g', f'cpu:{self.cgroup_path}']
        args += [self.aflgo_command, '-i', self.seed, '-o', self.output]
        args += ['-m', 'none']
        args += ['-d']
        args += ['-z', 'exp']
        args += ['-c', '20h']
        args += ['--', self.target]
        if not self.argument == '':
            args += self.argument.split(' ')
        logger.info(f'aflgo class 100 - arg : {args}')
        return args



class AFLGo(AFLGoBase):
    @property
    def aflgo_command(self):
        global FUZZER_CONFIG
        return FUZZER_CONFIG['aflgo']['command']

    def gen_run_args(self):
        self.check()
        args = []
        if self.cgroup_path:
            args += ['cgexec', '-g', f'cpu:{self.cgroup_path}']
        args += [self.aflgo_command, '-i', self.seed, '-o', self.output]
        args += ['-m', 'none']
        args += ['-d']
        args += ['-z', 'exp']
        args += ['-c', '20h']
        args += ['--', self.target]
        if not self.argument == '':
            args += self.argument.split(' ')
        logger.info(f'aflgo class 100 - arg : {args}')
        return args

class AFLGOController(Controller):
    def __init__(self, seed, output, group, program, argument, cgroup_path=''):
        self.db = peewee.SqliteDatabase(
                os.path.join(Config.DATABASE_DIR, 'dcfuzz-aflgo.db'))
        self.name = 'aflgo'
        self.seed = seed        
        self.output = output
        self.group = group
        self.program = program
        self.argument = argument
        self.cgroup_path = cgroup_path
        self.aflgos = []
        self.kwargs = {
                'seed': self.seed,
                'output': self.output,
                'group': self.group,
                'program': self.program,
                'argument': self.argument,
                'cgroup_path' : self.cgroup_path
        }

    def init(self):
        # logger.info(f'aflgo controller 001 - init aflgo driver')
        db_proxy.initialize(self.db)
        self.db.connect()
        self.db.create_tables([AFLGoModel, ControllerModel])
        # check select model        
        q = AFLGoModel.select()
        # logger.info("AFLGoModel count = %d", q.count())
        # logger.info("DB path = %s", self.db.database)
        # logger.info("AFLGoModel db bound = %r", AFLGoModel._meta.database)
        
        for fuzzer in AFLGoModel.select():
            aflgo = AFLGo(seed=fuzzer.seed, output=fuzzer.output, group=fuzzer.group, program=fuzzer.program, argument=fuzzer.argument, cgroup_path=self.cgroup_path, pid=fuzzer.pid)
            # logger.info(f'aflgo controller 002 - aflgo : {aflgo}')
            self.aflgos.append(aflgo)


    def start(self):
        # logger.info(f'aflgo controller 003 - start aflgo driver')
        if self.aflgos:
            print('already started', file=sys.stderr)
            return
        aflgo = AFLGo(**self.kwargs)
        aflgo.start()
        AFLGoModel.create(**self.kwargs, pid=aflgo.pid)
        ControllerModel.create(scale_num=1)
        ready_path = os.path.join(self.output, 'ready')
        pathlib.Path(ready_path).touch(mode=0o666, exist_ok=True)

    def scale(self, scale_num):
        pass

    def pause(self):
        # logger.info(f'aflgo controller 004 - pause aflgo driver')
        for aflgo in self.aflgos:
            aflgo.pause()

    def resume(self):
        # logger.info(f'aflgo controller 005 - resume aflgo driver')
        '''
        NOTE: prserve scaling
        '''
        controller = ControllerModel.get()
        for aflgo in self.aflgos:
            aflgo.resume()

    def stop(self):
        # logger.info(f'aflgo controller 006 - stop aflgo driver')
        for aflgo in self.aflgos:
            aflgo.stop()
        self.db.drop_tables([AFLGoModel, ControllerModel])


