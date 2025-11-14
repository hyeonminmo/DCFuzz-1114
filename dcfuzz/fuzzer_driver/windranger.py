import os
import pathlib
import sys
import time

import peewee
import psutil

from dcfuzz import config as Config


from .controller import Controller
from .db import ControllerModel, db_proxy
from .fuzzer import FuzzerDriverException, PSFuzzer



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
        return {
                'AFL_NO_UI': '1',
                'AFL_SKIP_CPUFREQ': '1',
                'AFL_NO_AFFINITY': '1',
                'AFL_SKIP_CRASHES': '1',
                'AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES':'1',
                'UBSAN_OPTIONS': 'print_stacktrace=1:halt_on_error=1'
                }
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
        args += ['-z', 'exp']
        args += ['-c', '45m']
        args += ['--', self.target]
        args += self.argument.split(' ')
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
        args += ['-z', 'exp']
        args += ['-c', '45m']
        args += ['--', self.target]
        args += self.argument.split(' ')
        return args

class AFLGoController(Controller):
    def __init__(self, seed, output, group, program, argument, thread=1, cgroup_path=''):
        self.db = peewee.SqliteDatabase(
                os.path.join(Config.DATABASE_DIR, 'dcfuzz-aflgo.db'))
        self.name = 'aflgo'
        self.seed = seed
        self.output = output
        self.group = group
        self.program = program
        self.argument = argument
        self.thread = thread
        self.cgroup_path = cgroup_path
        self.aflgos = []
        self.kwargs = {
            'seed': self.seed,
            'output': self.output,
            'group': self.group,
            'program': self.program,
            'argument': self.argument,
            'thread': self.thread,
            'cgroup_path' : self.cgroup_path
        }

    def init(self):
        db_proxy.initialize(self.db)
        self.db.connect()
        self.db.create_tables([AFLGoModel, ControllerModel])
        
        for fuzzer in AFLGoModel.selct():
            aflgo = AFLGo(seed=fuzzer.seed, output=fuzzer.output, group=fuzzer.group, program=fuzzer.program, argument=fuzzer.argument, thread=fuzzer.thread, cgroup_path=self.cgroup_path, pid=fuzzer.pid)
            self.aflgos.append(aflgo)


    def start(self):
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
        for aflgo in self.aflgos:
            aflgo.pause()

    def resume(self):
        '''
        NOTE: prserve scaling
        '''
        controller = ControllerModel.get()
        for aflgo in self.aflgos:
            aflgo.resume()

    def stop(self):
        for aflgo in self.aflgos:
            aflgo.stop()
        self.db.drop_tables([AFLGoModel, ControllerModel])


