import os
import subprocess
import sys
from abc import ABCMeta, abstractmethod
import logging

import psutil

from dcfuzz.common import IS_DEBUG

logger = logging.getLogger('dcfuzz.fuzzer_driver.fuzzer')

class FuzzerDriverException(Exception):
    pass


class Fuzzer(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def start(self):
        pass

    @abstractmethod
    def pause(self):
        pass

    @abstractmethod
    def resume(self):
        pass

    @abstractmethod
    def stop(self):
        pass


class PSFuzzer(Fuzzer):
    def __init__(self, pid, debug=False, debug_file=None):
        self.__pid = pid
        self.debug = debug
        self.debug_file = debug_file

    @property
    def pid(self):
        return self.__pid

    @property
    def proc(self):
        '''
        method to retrive process based on psutils
        '''
        proc = None
        
        if not self.pid:
            return None
        if psutil.pid_exists(self.pid):
            proc = psutil.Process(pid=self.pid)
        else:
            return None
        #logger.info(f'fuzzer_driver fuzzer 001 - pid : {self.pid}, pid_exists={psutil.pid_exists(self.pid)}')
        return proc

    @abstractmethod
    def gen_cwd(self):
        return None

    @abstractmethod
    def gen_run_args(self):
        pass

    def gen_env(self):
        return {}

    def pre_run(self):
        pass

    def run(self):
        if self.proc:
            return
        self.pre_run()
        args = self.gen_run_args()
        cwd = self.gen_cwd()
        env = {**os.environ, **self.gen_env()}

        # log_path = os.path.join(self.output, "fuzzer_std.log")
        # log_file = open(log_path, "w")
        if IS_DEBUG:
            # print(env)
            print(" ".join(args))
        if self.debug:
            assert self.debug_file
            with open(self.debug_file, 'w+') as f:
                proc = subprocess.Popen(args,
                                        env=env,
                                        cwd=cwd,
                                        stdin=subprocess.DEVNULL,
                                        stdout=f,
                                        stderr=subprocess.STDOUT)
        else:
            proc = subprocess.Popen(args,
                                    env=env,
                                    cwd=cwd,
                                    stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
        #                            bufsize =0)
        # 여기서 subprocess.Popen() 하면서 pid 생성이 됨.   
        assert proc
        self.__proc = proc
        self.__pid = proc.pid
        # logger.info(f'fuzzer_driver fuzzer 666 - proc : {proc}, pid : {proc.pid}, args : {args}, cwd : {cwd}')

    def start(self):
        logger.info(f'fuzzer_driver fuzzer 002 start')
        if self.proc:
            # NOTE: alreay start
            print('already started', file=sys.stderr)
            return
        self.run()

    def pause(self):
        logger.info(f'fuzzer_driver fuzzer 003 pause')
        if not self.proc:
            raise FuzzerDriverException
        for child in self.proc.children(recursive=True):
            try:
                child.suspend()
            except psutil.NoSuchProcess:
                pass
        self.proc.suspend()

    def resume(self):
        logger.info(f'fuzzer_driver fuzzer 004 resume')
        if not self.proc:
            raise FuzzerDriverException
        for child in self.proc.children(recursive=True):
            try:
                child.resume()
            except psutil.NoSuchProcess:
                pass
        self.proc.resume()

    def stop(self):
        logger.info(f'fuzzer_driver fuzzer 005 stop')
        if not self.proc:
            # NOTE: no need to raise exception, maybe fuzzer just timeout
            return
        for child in self.proc.children(recursive=True):
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
        self.proc.kill()
