#!/usr/bin/env python3

'''
config file for dcfuzz
'''

import os
import sys
import tempfile
from typing import Dict

# FIXME
if not __package__:
    sys.path.append(
        os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    __package__ = "dcfuzz"

INPUT_DIR = 'queue'
CRASH_DIR = 'crashes'

# NOTE: you can define your own config
CONFIG: Dict = {
    # these will be default parameters for cli.py
    'scheduler': {
        'prep_time': 300,
        'focus_time': 300,
        'coverage_update_time': 30,
        'sync_time': 300,
        'timeout': '86400'
    },
    # unused now
    'docker': {
        'root_dir': '/work/dcfuzz',
        'network': 'dcfuzz'
    },
    # binary directories for AFL-compiled binaries
    # justafl is used to get AFL bitmap
    # aflasan is used to triage crashes/bugs
    'evaluator': {
        'binary_root': '',
        'binary_crash_root': '',
    },
    'score_DAFL':{
        'command' : '/fuzzer/score/afl-fuzz',
        'target_root' : '/benchmark/bin/DAFL'
    },
    'dominator':{
        'command' : '',
        'target_root' : '/benchmark/bin/Dominator'
    },
    # only specify basic things
    # how to launch fuzzers with proper arguments is handled by fuzzer driver
    # new input dir need !!!! OOO
    'fuzzer': {
        'aflgo': {
            'input_dir': INPUT_DIR, # queue dir
            'crash_dir': CRASH_DIR,
            'command': '/fuzzer/AFLGo/afl-fuzz', # fuzzer binary path
            'target_root': '/benchmark/bin/AFLGo' # which binary is used to fuzz
        },
        'windranger': {
            'input_dir': INPUT_DIR,
            'crash_dir': CRASH_DIR,
            'command': '/fuzzer/WindRanger/fuzz/afl-fuzz',
            'target_root': '/benchmark/bin/WindRanger'
        },
        'dafl': {
            'input_dir': INPUT_DIR,
            'crash_dir': CRASH_DIR,
            'command': '/fuzzer/DAFL/afl-fuzz',
            'target_root': '/benchmark/bin/DAFL'
        }
        #'fairfuzz': {
        #    'input_dir': INPUT_DIR,
        #    'crash_dir': CRASH_DIR,
        #    'skip_crash_file': ['README.txt'],
        #    'command': '/fuzzer/afl-rb/afl-fuzz',
        #    'target_root': '/d/p/justafl',
        #    'afl_based': True
        #}
    },
    # each target has a group like e
    'target': {
        'cxxfilt-2016-4489': {
            'group': 'binutils',
            'seed': '/benchmark/seed/cxxfilt',
            #'dict': 'jpeg.dict',
            # default is AFL-style (@@ for input file)
            'args': {
                'default': '',
            }
            # fuzzers that do not support this target.
        },
        'cxxfilt-2016-4490': {
            'group': 'binutils',
            'seed': '/benchmark/seed/cxxfilt',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '',
            }
        },
        'cxxfilt-2016-4491': {
            'group': 'binutils',
            'seed': '/benchmark/seed/cxxfilt',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '',
            }
        },
        'cxxfilt-2016-4492': {
            'group': 'binutils',
            'seed': '/benchmark/seed/cxxfilt',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '',
            }
        },
        'cxxfilt-2016-4492-crash1': {
            'group': 'binutils',
            'seed': '/benchmark/seed/cxxfilt',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '',
            }
        },
        'cxxfilt-2016-4492-crash2': {
            'group': 'binutils',
            'seed': '/benchmark/seed/cxxfilt',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '',
            }
        },
        'cxxfilt-2016-6131': {
            'group': 'binutils',
            'seed': '/benchmark/seed/cxxfilt',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '',
            }
        },
        'nm-2017-14940': {
            'group': 'binutils',
            'seed': '/benchmark/seed/nm-2017-14940',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '-A -a -l -S -s --special-syms --synthetic --with-symbol-versions -D @@',
            }
        },
        'objdump-2017-8392': {
            'group': 'binutils',
            'seed': '/benchmark/seed/objdump-2017-8392',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '-SD @@',
            }
        },
        'objdump-2017-8396': {
            'group': 'binutils',
            'seed': '/benchmark/seed/objdump-2017-8396',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '-W @@',
            }
        },
        'objdump-2017-8397': {
            'group': 'binutils',
            'seed': '/benchmark/seed/objdump-2017-8397',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '-W @@',
            }
        },
        'objdump-2017-8398': {
            'group': 'binutils',
            'seed': '/benchmark/seed/objdump-2017-8398',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '-W @@',
            }
        },
        'swftophp-2016-9827': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2016-9827',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2016-9829': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2016-9829',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2016-9831': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2016-9831',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2017-9988': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2017-9988',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2017-11728': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2017-11728',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2017-11729': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2017-11729',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2018-11225': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2018-11225',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2018-11226': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2018-11226',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2018-20427': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2018-20427',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2018-7868': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2018-8807',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2018-8807': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2018-8807',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2018-8962': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2018-8807',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2019-12982': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2019-12982',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2019-9114': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2019-9114',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '@@',
            }
        },
        'swftophp-2020-6628': {
            'group': 'swftophp',
            'seed': '/benchmark/seed/swftophp-2020-6628',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '@@',
            }
        }
    }

}

# list of all fuzzers

FUZZERS = [ 'aflgo', 'windranger', 'dafl' ]

DATABASE_DIR= tempfile.mkdtemp()










