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
        'timeout': '24h'
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
    # only specify basic things
    # how to launch fuzzers with proper arguments is handled by fuzzer driver
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
            'group': 'cxxfilt',
            'seed': '/benchmark/seed/cxxfilt',
            #'dict': 'jpeg.dict',
            # default is AFL-style (@@ for input file)
            'args': {
                'default': '',
            }
            # fuzzers that do not support this target.
            # rcfuzz will do some sanity check when started.
        },
        'cxxfilt-2016-4490': {
            'group': 'cxxfilt',
            'seed': '/benchmark/seed/cxxfilt',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '',
            }
        },
        'cxxfilt-2016-4491': {
            'group': 'cxxfilt',
            'seed': '/benchmark/seed/cxxfilt',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '',
            }
        },
        'cxxfilt-2016-4492': {
            'group': 'cxxfilt',
            'seed': '/benchmark/seed/cxxfilt',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '',
            }
        },
        'cxxfilt-2016-4492-crash1': {
            'group': 'cxxfilt',
            'seed': '/benchmark/seed/cxxfilt',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '',
            }
        },
        'cxxfilt-2016-4492-crash2': {
            'group': 'cxxfilt',
            'seed': '/benchmark/seed/cxxfilt',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '',
            }
        },
        'cxxfilt-2016-6131': {
            'group': 'cxxfilt',
            'seed': '/benchmark/seed/cxxfilt',
            #'code_dir': 'unibench/gdk-pixbuf-2.31.1',
            #'dict': 'jpeg.dict',
            'args': {
                'default': '',
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
        }


    }

}

# list of all fuzzers

FUZZERS = [ 'aflgo', 'windranger', 'dafl' ]

DATABASE = tempfile.mkdtemp()










