from triage import *

# (target bin, target cmdline, input src, additional option, triage function)

FUZZ_TARGETS = [
    ("cxxfilt-2016-4487", "", "stdin", {
        "asan": check_cxxfilt_2016_4487
    }),
    ("cxxfilt-2016-4489", "", "stdin", {
        "asan": check_cxxfilt_2016_4489
    }),
    ("cxxfilt-2016-4490", "", "stdin", {
        "asan": check_cxxfilt_2016_4490
    }),
    ("cxxfilt-2016-4491", "", "stdin", {
        "asan": check_cxxfilt_2016_4491
    }),
    ("cxxfilt-2016-4492", "", "stdin", {
        "asan": check_cxxfilt_2016_4492
    }),
    ("cxxfilt-2016-6131", "", "stdin", {
        "asan": check_cxxfilt_2016_6131
    }),
    ("nm-2017-8397", "-A -a -l -S -s --special-syms --synthetic --with-symbol-versions -D @@", "file", {
        "asan": check_nm_2017_14940
    }),
    ("objdump-2017-8392", "-SD @@", "file", {
        "asan": check_objdump_2017_8392
    }),
    ("objdump-2017-8396", "-W @@", "file", {
        "asan": check_objdump_2017_8396
    }),
    ("objdump-2017-8397", "-W @@", "file", {
        "asan": check_objdump_2017_8397
    }),
    ("objdump-2017-8398", "-W @@", "file", {
        "asan": check_objdump_2017_8398
    }),


    ## Fuzz targets with alternate target point(s)
    ("cxxfilt-2016-4489-crash", "", "stdin", {
        "asan": check_cxxfilt_2016_4489
    }),
    ("cxxfilt-2016-4489-caller", "", "stdin", {
        "asan": check_cxxfilt_2016_4489
    }),
    ("cxxfilt-2016-4492-crash1", "", "stdin", {
        "asan": check_cxxfilt_2016_4492
    }),
    ("cxxfilt-2016-4492-crash2", "", "stdin", {
        "asan": check_cxxfilt_2016_4492
    }),
    ("swftophp-2016-9827", "@@", "file", {
        "asan": check_swftophp_2016_9827
    }),
    ("swftophp-2016-9829", "@@", "file", {
        "asan": check_swftophp_2016_9829
    }),
    ("swftophp-2016-9831", "@@", "file", {
        "asan": check_swftophp_2016_9831_v3,
        "asan-a": check_swftophp_2016_9831_v1,
        "asan-b": check_swftophp_2016_9831_v2,
        "asan-c": check_swftophp_2016_9831_v3
    }),
    ("swftophp-2017-9988", "@@", "file", {
        "asan": check_swftophp_2017_9988
    }),
    ("swftophp-2017-11728", "@@", "file", {
        "asan": check_swftophp_2017_11728
    }),
    ("swftophp-2017-11729", "@@", "file", {
        "asan": check_swftophp_2017_11729
    }),
    ("swftophp-2018-7868", "@@", "file", {
        "asan": check_swftophp_2018_7868
    }),
    ("swftophp-2018-8807", "@@", "file", {
        "asan": check_swftophp_2018_8807
    }),
    ("swftophp-2018-8962", "@@", "file", {
        "asan": check_swftophp_2018_8962
    }),
    ("swftophp-2018-11095", "@@", "file", {
        "asan": check_swftophp_2018_11095
    }),
    ("swftophp-2018-11225", "@@", "file", {
        "asan": check_swftophp_2018_11225
    }),
    ("swftophp-2018-11226", "@@", "file", {
        "asan": check_swftophp_2018_11226
    }),
    ("swftophp-2018-20427", "@@", "file", {
        "asan": check_swftophp_2018_20427
    }),
    ("swftophp-2019-12982", "@@", "file", {
        "asan": check_swftophp_2019_12982
    }),
    ("swftophp-2019-9114", "@@", "file", {
        "asan": check_swftophp_2019_9114
    }),
    ("swftophp-2020-6628", "@@", "file", {
        "asan": check_swftophp_2020_6628
    }),

]

SLICE_TARGETS = {
    'swftophp': {
        'frontend':'cil',
        'entry_point':'main',
        'bugs': [
            '2016-9827', '2016-9829', '2016-9831', '2017-9988', '2017-11728', '2017-11729'
        ]
    },
     'swftophp-4.8': {
        'frontend':'cil',
        'entry_point':'main',
        'bugs': ['2018-7868', '2018-8807', '2018-8962', '2018-11095', '2018-11225','2018-11226', '2018-20427', '2019-12982', '2020-6628']
    },
    'swftophp-4.8.1': {
        'frontend':'cil',
        'entry_point':'main',
        'bugs': ['2019-9114']
    },
    'cxxfilt': {
        'frontend': 'cil',
        'entry_point':'main',
        'bugs': [
            '2016-4487', '2016-4489', '2016-4490', '2016-4491', '2016-4492', '2016-6131',
            '2016-4489-crash', '2016-4489-caller', '2016-4492-crash1', '2016-4492-crash2'
        ]
    },
    'nm': {
        'frontend':'cil',
        'entry_point':'main',
        'bugs': ['2017-14940']
    },
    'objdump': {
        'frontend':'cil',
        'entry_point':'main',
        'bugs': ['2017-8392', '2017-8396', '2017-8397', '2017-8398']
    },
}

EXP_ENV = {
    "TIMELIMTS": {
        "table3": 5000,
        "table4": 1000,
        "table5": 5000,
        "table6": 43200,
        "table8": 1000,
        "table9": 86400,
        "table9-minimal": 43200,
        "figure6": 1000,
        "figure7": 15000,
        "custom": 86400
    },
    "ITERATIONS": {
        "table3": 40,
        "table4": 40,
        "table5": 40,
        "table6": 40,
        "table8": 40,
        "table9-minimal": 40,
        "table9": 40,
        "figure6": 160,
        "figure7": 160,
        "custom": 160
    },
    "TOOLS": {
        "table3": ["AFLGo", "Beacon", "WindRanger", "SelectFuzz", "DAFL"],
        "table4": ["Beacon", "WindRanger", "SelectFuzz", "DAFL"],
        "table5": ["AFLGo", "Beacon", "WindRanger", "SelectFuzz", "DAFL"],
        "table6": ["AFLGo", "Beacon", "WindRanger", "SelectFuzz", "DAFL"],
        "table8": ["AFLGo", "Beacon"],
        "table9": ["AFLGo", "Beacon", "WindRanger", "SelectFuzz", "DAFL"],
        "table9-minimal": ["AFLGo", "Beacon", "WindRanger", "SelectFuzz", "DAFL"],
        "figure6": ["AFLGo", "Beacon", "WindRanger", "SelectFuzz", "DAFL"],
        "figure7": ["AFLGo", "DAFL"],
        "custom": ["AFLGo", "Beacon", "WindRanger", "SelectFuzz", "DAFL"],
    },
    "TARGETS": {
        "table3": [
            "cxxfilt-2016-4492-crash1",
            "cxxfilt-2016-4492-crash2",
        ],
        "table4": [
            "cxxfilt-2016-4489-crash",
            "cxxfilt-2016-4489-caller",
        ],
        "table5": [
            "swftophp-2016-9831",
        ],
        "table6": [
            "cxxfilt-2016-4491",
        ],
        "table8": [
            "cxxfilt-2016-4489",
            "swftophp-2016-9831",
        ],
        "table9": [
            "cxxfilt-2016-4487",
            "cxxfilt-2016-4489",
            "cxxfilt-2016-4490",
            "cxxfilt-2016-4491",
            "cxxfilt-2016-4492",
            "cxxfilt-2016-6131",
            "swftophp-2016-9827",
            "swftophp-2016-9829",
            "swftophp-2016-9831",
            "swftophp-2017-9988",
            "swftophp-2017-11728",
            "swftophp-2017-11729",
        ],
        "table9-minimal": [
            "cxxfilt-2016-4492",
        ],
        "figure6": [
            "cxxfilt-2016-4490",
        ],
        "figure7": [
            "swftophp-2017-9988",
        ],
    },
    "PATCH_VERSIONS": {
        "table3": "default",
        "table4": "default",
        "table5": "",
        "table6": "a b",
        "table8": "default",
        "table9": "default",
        "table9-minimal": "default",
        "figure6": "default",
        "figure7": "default",
        "custom": "default",
    },
}


def generate_fuzzing_worklist(target_list, iteration):
    worklist = []
    for (targ_prog, cmdline, src, _) in FUZZ_TARGETS:
        if targ_prog in target_list:
            if src not in ["stdin", "file"]:
                print("Invalid input source specified: %s" % src)
                exit(1)
            for i in range(iteration):
                iter_id = "iter-%d" % i
                worklist.append((targ_prog, cmdline, src, iter_id))
    return worklist


def generate_slicing_worklist(benchmark):
    if benchmark == "all":
        worklist = list(SLICE_TARGETS.keys())
    elif benchmark in SLICE_TARGETS:
        worklist = [benchmark]
    else:
        print("Unsupported benchmark: %s" % benchmark)
        exit(1)
    return worklist


def generate_replay_worklist(benchmark, iteration):
    return generate_fuzzing_worklist(benchmark, iteration)


def check_targeted_crash_asan(targ, replay_buf, triage_ver):
    for (targ_prog, _, _, crash_checker) in FUZZ_TARGETS:
        if targ_prog == targ:
            triage_func = crash_checker.get(triage_ver)
            if triage_func == None:
                print("Unknown triage method: %s" % triage_ver)
                exit(1)
            return triage_func(replay_buf)
    print("Unknown target: %s" % targ)
    exit(1)


def check_targeted_crash_patch(targ, replay_orig, replay_patch):
    # TEMPORARY: Ignore irregular crash (cxxfilt)
    if "d_find_pack" in replay_orig or "d_find_pack" in replay_patch:
        return False
    # WARNING: Timeout can cause false negative
    if "TIMEOUT" in replay_patch:
        return False
    # TRUE case. The crash is different.
    if get_crash_func(replay_orig) != get_crash_func(replay_patch):
        # WARNING: The patched version does not exist
        if "No such file or directory" in replay_patch:
            print("Warning: The patched version does not exist for %s" % targ)
            return False
        # WARNING: In case of stack overflow, check for all functions in the stack trace
        if check_all(replay_orig, ["stack-overflow"]) and check_all(
                replay_patch, ["stack-overflow"]):
            set_orig = get_all_funcs(replay_orig)
            set_patch = get_all_funcs(replay_patch)
            # Conservative check: If the stack traces share at least one function,
            #                     it is considered as the same crash.
            #                     Thus, not removed by the patch.
            if len(set_orig.intersection(set_patch)) > 0:
                return False
        return True
    return False
