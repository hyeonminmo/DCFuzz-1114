import numpy as np
import logging

logger = logging.getLogger('dcfuzz.thompson')

class fuzzer():
    def __init__(self):
        self.S = 1 # success count
        self.F = 1 # fail count
        self.prob = 0.0
        self.total_runTime = 0
        self.score = 0
        self.dom = 0


def selectFuzzer(fuzzers):
    for value in fuzzers.values():
        value.prob = np.random.beta(value.S, value.F, size = 1)
        logger.info(f'thomps 001 - Success: { value.S }, Fail : {value.F}, Prob: { value.prob }')

    selectedFuzzer = max(fuzzers, key=lambda key: fuzzers[key].prob)

    logger.info(f'thomps 002 - selected Fuzzers: {selectedFuzzer}')
    
    return selectedFuzzer

def updateFuzzerCount(tsfuzzer, selected_fuzzers, criteria):
    for selected_fuzzer in selected_fuzzers:
        fuzzer = tsfuzzer[selected_fuzzer]
        if criteria == 1:
            fuzzer.S = fuzzer.S + fuzzer.diff
            logger.info(f'thomps 003 - {selected_fuzzers[0]} is success')
            fuzzer.diff *= 0.5 
        else:
            fuzzer.F = fuzzer.F + fuzzer.diff
            logger.info(f'thomps 004 - {selected_fuzzers[0]} is fail')
            fuzzer.diff += 1

def updateFuzzerCountPrep(tsfuzzer, selected_fuzzer, criteria):
    fuzzer = tsfuzzer[selected_fuzzer]
    if criteria == 1:
        fuzzer.S = fuzzer.S + 1
        logger.info(f'thomps 005 - {selected_fuzzer} is success')
    else:
        fuzzer.F = fuzzer.F + 1
        logger.info(f'thomps 006 - {selected_fuzzer} is fail')

def rankFuzzer(fuzzers):
    # compare dom coverage first
    ranked = sorted(
        fuzzers,
        key=lambda f: (fuzzers[f].dom, fuzzers[f].score),
        reverse=True
    )

    rank_deltas = [
        (19, 1),
        (10, 10),
        (1, 19)
    ]

    groups = []
    current_group = [ranked[0]]

    for prev, cur in zip(ranked, ranked[1:]):
        prev_f = fuzzers[prev]
        cur_f = fuzzers[cur]

        # compare score second
        if prev_f.dom == cur_f.dom and prev_f.score == cur_f.score:
            current_group.append(cur)
        else:
            groups.append(current_group)
            current_group = [cur]

    groups.append(current_group)

    for idx, group in enumerate(groups):
        if idx >= len(rank_deltas):
            break
        dS, dF = rank_deltas[idx]
        for f in group:
            fuzzers[f].S += dS
            fuzzers[f].F += dF
        
        
