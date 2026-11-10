import logging
from typing import Dict, Iterable, List, Optional

import numpy as np

logger = logging.getLogger('dcfuzz.thompson')


DEFAULT_RANK_DELTAS = (
    (19, 1),
    (10, 10),
    (1, 19),
)


class fuzzer():
    def __init__(self):
        self.S = 1  # success count
        self.F = 1  # fail count
        self.prob = 0.0  # beta sample used for the latest selection
        self.selection_probability = 0.0  # estimated probability of being selected
        self.total_runTime = 0
        self.score = 0  # prox_score
        self.dom = 0  # dom_covered


def _state_snapshot(fuzzers) -> Dict[str, Dict[str, float]]:
    """Return a JSON-serializable snapshot of all Thompson/fuzzer metrics."""
    return {
        name: {
            "S": int(value.S),
            "F": int(value.F),
            "prox_score": int(value.score),
            "dom_covered": int(value.dom),
            "beta_sample": float(value.prob),
            "selection_probability": float(value.selection_probability),
        }
        for name, value in fuzzers.items()
    }


def _rank_key(value, use_dominator: bool):
    if use_dominator:
        return value.dom, value.score
    return (value.score,)


def _same_rank(lhs, rhs, use_dominator: bool) -> bool:
    if use_dominator:
        return lhs.dom == rhs.dom and lhs.score == rhs.score
    return lhs.score == rhs.score


def get_rank_groups(fuzzers, use_dominator: bool = False) -> List[List[str]]:
    """
    Rank fuzzers without changing S/F.

    prox-only: prox_score descending
    dom+prox:  dom_covered descending, then prox_score descending

    Fuzzer names are used only as a deterministic tie order. Equal metric values
    remain in the same rank group.
    """
    if not fuzzers:
        return []

    ranked = sorted(
        fuzzers,
        key=lambda name: (_rank_key(fuzzers[name], use_dominator), name),
        reverse=True,
    )

    groups: List[List[str]] = []
    current_group = [ranked[0]]

    for prev, cur in zip(ranked, ranked[1:]):
        if _same_rank(fuzzers[prev], fuzzers[cur], use_dominator):
            current_group.append(cur)
        else:
            groups.append(current_group)
            current_group = [cur]

    groups.append(current_group)
    return groups


def _rank_positions(groups: Iterable[Iterable[str]]) -> Dict[str, int]:
    """Use group rank (1, 2, 3, ...) so ties receive the same position."""
    positions: Dict[str, int] = {}
    for position, group in enumerate(groups, start=1):
        for name in group:
            positions[name] = position
    return positions


def rankFuzzer(
    fuzzers,
    use_dominator: bool = False,
    policy_name: Optional[str] = None,
    round_num: Optional[int] = None,
    prep_round: Optional[int] = None,
    rank_deltas=DEFAULT_RANK_DELTAS,
):
    """
    Rank fuzzers and update Thompson S/F according to rank groups.

    Returns a structured report so the caller can compare prox-only and
    dominator-aware counterfactual rankings in the same evaluation round.
    """
    policy_name = policy_name or ("dom_prox" if use_dominator else "prox_only")
    groups = get_rank_groups(fuzzers, use_dominator=use_dominator)
    before = _state_snapshot(fuzzers)
    applied_updates: Dict[str, Dict[str, int]] = {}

    for idx, group in enumerate(groups):
        if idx >= len(rank_deltas):
            # Preserve the previous behavior: only configured rank tiers update S/F.
            for name in group:
                applied_updates[name] = {"dS": 0, "dF": 0}
            continue

        dS, dF = rank_deltas[idx]
        for name in group:
            fuzzers[name].S += dS
            fuzzers[name].F += dF
            applied_updates[name] = {"dS": int(dS), "dF": int(dF)}

    after = _state_snapshot(fuzzers)
    report = {
        "policy": policy_name,
        "use_dominator": bool(use_dominator),
        "round": round_num,
        "prep_round": prep_round,
        "rank_groups": groups,
        "rank_positions": _rank_positions(groups),
        "state_before": before,
        "updates": applied_updates,
        "state_after": after,
    }

    logger.info(
        "thomps 100 - policy=%s round=%s prep_round=%s rank_groups=%s positions=%s",
        policy_name,
        round_num,
        prep_round,
        groups,
        report["rank_positions"],
    )
    for name in fuzzers:
        logger.info(
            "thomps 101 - policy=%s round=%s prep_round=%s fuzzer=%s "
            "dom_covered=%s prox_score=%s S_before=%s F_before=%s "
            "dS=%s dF=%s S_after=%s F_after=%s",
            policy_name,
            round_num,
            prep_round,
            name,
            before[name]["dom_covered"],
            before[name]["prox_score"],
            before[name]["S"],
            before[name]["F"],
            applied_updates.get(name, {}).get("dS", 0),
            applied_updates.get(name, {}).get("dF", 0),
            after[name]["S"],
            after[name]["F"],
        )

    return report


def estimate_selection_probabilities(fuzzers, samples: int = 10000, seed=None):
    """
    Estimate P(each fuzzer has the largest Thompson sample).

    This is different from the single beta sample used for the actual choice.
    Vectorized Monte Carlo keeps the overhead small for the usual 3 fuzzers.
    """
    names = list(fuzzers.keys())
    if not names:
        return {}
    if samples <= 0:
        return {name: 0.0 for name in names}

    rng = np.random.default_rng(seed)
    draws = np.column_stack([
        rng.beta(fuzzers[name].S, fuzzers[name].F, size=samples)
        for name in names
    ])
    winners = np.argmax(draws, axis=1)
    counts = np.bincount(winners, minlength=len(names))
    return {
        name: float(counts[idx] / samples)
        for idx, name in enumerate(names)
    }


def selectFuzzer(
    fuzzers,
    seed=None,
    probability_samples: int = 10000,
    policy_name: str = "actual",
    round_num: Optional[int] = None,
    return_details: bool = False,
):
    """
    Select one fuzzer using Thompson Sampling and log both:
      - beta_sample: the one draw actually used for this decision
      - selection_probability: Monte Carlo estimate of winning probability

    Passing the same seed to two policy states provides a common-random-number
    comparison: identical S/F states yield identical beta samples, while any
    difference is attributable to the ranking policy's state updates.
    """
    if not fuzzers:
        raise ValueError("selectFuzzer requires at least one fuzzer")

    names = list(fuzzers.keys())
    sample_rng = np.random.default_rng(seed)
    # Use a deterministic but separate stream for Monte Carlo estimation.
    probability_seed = None if seed is None else int(seed) ^ 0x9E3779B97F4A7C15
    selection_probabilities = estimate_selection_probabilities(
        fuzzers,
        samples=probability_samples,
        seed=probability_seed,
    )

    for name in names:
        value = fuzzers[name]
        value.prob = float(sample_rng.beta(value.S, value.F))
        value.selection_probability = float(selection_probabilities[name])
        logger.info(
            "thomps 001 - policy=%s round=%s fuzzer=%s Success=%s Fail=%s "
            "beta_sample=%.12f selection_probability=%.12f",
            policy_name,
            round_num,
            name,
            value.S,
            value.F,
            value.prob,
            value.selection_probability,
        )

    selected_fuzzer = max(names, key=lambda name: fuzzers[name].prob)
    details = {
        "policy": policy_name,
        "round": round_num,
        "random_seed": None if seed is None else int(seed),
        "probability_samples": int(probability_samples),
        "selected_fuzzer": selected_fuzzer,
        "fuzzers": _state_snapshot(fuzzers),
    }

    logger.info(
        "thomps 002 - policy=%s round=%s selected_fuzzer=%s random_seed=%s",
        policy_name,
        round_num,
        selected_fuzzer,
        seed,
    )

    if return_details:
        return selected_fuzzer, details
    return selected_fuzzer


def updateFuzzerCount(dcfuzzer, selected_fuzzer, criteria, delta: int = 20):
    """
    Update the selected fuzzer's Thompson success/failure count.

    criteria == 1: success -> S += delta
    otherwise:     failure -> F += delta

    The default delta is 20 so one focus-round outcome has the requested
    weight while preserving the existing initial Beta(1, 1) prior.
    """
    if delta <= 0:
        raise ValueError("delta must be a positive integer")

    selected = dcfuzzer[selected_fuzzer]
    before_s = int(selected.S)
    before_f = int(selected.F)

    if criteria == 1:
        selected.S += delta
        outcome = 'success'
        dS, dF = delta, 0
    else:
        selected.F += delta
        outcome = 'fail'
        dS, dF = 0, delta

    report = {
        'fuzzer': selected_fuzzer,
        'outcome': outcome,
        'delta': int(delta),
        'dS': int(dS),
        'dF': int(dF),
        'S_before': before_s,
        'F_before': before_f,
        'S_after': int(selected.S),
        'F_after': int(selected.F),
    }

    logger.info(
        'thomps 003 - fuzzer=%s outcome=%s dS=%s dF=%s '
        'S_before=%s F_before=%s S_after=%s F_after=%s',
        selected_fuzzer,
        outcome,
        dS,
        dF,
        before_s,
        before_f,
        selected.S,
        selected.F,
    )
    return report
