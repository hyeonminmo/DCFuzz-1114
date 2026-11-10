import os
import re
import sys
from pathlib import Path
import shutil
import time
import logging
import subprocess
import peewee

from . import config as Config
from .evaluateDB import AFLGoSeed, WindRangerSeed, DAFLSeed, init_db


CONFIG = Config.CONFIG
SCORE_CONFIG = CONFIG['score_DAFL']
DAFL_CONFIG = CONFIG['fuzzer']['dafl']
DOMINATOR_CONFIG = CONFIG['dominator']

logger = logging.getLogger('dcfuzz.evaluate')

# helper
def seed_id_num(name: str) -> int:
    """
    Extract numeric part from AFL-style seed id.
    Examples:
    - id:000100 -> 100
    - dafl_id:000100 -> 100
    """
    m = re.search(r"id:(\d+)", name)
    if not m:
        return -1
    return int(m.group(1))


def safe_int(v, default=-1):
    return int(v) if v is not None else default



# -----------------------------
# Args / Run
# -----------------------------
def gen_run_args(seed, output, program):
    global SCORE_CONFIG, DAFL_CONFIG, CONFIG
    logger.info("evaluator 100 - start gen_run_args")
    args = []
    command = SCORE_CONFIG['command']

    target = DAFL_CONFIG['target_root']
    target_root = os.path.join(target, program)

    target_config = CONFIG['target'][program]
    target_args = target_config['args']['default']
    logger.info(f"evaluator 101 - command : {command}, target_args : {target_args}, target_root : {target_root}")

    args += [command, '-i', seed, '-o', output]
    args += ['-m', 'none']
    args += ['-t', '10000+']
    args += ['-d']
    args += ['--', target_root]
    if target_args != '':
        args += target_args.split(' ')
    return args


def gen_dominator_args(seed_file: str, program: str):
    """
    Run dominator-instrumented target directly for a single seed.

    Rules:
    - if target args contain '@@', replace it with seed path
    - otherwise append seed path as the final argv
      (needed for cases like cxxfilt whose config args are '')
    """
    global DOMINATOR_CONFIG, CONFIG

    target_root = os.path.join(DOMINATOR_CONFIG['target_root'], program)
    target_config = CONFIG['target'][program]
    target_args = target_config['args']['default']

    args = [target_root]
    if target_args:
        for part in target_args.split(' '):
            if part == '@@':
                args.append(seed_file)
            else:
                args.append(part)
        if '@@' not in target_args.split(' '):
            args.append(seed_file)
    else:
        args.append(seed_file)

    logger.info(f"evaluator 110 - dominator args : {args}")
    return args


def normalize_afl_seed_id(name: str) -> str:
    """
    Extract only 'id:XXXXXX' from AFL seed name.
    Accepts both 'id:XXXXXX' and '{fuzzer}_id:XXXXXX'.
    """
    base = os.path.basename(name)

    m = re.search(r"((?:[a-zA-Z0-9]+_)?id:\d+)", base)
    if not m:
        raise ValueError(f"Invalid AFL seed name: {name}")

    return m.group(1)


def extract_afl_seed_id(line: str) -> str:
    _, rest = line.split(",", 1)
    base = os.path.basename(rest)
    m = re.search(r"((?:[a-zA-Z0-9]+_)?id:\d+)", base)
    if not m:
        raise ValueError(f"Cannot find seed id in line: {line}")
    return m.group(0)


def parse_score_file(path):
    parse_data = {}
    with open(path, "r") as f:
        lines = f.read().strip().splitlines()

    for line in lines[1:]:
        parts = line.split(",")

        prox_score = int(parts[-3])
        bitmap_size = int(parts[-1])

        name = extract_afl_seed_id(line)
        parse_data[name] = (prox_score, bitmap_size)
        logger.info(f"evaluator 222 - name : {name}, parse_data : {parse_data[name]}")

    return parse_data


def parse_dom_covered(output: str):
    m = re.search(r"DOM_COVERED=(\d+)", output)
    if not m:
        logger.info(f"evaluator 333 - DOM_COVERED not found in output: {output}")
        return None
    return int(m.group(1))


def run_dominator_for_seed(seed_file: str, program: str):
    args = gen_dominator_args(seed_file=seed_file, program=program)
    log_path = f"{seed_file}.dom.log"

    try:
        with open(log_path, "wb") as logf:
            result = subprocess.run(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=logf
            )
    except Exception:
        logger.exception(
            f"evaluator 334x - subprocess.run failed, seed={seed_file}, args={args}"
        )
        raise

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        log_text = f.read()

    dom_covered = parse_dom_covered(log_text)

    logger.info(
        f"evaluator 334 - dominator rc={result.returncode}, seed={seed_file}, dom_covered={dom_covered}"
    )

    return dom_covered if dom_covered is not None else 0


def evaluate_dom_covered_for_snapshot(snapshot_dir: str, program: str, alias_to_real=None):
    """
    Evaluate each staged seed in snapshot_dir with Dominator binary.
    Returns: { real_seed_id: dom_covered }
    """
    if alias_to_real is None:
        alias_to_real = {}

    dom_result = {}
    src = Path(snapshot_dir)

    for p in sorted(src.iterdir(), key=lambda x: x.name):
        if not p.is_file():
            continue
        if p.name.startswith('.') or p.name == 'README.txt':
            continue
        if '-sync' in p.name:
            continue
        if p.name.endswith('.dom.log'):
            continue

        alias_seed_id = normalize_afl_seed_id(p.name)
        real_seed_id = alias_to_real.get(alias_seed_id, alias_seed_id)

        dom_result[real_seed_id] = run_dominator_for_seed(seed_file=str(p), program=program)

        logger.info(
            f"evaluator 335 - alias_seed_id={alias_seed_id}, real_seed_id={real_seed_id}, dom_covered={dom_result[real_seed_id]}"
        )

    return dom_result


def wait_for_file(path):
    wait_time = 0
    while not os.path.exists(path):
        wait_time += 1
        time.sleep(1)
        if wait_time == 600:
            logger.info('evaluator 666 - no exists')
            break


def cleanup_score_artifacts(score_file, snapshot_dir, score_workdir):
    if os.path.exists(score_file):
        try:
            os.remove(score_file)
        except Exception:
            pass

    if os.path.exists(snapshot_dir):
        shutil.rmtree(snapshot_dir, ignore_errors=True)

    if os.path.exists(score_workdir):
        shutil.rmtree(score_workdir, ignore_errors=True)


def get_seed_model(fuzzer: str):
    f = fuzzer.lower()
    if f == "aflgo":
        return AFLGoSeed
    if f == "windranger":
        return WindRangerSeed
    if f == "dafl":
        return DAFLSeed
    raise ValueError(f"Unknown fuzzer: {fuzzer}")


# -----------------------------
# Snapshot: copy only "new" seeds for this fuzzer
# -----------------------------
def snapshot_dir_incremental(fuzzer: str, src_queue: str, dst_dir: str):
    logger.info(f'evaluator 003 - incremental snapshot: fuzzer={fuzzer}, src_queue={src_queue}, dst_dir={dst_dir}')

    SeedModel = get_seed_model(fuzzer)

    src = Path(src_queue)
    dst = Path(dst_dir)

    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True, exist_ok=True)

    staged_names = []
    alias_to_real = {}

    alias_idx = 0

    for p in sorted(src.iterdir(), key=lambda x: x.name):
        if not p.is_file():
            continue
        if p.name.startswith(".") or p.name == "README.txt":
            continue
        if p.name.endswith(".dom.log"):
            continue

        real_seed_id = normalize_afl_seed_id(p.name)

        if SeedModel.select().where(SeedModel.name == real_seed_id).exists():
            continue

        # Sync seed는 원본 seed의 score/dom 정보를 상속하지 않는다.
        # 이후 이 sync seed로부터 생성된 일반 child seed만 새로 평가/저장된다.
        if "-sync" in p.name:
            logger.info(
                f"evaluator 004s - skip sync seed without inheriting source score: {p.name}"
            )
            continue

        alias_seed_id = f"id:{alias_idx:06d}"
        alias_idx += 1

        shutil.copy2(p, dst / alias_seed_id)

        staged_names.append(real_seed_id)
        alias_to_real[alias_seed_id] = real_seed_id

        logger.info(
            f"evaluator 004x - snapshot alias: "
            f"{alias_seed_id} -> {real_seed_id}, src={p.name}"
        )

    logger.info(
        f"evaluator 004 - staged new seeds: {len(staged_names)}"
    )

    return staged_names, alias_to_real

def max_prox_from_db(fuzzer: str) -> dict:
    SeedModel = get_seed_model(fuzzer)

    prox_rows = list(
        SeedModel
        .select()
        .where(SeedModel.prox_score.is_null(False))
    )

    dom_rows = list(
        SeedModel
        .select()
        .where(SeedModel.dom_covered.is_null(False))
    )

    prox_row = max(
        prox_rows,
        key=lambda r: (
            safe_int(r.prox_score),
            safe_int(r.dom_covered),
            seed_id_num(r.name)
        ),
        default=None
    )

    dom_row = max(
        dom_rows,
        key=lambda r: (
            safe_int(r.dom_covered),
            safe_int(r.prox_score),
            seed_id_num(r.name)
        ),
        default=None
    )

    max_prox_score = safe_int(prox_row.prox_score) if prox_row else -1
    max_dom_covered = safe_int(dom_row.dom_covered) if dom_row else -1

    prox_seed_id = prox_row.name if prox_row else None
    dom_seed_id = dom_row.name if dom_row else None

    logger.info(
        f"evaluator 021 - fuzzer={fuzzer} max_prox_score={max_prox_score}, prox_seed_id={prox_seed_id}"
    )
    logger.info(
        f"evaluator 022 - fuzzer={fuzzer} max_dom_covered={max_dom_covered}, dom_seed_id={dom_seed_id}"
    )

    return {
        'max_prox_score': max_prox_score,
        'max_dom_covered': max_dom_covered
    }


def extract_score(fuzzer, seed, output_dir, program):
    logger.info(f'evaluator 001 - fuzzer : {fuzzer}, seed : {seed}, output_dir : {output_dir}, program : {program}')

    seed_path = os.path.realpath(seed)
    output_path = os.path.realpath(output_dir)

    base_dir = "/home/dcfuzz"
    score_path = os.path.join(base_dir, "initial_seed_scores.txt")

    os.makedirs(output_path, exist_ok=True)

    db_path = os.path.join(output_path, f"{fuzzer}.sqlite")
    database = peewee.SqliteDatabase(db_path)
    init_db(database)

    snapshot_input = os.path.join(output_path, "input_snapshot")

    score_workdir = os.path.join(output_path, f"_score_run_{fuzzer}_{program}")

    # delete remain file or folder
    cleanup_score_artifacts(score_file=score_path, snapshot_dir=snapshot_input, score_workdir=score_workdir)
    os.makedirs(score_workdir, exist_ok=True)

    staged_names, alias_to_real = snapshot_dir_incremental(
        fuzzer=fuzzer,
        src_queue=seed_path,
        dst_dir=snapshot_input
    )

    if not staged_names:
        max_cached = max_prox_from_db(fuzzer)
        logger.info(f"evaluator 010 - no new non-sync seeds for {fuzzer}. return max_cached={max_cached}")
        cleanup_score_artifacts(score_file=score_path, snapshot_dir=snapshot_input, score_workdir=score_workdir)
        return max_cached

    # 1) get prox_score / bitmap_size by DAFL scorer
    args = gen_run_args(seed=snapshot_input, output=score_workdir, program=program)
    logger.info(f'evaluator 002 - args : {args}')

    result = subprocess.run(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:
        logger.info(f"evaluator 9999 : afl-fuzz failed (rc={result.returncode})")
        logger.info(f"evaluator 6666 : stdout: {result.stdout}")
        logger.info(f"evaluator 6666 : stderr: {result.stderr}")

    wait_for_file(path=score_path)

    if not os.path.exists(score_path):
        max_cached = max_prox_from_db(fuzzer)
        logger.info(f"evaluator 011 - score file not created. return max_cached={max_cached}")
        cleanup_score_artifacts(score_file=score_path, snapshot_dir=snapshot_input, score_workdir=score_workdir)
        return max_cached

    alias_to_score = parse_score_file(score_path)

    name_to_score = {}
    for alias_seed_id, score_tuple in alias_to_score.items():
        real_seed_id = alias_to_real.get(alias_seed_id)

        if real_seed_id is None:
            logger.info(
                f"evaluator 223 - score alias not found in alias_to_real: {alias_seed_id}, score={score_tuple}"
            )
            continue

        name_to_score[real_seed_id] = score_tuple

    logger.info(f"evaluator 224 - converted DAFL scores: {name_to_score}")

    # 2) get DOM_COVERED per seed by Dominator binary
    name_to_dom_covered = evaluate_dom_covered_for_snapshot(
        snapshot_dir=snapshot_input,
        program=program,
        alias_to_real=alias_to_real
    )

    SeedModel = get_seed_model(fuzzer)
    with database.atomic():
        # 1. 일반 new seed 저장
        for name in staged_names:
            prox, bmsz = name_to_score.get(name, (None, None))
            dom_covered = name_to_dom_covered.get(name)

            row, _ = SeedModel.get_or_create(name=name)
            row.prox_score = prox
            row.bitmap_size = bmsz
            row.dom_covered = dom_covered
            row.save()

            logger.info(
                f"evaluator 336 - save DB name={name}, "
                f"prox={prox}, bitmap={bmsz}, dom_covered={dom_covered}"
            )

    cleanup_score_artifacts(score_file=score_path, snapshot_dir=snapshot_input, score_workdir=score_workdir)

    max_results = max_prox_from_db(fuzzer)
    logger.info(f"evaluator 020 - fuzzer={fuzzer}, max_prox_score={max_results['max_prox_score']}, max_dom_covered={max_results['max_dom_covered']}")
    return max_results
