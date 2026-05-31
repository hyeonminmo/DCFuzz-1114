#!/bin/bash
set -euo pipefail

. $(dirname "$0")/build_bench_common.sh

function require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[dominator-build] ERROR: required command not found: $cmd" >&2
        exit 1
    fi
}

function find_precodegen_bc() {
    local project="$1"
    local bin_name="$2"
    local rundir="/benchmark/RUNDIR-$project"

    if find "$rundir" -name "*${bin_name}*precodegen.bc" | grep -q .; then
        find "$rundir" -name "*${bin_name}*precodegen.bc" | head -n 1
        return 0
    fi

    if find "$rundir" -name "*precodegen.bc" | grep -q .; then
        find "$rundir" -name "*precodegen.bc" -printf '%s %p\n' \
            | sort -nr | head -n 1 | cut -d' ' -f2-
        return 0
    fi

    return 1
}

# arg1 : Target project
# arg2~: Fuzzing targets
function build_with_Dominator() {
    for TARG in "$@"; do
        local str_array=($TARG)
        local BIN_NAME=${str_array[0]}

        cd /benchmark

        CC="/fuzzer/AFLGo/afl-clang-fast"
        CXX="/fuzzer/AFLGo/afl-clang-fast++"
        TMP_DIR=/benchmark/temp_$1

        for BUG_NAME in "${str_array[@]:1}"; do
            echo "[dominator-build] ==================================================" >&2
            echo "[dominator-build] project=$1 bin=$BIN_NAME bug=$BUG_NAME" >&2
            echo "[dominator-build] ==================================================" >&2

            mkdir -p $TMP_DIR

            cp "/benchmark/target/line/$BIN_NAME/$BUG_NAME" "$TMP_DIR/BBtargets.txt"

            ###################################################################
            # 1. AFLGo 1차 build 수행: BBnames / BBcalls 생성 목적
            ###################################################################
            CC_AFLGO="/fuzzer/AFLGo/afl-clang-fast"
            CXX_AFLGO="/fuzzer/AFLGo/afl-clang-fast++"

            ADDITIONAL_AFLGO="-g -targets=$TMP_DIR/BBtargets.txt \
                                -outdir=$TMP_DIR -flto -fuse-ld=gold \
                                -Wl,-plugin-opt=save-temps"

            build_target $1 $CC_AFLGO $CXX_AFLGO "$ADDITIONAL_AFLGO"

            # AFLGo 산출물 정리
            if [ -f "$TMP_DIR/BBnames.txt" ]; then
                cp "$TMP_DIR/BBnames.txt" "$TMP_DIR/BBnames.raw.txt"
                rev "$TMP_DIR/BBnames.txt" | cut -d: -f2- | rev | sort | uniq \
                    > "$TMP_DIR/BBnames2.txt"
                mv "$TMP_DIR/BBnames2.txt" "$TMP_DIR/BBnames.txt"
            fi

            if [ -f "$TMP_DIR/BBcalls.txt" ]; then
                cp "$TMP_DIR/BBcalls.txt" "$TMP_DIR/BBcalls.raw.txt"
                sort "$TMP_DIR/BBcalls.txt" | uniq > "$TMP_DIR/BBcalls2.txt"
                mv "$TMP_DIR/BBcalls2.txt" "$TMP_DIR/BBcalls.txt"
            fi

            # AFLGo build directory 제거
            rm -rf /benchmark/RUNDIR-$1

            ###################################################################
            # 2. SVF 분석용 clean LLVM build 수행
            ###################################################################
            CC_SVF="clang-12"
            CXX_SVF="clang++-12"

            ADDITIONAL_SVF="-g -flto -fuse-ld=gold \
                            -Wl,-plugin-opt=save-temps"

            build_target $1 $CC_SVF $CXX_SVF "$ADDITIONAL_SVF"

            local BCFILE=""
            BCFILE="$(find_precodegen_bc "$1" "$BIN_NAME" || true)"
            echo "$BCFILE" > "$TMP_DIR/bcfile.txt"

            if [ -z "$BCFILE" ] || [ ! -f "$BCFILE" ]; then
                echo "[dominator-build] ERROR: clean precodegen.bc not found for $BIN_NAME-$BUG_NAME" >&2
                exit 1
            fi

            cp "$BCFILE" "$TMP_DIR/module.bc"
            llvm-dis-12 "$TMP_DIR/module.bc" -o "$TMP_DIR/module.ll"

            ###################################################################
            # 3. SVF wpa 실행
            ###################################################################
            require_cmd wpa
            mkdir -p "$TMP_DIR/svf"

            (
                cd "$TMP_DIR/svf"
                wpa -ander -dump-icfg -dump-callgraph "$TMP_DIR/module.bc" \
                    > "$TMP_DIR/svf_wpa.log" 2>&1
            ) || {
                echo "[dominator-build] ERROR: SVF wpa failed" >&2
                cat "$TMP_DIR/svf_wpa.log" >&2
                exit 1
            }

            ###################################################################
            # 4. normalize_svf_icfg.py 실행
            # module.ll 또는 bitcode에서 ICFG 입력 데이터(nodes, intra edges, call edges, return edges, call-return mapping φ) 를 생성하도록 변경
            ###################################################################
            python3 "$DOM_SCRIPT_DIR/normalize_svf_icfg.py" \
                --svf-dir "$TMP_DIR/svf" \
                --module-bc "$TMP_DIR/module.bc" \
                --module-ll "$TMP_DIR/module.ll" \
                --bbnames "$TMP_DIR/BBnames.txt" \
                --bbcalls "$TMP_DIR/BBcalls.txt" \
                --targets "$TMP_DIR/BBtargets.txt" \
                --outdir "$TMP_DIR" \
                > "$TMP_DIR/normalize_svf_icfg.log" 2>&1

            ###################################################################
            # 5. extract_dominator.py 실행 - ICFG 기반 dominator 추출
            ###################################################################
            : > "$TMP_DIR/dominator_nodes.txt"
            : > "$TMP_DIR/extract_dominator.log"

            local TARGET_LINE
            TARGET_LINE="$(grep -v '^[[:space:]]*$' "$TMP_DIR/BBtargets.txt" \
                | grep -v '^[[:space:]]*#' \
                | head -n 1 \
                | xargs)"
            echo "[dominator-build] extract dominators for target=$TARGET_LINE" >&2

            python3 "$DOM_SCRIPT_DIR/extract_dominator.py" \
                --icfg-dir "$TMP_DIR" \
                --module-ll "$TMP_DIR/module.ll" \
                --target "$TARGET_LINE" \
                > "$TMP_DIR/dominator_nodes.txt" \
                2> "$TMP_DIR/extract_dominator.log" 

            ###################################################################
            # 6. make_dominator.py 실행
            ###################################################################
            python3 "$DOM_SCRIPT_DIR/make_dominator.py" \
                "$TMP_DIR/dominator_nodes.txt" \
                "$TMP_DIR/dominator_map.tsv" \
                > "$TMP_DIR/make_dominator.log" 2>&1

            ###################################################################
            # 7. 결과 저장
            ###################################################################
            mv /benchmark/RUNDIR-$1 /info/dominator/run_$BIN_NAME-$BUG_NAME
            mv $TMP_DIR /info/dominator/temp_$BIN_NAME-$BUG_NAME

            rm -rf $TMP_DIR
            rm -rf /benchmark/RUNDIR-$1
        done
    done
}

export DOM_SCRIPT_DIR="/benchmark/script"

require_cmd llvm-dis-12
require_cmd python3

for script in normalize_svf_icfg.py extract_dominator.py make_dominator.py; do
    if [ ! -f "$DOM_SCRIPT_DIR/$script" ]; then
        echo "[dominator-build] ERROR: missing script: $DOM_SCRIPT_DIR/$script" >&2
        exit 1
    fi
done

mkdir -p /benchmark/bin/Dominator
mkdir -p /info/dominator

# build_with_Dominator "libming-4.7" \
#     "objdump 2017-8392 2017-8396 2017-8397 2017-8398"

# build_with_Dominator "libming-4.7" \
#     "swftophp 2016-9827 2016-9829 2016-9831 2017-9988 2017-11728 2017-11729"
# build_with_Dominator "libming-4.8" \
#     "swftophp 2018-7868 2018-8807 2018-8962 2018-11225 2018-11226 2020-6628 2018-20427 2019-12982"
# build_with_Dominator "libming-4.8.1" \
#     "swftophp 2019-9114"
# build_with_Dominator "binutils-2.26" \
#     "cxxfilt 2016-4489 2016-4490 2016-4491 2016-4492 2016-6131"
build_with_Dominator "binutils-2.28" \
   "objdump 2017-8392" #2017-8396 2017-8397 2017-8398"
# build_with_Dominator "binutils-2.29" \
#     "nm 2017-14940"


wait
