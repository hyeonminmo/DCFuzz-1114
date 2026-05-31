#!/bin/bash
set -euo pipefail

. $(dirname "$0")/build_bench_common.sh

# arg1 : Target project
# arg2~: Fuzzing targets
function build_with_Dominator() {
    for TARG in "$@"; do
        local str_array=($TARG)
        local BIN_NAME=${str_array[0]}

        cd /benchmark
        TMP_DIR=/benchmark/temp_$1

        for BUG_NAME in "${str_array[@]:1}"; do
            echo "[dominator-build] ==================================================" >&2
            echo "[dominator-build] project=$1 bin=$BIN_NAME bug=$BUG_NAME" >&2
            echo "[dominator-build] ==================================================" >&2
            INFO_DIR=/info/dominator/temp_$BIN_NAME-$BUG_NAME

            mkdir -p $TMP_DIR

            ###################################################################
            # extract_valid_paths.py 실행 - target까지의 context-sensitive valid-path 추출
            ###################################################################
            local TARGET_LINE
            TARGET_LINE="$(grep -v '^[[:space:]]*$' "$INFO_DIR/BBtargets.txt" \
                | grep -v '^[[:space:]]*#' \
                | head -n 1 \
                | xargs)"

            echo "[dominator-build] extract valid paths for target=$TARGET_LINE" >&2

            : > "$INFO_DIR/valid_paths.txt"
            : > "$INFO_DIR/extract_valid_paths.log"

            echo "[dominator-build] extract valid paths for target=$TARGET_LINE" >&2

            python3 "$DOM_SCRIPT_DIR/extract_valid_paths.py" \
                --icfg-dir "$INFO_DIR" \
                --module-ll "$INFO_DIR/module.ll" \
                --target "$TARGET_LINE" \
                --dominator-nodes "$INFO_DIR/dominator_nodes.txt" \
                > "$TMP_DIR/valid_paths.txt" \
                2> "$TMP_DIR/extract_valid_paths.log" || {
                    echo "[dominator-build] ERROR: extract_valid_paths.py failed for target=$TARGET_LINE" >&2
                    echo "[dominator-build] ===== extract_valid_paths.log =====" >&2
                    cat "$TMP_DIR/extract_valid_paths.log" >&2 || true
                    echo "[dominator-build] ===== valid_paths.txt =====" >&2
                    cat "$TMP_DIR/valid_paths.txt" >&2 || true
                    exit 1
                }
            mv $TMP_DIR /info/dominator/temp_$BIN_NAME-$BUG_NAME

            rm -rf $TMP_DIR
        done
    done
}

export DOM_SCRIPT_DIR="/benchmark/script"

# build_with_Dominator "libming-4.7" \
#     "swftophp 2016-9827 "

# build_with_Dominator "libming-4.7" \
#     "swftophp 2016-9827 2016-9829 2016-9831 2017-9988 2017-11728 2017-11729"
# build_with_Dominator "libming-4.8" \
#     "swftophp 2018-7868 2018-8807 2018-8962 2018-11225 2018-11226 2020-6628 2018-20427 2019-12982"
# build_with_Dominator "libming-4.8.1" \
#     "swftophp 2019-9114"
# build_with_Dominator "binutils-2.26" \
#     "cxxfilt 2016-4489 2016-4490 2016-4491 2016-4492 2016-6131"
# build_with_Dominator "binutils-2.28" \
#    "objdump 2017-8392 2017-8396 2017-8397 2017-8398"
# build_with_Dominator "binutils-2.29" \
#     "nm 2017-14940"

wait
