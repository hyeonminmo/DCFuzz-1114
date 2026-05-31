#!/bin/bash
set -euo pipefail

. $(dirname "$0")/build_bench_common.sh

PASS_SO="/fuzzer/Dominator/libDominatorCoveragePass.so"
RUNTIME_SRC="/fuzzer/Dominator/dominator_runtime.c"

function count_dominators() {
    local map="$1"

    awk -F'\t' '
        NF >= 3 {
            id = $1 + 0
            if (!seen || id > max) max = id
            seen = 1
        }
        END {
            if (seen) print max + 1
            else print 0
        }
    ' "$map"
}

function make_lto_wrapper() {
    local out="$1"
    local real="$2"
    local pass_so="$3"
    local dom_map="$4"
    local runtime_obj="$5"

    cat > "$out" <<EOF
#!/bin/bash
set -e

REAL="$real"
PASS_SO="$pass_so"
DOM_MAP="$dom_map"
RUNTIME_OBJ="$runtime_obj"

compile_only=0
has_lto=0
is_configure_test=0
info_query=0
no_codegen=0

for a in "\$@"; do
    case "\$a" in
        -c|-S)
            compile_only=1
            ;;
        -E|-M|-MM)
            no_codegen=1
            ;;
        -flto|-flto=*)
            has_lto=1
            ;;
        *conftest*)
            is_configure_test=1
            ;;
        --version|-v|-V|-qversion|-dumpmachine|-dumpversion|-print-*)
            info_query=1
            ;;
    esac
done

# configure test, version query, preprocessing/dependency generation에는 pass를 붙이지 않음
if [ "\$is_configure_test" -eq 1 ] || [ "\$info_query" -eq 1 ] || [ "\$no_codegen" -eq 1 ]; then
    exec "\$REAL" "\$@"
fi

# 실제 소스 컴파일 단계에서 pass 로드
# -dominator-map은 LLVM pass 옵션이므로 -mllvm으로 전달
if [ "\$compile_only" -eq 1 ] && [ "\$has_lto" -eq 1 ]; then
    exec "\$REAL" "\$@" \\
        -Xclang -load -Xclang "\$PASS_SO" \\
        -mllvm "-dominator-map=\$DOM_MAP"
fi

# 일반 compile-only는 그대로 수행
if [ "\$compile_only" -eq 1 ]; then
    exec "\$REAL" "\$@"
fi

# link 단계에서는 pass를 로드하지 말고 runtime만 링크
exec "\$REAL" "\$@" "\$RUNTIME_OBJ"
EOF

    chmod +x "$out"
}

# arg1 : Target project
# arg2~: Fuzzing targets
function build_with_Dominator() {
    local PROJECT="$1"
    shift

    for TARG in "$@"; do
        local str_array=($TARG)
        local BIN_NAME=${str_array[0]}

        cd /benchmark

        TMP_DIR=/benchmark/temp_$PROJECT

        for BUG_NAME in "${str_array[@]:1}"; do
            echo "[dominator-build] ==================================================" >&2
            echo "[dominator-build] project=$PROJECT bin=$BIN_NAME bug=$BUG_NAME" >&2
            echo "[dominator-build] ==================================================" >&2

            local INFO_DIR="/info/dominator/temp_${BIN_NAME}-${BUG_NAME}"
            local DOM_MAP="$INFO_DIR/dominator_map.tsv"

            mkdir -p "$TMP_DIR"

            ###################################################################
            # 1. dominator_map.tsv의 ID 개수 계산
            ###################################################################
            local DOM_NUM
            DOM_NUM="$(count_dominators "$DOM_MAP")"

            if [ "$DOM_NUM" -le 0 ]; then
                echo "[dominator-build] ERROR: empty dominator map: $DOM_MAP" >&2
                exit 1
            fi

            ###################################################################
            # 2. dominator_runtime.c 컴파일
            ###################################################################
            RUNTIME_OBJ="$TMP_DIR/dominator_runtime.o"

            clang-12 -O2 -c \
                -DDOMINATOR_NUM="$DOM_NUM" \
                "$RUNTIME_SRC" \
                -o "$RUNTIME_OBJ"

            ###################################################################
            # 3. LTO link 단계에서 DominatorCoveragePass를 로드하는 wrapper 생성
            ###################################################################
            local CC_DOM="$TMP_DIR/dom-clang"
            local CXX_DOM="$TMP_DIR/dom-clang++"

            local REAL_CC="$(command -v clang-12)"
            local REAL_CXX="$(command -v clang++-12)"

            make_lto_wrapper "$CC_DOM" "$REAL_CC" "$PASS_SO" "$DOM_MAP" "$RUNTIME_OBJ"
            make_lto_wrapper "$CXX_DOM" "$REAL_CXX" "$PASS_SO" "$DOM_MAP" "$RUNTIME_OBJ"

            ###################################################################
            # 4. dominator_map.tsv 기반 대상 프로그램 재빌드
            ###################################################################
            rm -rf /benchmark/RUNDIR-$PROJECT

            ADDITIONAL_DOM="-g -flto -fuse-ld=gold \
                            -Wl,-plugin-opt=save-temps"

            build_target "$PROJECT" "$CC_DOM" "$CXX_DOM" "$ADDITIONAL_DOM" \
                > "$TMP_DIR/build_dominator.log" 2>&1 || {
                    echo "[dominator-build] ERROR: build_target failed" >&2
                    cat "$TMP_DIR/build_dominator.log" >&2 || true
                    exit 1
                }

            ###################################################################
            # 5. DCFuzz에서 실행할 계측 binary 복사
            ###################################################################
            copy_build_result "$PROJECT" "$BIN_NAME" "$BUG_NAME" "Dominator"

            ###################################################################
            # 6. 빌드 결과 저장
            ###################################################################
            cp "$TMP_DIR/build_dominator.log" "$INFO_DIR/build_dominator.log"
            cp "$RUNTIME_OBJ" "$INFO_DIR/dominator_runtime.o"
            
            rm -rf /info/dominator/run_$BIN_NAME-$BUG_NAME
            mv /benchmark/RUNDIR-$PROJECT /info/dominator/run_$BIN_NAME-$BUG_NAME

            rm -rf "$TMP_DIR"
            rm -rf /benchmark/RUNDIR-$PROJECT
        done
    done
}

mkdir -p /benchmark/bin/Dominator

# build_with_Dominator "libming-4.7" \
#     "swftophp 2016-9827 2016-9829 2016-9831 2017-9988 2017-11728 2017-11729"
# build_with_Dominator "libming-4.8" \
#     "swftophp 2018-7868 2018-8807 2018-8962 2018-11225 2018-11226 2020-6628 2018-20427 2019-12982"
# build_with_Dominator "libming-4.8.1" \
#     "swftophp 2019-9114"
build_with_Dominator "binutils-2.26" \
    "cxxfilt 2016-4489 2016-4490 2016-4491 2016-4492 2016-6131"
# build_with_Dominator "binutils-2.28" \
#    "objdump 2017-8392 2017-8396 2017-8397 2017-8398"
# build_with_Dominator "binutils-2.29" \
#     "nm 2017-14940"
wait