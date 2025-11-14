#!/bin/bash
. $(dirname $0)/build_bench_common.sh

# arg1 : Target project
# arg2~: Fuzzing targets
function build_with_ASAN() {
    build_target $1 "clang" "clang++" "$ASAN_FLAGS"
    for TARG in "${@:2}"; do
        str_array=($TARG)
        BIN_NAME=${str_array[0]}
        for BUG_NAME in "${str_array[@]:1}"; do
            copy_build_result $1 $BIN_NAME $BUG_NAME "ASAN"
        done
    done
    rm -rf RUNDIR-$1 || exit 1
}



# Build with ASAN only
mkdir -p /benchmark/bin/ASAN
build_with_ASAN "libming-4.7" \
    "swftophp 2016-9827 2016-9829 2016-9831 2017-9988 2017-11728 2017-11729" $
build_with_ASAN "libming-4.8" \
    "swftophp 2018-7868 2018-8807 2018-8962 2018-11225 2018-11226 2020-6628 2018-20427 2019-12982" &
build_with_ASAN "libming-4.8.1" \
    "swftophp-4.8.1 2019-9114" &
wait

build_with_ASAN "binutils-2.26" \
    "cxxfilt 2016-4487 2016-4489 2016-4490 2016-4491 2016-4492 2016-6131 \
            2016-4489-crash 2016-4489-caller 2016-4492-crash1 2016-4492-crash2" &
build_with_ASAN "binutils-2.28" \
    "objdump 2017-8392 2017-8396 2017-8397 2017-8398" &
build_with_ASAN "binutils-2.29" "nm 2017-14940" &

wait