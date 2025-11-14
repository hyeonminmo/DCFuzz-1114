#!/bin/bash

. $(dirname $0)/build_bench_common.sh
set -x
# arg1 : Target project
# arg2 : Compiler to use for the final build.
# arg3 : Additional compiler options (e.g. LDFLAGS) for the final build.
# arg4~: fuzzing target string
function build_with_WindRanger() {

    for TARG in "${@:4}"; do
        str_array=($TARG)
        BIN_NAME=${str_array[0]}

        arr=(${BIN_NAME//-/ })
        SIMPLE_BIN_NAME=${arr[0]}
	
        cd /benchmark
        CC="/root/go/bin/gclang"
        CXX="/root/go/bin/gclang++"

        build_target $1 $CC $CXX ""

        cd RUNDIR-$1
        get-bc $BIN_NAME || exit 1
	    #get-bc $BIN_NAME


        for BUG_NAME in "${str_array[@]:1}"; do
            /fuzzer/WindRanger/instrument/bin/cbi --targets=/benchmark/target/line/$BIN_NAME/$BUG_NAME ./$BIN_NAME.bc
            ### ASAN disabled
            $2 ./$BIN_NAME.ci.bc $3 -o ./$BIN_NAME-$BUG_NAME
            cp ./$BIN_NAME-$BUG_NAME /benchmark/bin/WindRanger/$BIN_NAME-$BUG_NAME
            cp ./distance.txt /benchmark/bin/WindRanger/$BIN_NAME-$BUG_NAME-distance.txt
            cp ./targets.txt /benchmark/bin/WindRanger/$BIN_NAME-$BUG_NAME-targets.txt
            cp ./condition_info.txt /benchmark/bin/WindRanger/$BIN_NAME-$BUG_NAME-condition_info.txt
        done
        cd ..
        ### copy rundir to info dir
        cp -r RUNDIR-$1 /info/WindRanger/$BIN_NAME-$BUG_NAME
        rm -rf RUNDIR-$1 || exit 1
    done

}

export PATH=/fuzzer/WindRanger/clang+llvm/bin:$PATH
export PATH=/root/go/bin:$PATH

# Build with Beacon
mkdir -p /benchmark/bin/WindRanger
build_with_WindRanger "libming-4.7" "/fuzzer/WindRanger/fuzz/afl-clang-fast" "-lm -lz" \
    "swftophp 2016-9827 2016-9829 2016-9831 2017-9988 2017-11728 2017-11729" &
build_with_WindRanger "libming-4.8" "/fuzzer/WindRanger/fuzz/afl-clang-fast" "-lm -lz" \
    "swftophp 2018-7868 2018-8807 2018-8962 2018-11225 2018-11226 2020-6628 2018-20427 2019-12982" &
build_with_WindRanger "libming-4.8.1" "/fuzzer/WindRanger/fuzz/afl-clang-fast" "-lm -lz" \
    "swftophp-4.8.1 2019-9114" &
build_with_WindRanger "binutils-2.26" "/fuzzer/WindRanger/fuzz/afl-clang-fast" "-ldl" \
    "cxxfilt 2016-4487 2016-4489 2016-4490 2016-4491 2016-4492 2016-6131 \
             2016-4489-crash 2016-4489-caller 2016-4492-crash1 2016-4492-crash2" &
build_with_WindRanger "binutils-2.28" "/fuzzer/WindRanger/fuzz/afl-clang-fast" "-ldl" \
    "objdump 2017-8392 2017-8396 2017-8397 2017-8398" &
build_with_WindRanger "binutils-2.29" "/fuzzer/WindRanger/fuzz/afl-clang-fast" "-ldl -fsanitize=address" \
    "nm 2017-14940" &


wait
