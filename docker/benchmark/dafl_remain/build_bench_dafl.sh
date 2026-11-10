#!/bin/bash

. $(dirname $0)/build_bench_common.sh

# arg1 : Target project
# arg2~: Fuzzing targets
function build_with_DAFL() {

    for TARG in "${@:2}"; do
        str_array=($TARG)
        BIN_NAME=${str_array[0]}

        # Run Sparrow per target binary.
        if [ "$1" = "libming-4.8" ]; then
            python3 /benchmark/scripts/run_sparrow.py "${BIN_NAME}-4.8"
        elif [ "$1" = "libming-4.8.1" ]; then
            python3 /benchmark/scripts/run_sparrow.py "${BIN_NAME}-4.8.1"
        elif [ "$1" = "libming-4.7.1" ]; then
            python3 /benchmark/scripts/run_sparrow.py "${BIN_NAME}-4.7.1"
        elif [ "$1" = "binutils-2.31.1" ]; then
            python3 /benchmark/scripts/run_sparrow.py "${BIN_NAME}-2.31.1"
        elif [ "$1" = "libjpeg-1.5.90" ]; then
            python3 /benchmark/scripts/run_sparrow_cjpeg.py "${BIN_NAME}-1.5.90"
        elif [ "$1" = "libjpeg-2.0.4" ]; then
            python3 /benchmark/scripts/run_sparrow_cjpeg.py "${BIN_NAME}-2.0.4"
        elif [ "$1" = "lrzip-9de7ccb" ]; then
            python3 /benchmark/scripts/run_sparrow.py "${BIN_NAME}-9de7ccb"
        elif [ "$1" = "lrzip-ed51e14" ]; then
            python3 /benchmark/scripts/run_sparrow.py "${BIN_NAME}-ed51e14"
        else
            python3 /benchmark/scripts/run_sparrow.py "${BIN_NAME}"           
        fi
#    done
# }        
        #python3 /benchmark/scripts/run_sparrow.py $BIN_NAME

        cd /benchmark
        CC="/fuzzer/DAFL/afl-clang-fast"
        CXX="/fuzzer/DAFL/afl-clang-fast++"
        
        for BUG_NAME in "${str_array[@]:1}"; do
            if [ "$1" = "libming-4.8" ]; then
                export DAFL_SELECTIVE_COV="/benchmark/DAFL-input/inst-targ/${BIN_NAME}-4.8/$BUG_NAME"
                export DAFL_DFG_SCORE="/benchmark/DAFL-input/dfg/${BIN_NAME}-4.8/$BUG_NAME" 
            elif [ "$1" = "libming-4.8.1" ]; then
                export DAFL_SELECTIVE_COV="/benchmark/DAFL-input/inst-targ/${BIN_NAME}-4.8.1/$BUG_NAME"
                export DAFL_DFG_SCORE="/benchmark/DAFL-input/dfg/${BIN_NAME}-4.8.1/$BUG_NAME"
            elif [ "$1" = "libming-4.7.1" ]; then
                export DAFL_SELECTIVE_COV="/benchmark/DAFL-input/inst-targ/${BIN_NAME}-4.7.1/$BUG_NAME"
                export DAFL_DFG_SCORE="/benchmark/DAFL-input/dfg/${BIN_NAME}-4.7.1/$BUG_NAME"
            elif [ "$1" = "binutils-2.31.1" ]; then
                export DAFL_SELECTIVE_COV="/benchmark/DAFL-input/inst-targ/${BIN_NAME}-2.31.1/$BUG_NAME"
                export DAFL_DFG_SCORE="/benchmark/DAFL-input/dfg/${BIN_NAME}-2.31.1/$BUG_NAME"
            elif [ "$1" = "libjpeg-1.5.90" ]; then
                export DAFL_SELECTIVE_COV="/benchmark/DAFL-input/inst-targ/${BIN_NAME}-1.5.90/$BUG_NAME"
                export DAFL_DFG_SCORE="/benchmark/DAFL-input/dfg/${BIN_NAME}-1.5.90/$BUG_NAME"
            elif [ "$1" = "libjpeg-2.0.4" ]; then
                export DAFL_SELECTIVE_COV="/benchmark/DAFL-input/inst-targ/${BIN_NAME}-2.0.4/$BUG_NAME"
                export DAFL_DFG_SCORE="/benchmark/DAFL-input/dfg/${BIN_NAME}-2.0.4/$BUG_NAME"
            elif [ "$1" = "lrzip-9de7ccb" ]; then
                export DAFL_SELECTIVE_COV="/benchmark/DAFL-input/inst-targ/${BIN_NAME}-9de7ccb/$BUG_NAME"
                export DAFL_DFG_SCORE="/benchmark/DAFL-input/dfg/${BIN_NAME}-9de7ccb/$BUG_NAME"
            elif [ "$1" = "lrzip-ed51e14" ]; then
                export DAFL_SELECTIVE_COV="/benchmark/DAFL-input/inst-targ/${BIN_NAME}-ed51e14/$BUG_NAME"
                export DAFL_DFG_SCORE="/benchmark/DAFL-input/dfg/${BIN_NAME}-ed51e14/$BUG_NAME"
            else
                export DAFL_SELECTIVE_COV="/benchmark/DAFL-input/inst-targ/${BIN_NAME}/$BUG_NAME"
                export DAFL_DFG_SCORE="/benchmark/DAFL-input/dfg/${BIN_NAME}/$BUG_NAME"        
            fi    
            
            # Build with ASAN disabled.
            if [ -d "RUNDIR-$1" ]; then
                mv RUNDIR-* /info/dafl/
            fi
            build_target $1 $CC $CXX " "
            copy_build_result $1 $BIN_NAME $BUG_NAME "DAFL"
            # rm -rf RUNDIR-$1
        done

    done
}

# Build with DAFL
mkdir -p /benchmark/build_log
mkdir -p /benchmark/bin/DAFL

# build_with_DAFL "libming-4.7" \
#     "swftophp 2016-9827 2016-9829 2016-9831 2017-9988 2017-11728 2017-11729" 
# build_with_DAFL "libming-4.8" \
#     "swftophp 2018-7868 2018-8807 2018-8962 2018-11225 2018-11226 2018-20427 2019-12982 2020-6628"
# build_with_DAFL "libming-4.8.1" "swftophp 2019-9114"

# wait

# build_with_DAFL "binutils-2.26" \
#     "cxxfilt 2016-4487 2016-4489 2016-4490 2016-4491 2016-4492 2016-6131 2016-4489-crash 2016-4492-crash2" 
# build_with_DAFL "binutils-2.28" \
#    "objdump 2017-8392 2017-8396 2017-8397 2017-8398"
# build_with_DAFL "binutils-2.29" "nm 2017-14940"

# wait

# ## remain
# build_with_DAFL "binutils-2.26" \
#     "cxxfilt 2016-4487" 
# build_with_DAFL "binutils-2.28" \
#     "objcopy 2017-8393 2017-8394 2017-8395"
# build_with_DAFL "binutils-2.29" \
#     "readelf 2017-16828"
# build_with_DAFL "binutils-2.31.1" \
#     "objdump 2018-17360"
# build_with_DAFL "binutils-2.27" \
#     "strip 2017-7303"

# build_with_DAFL "libjpeg-1.5.90" \
#     "cjpeg 2018-14498"
build_with_DAFL "libjpeg-2.0.4" \
    "cjpeg 2020-13790"
# build_with_DAFL "libxml2-2.9.4" \
#     "xmllint 2017-5969 2017-9047 2017-9048" 
# build_with_DAFL "libming-4.7.1" \
#     "swftophp 2017-7578"
# build_with_DAFL "libming-4.8" \
#     "swftophp 2018-11095"
# build_with_DAFL "lrzip-9de7ccb" \
#     "lrzip 2017-8846"
# build_with_DAFL "lrzip-ed51e14" \
#     "lrzip 2018-11496"
# build_with_DAFL "libxml2-2.9.4" \
#     "xmllint 2017-5969" 
# build_with_DAFL "libxml2-2.9.4" \
#     "xmllint 2017-9047" 
# build_with_DAFL "libxml2-2.9.4" \
#     "xmllint 2017-9048"    
# wait


# cp /benchmark/bin/DAFL/cxxfilt-2016-4489 /benchmark/bin/DAFL/cxxfilt-2016-4489-caller
# cp /benchmark/bin/DAFL/cxxfilt-2016-4492 /benchmark/bin/DAFL/cxxfilt-2016-4492-crash1