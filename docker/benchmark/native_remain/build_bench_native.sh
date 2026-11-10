#!/bin/bash
. $(dirname $0)/build_bench_common.sh

# export NATIVE_CFLAGS="-O2 -g0 -fno-omit-frame-pointer"
# export NATIVE_CXXFLAGS="${NATIVE_CFLAGS}"

# arg1 : Target project
# arg2~: Fuzzing targets
function build_with_Native() {
    for TARG in "${@:2}"; do
        str_array=($TARG)
        BIN_NAME=${str_array[0]}

        cd /benchmark

        for BUG_NAME in "${str_array[@]:1}"; do
            echo "$BIN_NAME $BUG_NAME"
            build_target_native $1 "clang" "clang++" "-O2 -g0 -fno-omit-frame-pointer -Wno-error" $BIN_NAME $BUG_NAME 
            copy_build_result $1 $BIN_NAME $BUG_NAME "NATIVE"
            mv /benchmark/RUNDIR-$1 /info/native/run_$BIN_NAME-$BUG_NAME
            rm -rf RUNDIR-$1|| exit 1
        done
    done
}

# Build with native only
mkdir -p /benchmark/bin/NATIVE
mkdir -p /info/native

# build_with_Native "libming-4.7" \
#     "swftophp 2016-9827 2016-9829 2016-9831 2017-9988 2017-11728 2017-11729" 
# build_with_Native "libming-4.8" \
#     "swftophp 2018-7868 2018-8807 2018-8962 2018-11225 2018-11226 2020-6628 2018-20427 2019-12982" 
# build_with_Native "libming-4.8.1" \
#     "swftophp 2019-9114" 
# wait

# build_with_Native "binutils-2.26" \
#     "cxxfilt 2016-4489 2016-4490 2016-4491 2016-4492 2016-6131" 
# build_with_Native "binutils-2.28" \
#     "objdump 2017-8392 2017-8396 2017-8397 2017-8398" 
# build_with_Native "binutils-2.29" "nm 2017-14940" 

# ## remain
# build_with_Native "binutils-2.26" \
#     "cxxfilt 2016-4487" 
# build_with_Native "binutils-2.28" \
#     "objcopy 2017-8393 2017-8394 2017-8395"
# build_with_Native "binutils-2.29" \
#     "readelf 2017-16828"
# build_with_Native "binutils-2.31.1" \
#     "objdump 2018-17360"
# build_with_Native "binutils-2.27" \
#     "strip 2017-7303"

# build_with_Native "libjpeg-1.5.90" \
#     "cjpeg 2018-14498"
# build_with_Native "libjpeg-2.0.4" \
#     "cjpeg 2020-13790"
build_with_Native "libxml2-2.9.4" \
    "xmllint 2017-5969 2017-9047 2017-9048" 
# build_with_Native "libming-4.7.1" \
#     "swftophp 2017-7578"
# build_with_Native "libming-4.8" \
#     "swftophp 2018-11095"
# build_with_Native "lrzip-9de7ccb" \
#     "lrzip 2017-8846"
# build_with_Native "lrzip-ed51e14" \
#     "lrzip 2018-11496"
   
wait