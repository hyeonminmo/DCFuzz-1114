#!/bin/bash

cd /
git clone https://github.com/prosyslab/smake.git smake
cd smake
git checkout 4820d08fc1e43555c2be842984d9a7043d42d07b

cd /benchmark
. $(dirname $0)/build_bench_common.sh
mkdir -p /benchmark/smake-out

### Program: libming-4.7
cd /benchmark
build_target libming-4.7 clang clang++ " "
cd /benchmark/RUNDIR-libming-4.7/BUILD
make clean
yes | /smake/smake --init
/smake/smake -j 1
cp -r sparrow/util/swftophp /benchmark/smake-out/swftophp || exit 1


### Program: binutils-2.26
cd /benchmark
build_target binutils-2.26 clang clang++ " "
cd /benchmark/RUNDIR-binutils-2.26/binutils-2.26
make clean
yes | /smake/smake --init
/smake/smake -j 1
cp -r sparrow/binutils/cxxfilt /benchmark/smake-out/cxxfilt || exit 1


