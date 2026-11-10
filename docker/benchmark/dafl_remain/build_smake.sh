#!/bin/bash

cd /
git clone https://github.com/prosyslab/smake.git smake
cd smake
git checkout 4820d08fc1e43555c2be842984d9a7043d42d07b

cd /benchmark
. $(dirname $0)/build_bench_common.sh
mkdir -p /benchmark/smake-out

# ### Program: libming-4.7
# cd /benchmark
# build_target libming-4.7 clang clang++ " "
# cd /benchmark/RUNDIR-libming-4.7/BUILD
# make clean
# yes | /smake/smake --init
# /smake/smake -j 1
# cp -r sparrow/util/swftophp /benchmark/smake-out/swftophp || exit 1

# ### Program: libming-4.7.1
# cd /benchmark
# build_target libming-4.7.1 clang clang++ " "
# cd /benchmark/RUNDIR-libming-4.7.1/BUILD
# make clean
# yes | /smake/smake --init
# /smake/smake -j 1
# cp -r sparrow/util/swftophp /benchmark/smake-out/swftophp-4.7.1 || exit 1

# ### Program: libming-4.8
# cd /benchmark
# build_target libming-4.8 clang clang++ " "
# cd /benchmark/RUNDIR-libming-4.8/BUILD
# make clean
# yes | /smake/smake --init
# /smake/smake -j 1
# cp -r sparrow/util/swftophp /benchmark/smake-out/swftophp-4.8 || exit 1

# ### Program: libming-4.8.1
# cd /benchmark
# build_target libming-4.8.1 clang clang++ " "
# cd /benchmark/RUNDIR-libming-4.8.1/BUILD
# make clean
# yes | /smake/smake --init
# /smake/smake -j 1
# cp -r sparrow/util/swftophp /benchmark/smake-out/swftophp-4.8.1 || exit 1


### Program: binutils-2.26
cd /benchmark
build_target binutils-2.26 clang clang++ " "
cd /benchmark/RUNDIR-binutils-2.26/binutils-2.26
make clean
yes | /smake/smake --init
/smake/smake -j 1
cp -r sparrow/binutils/cxxfilt /benchmark/smake-out/cxxfilt || exit 1

# ### Program: binutils-2.27
# cd /benchmark
# build_target binutils-2.27 clang clang++ " "
# cd /benchmark/RUNDIR-binutils-2.27/binutils-2.27
# make clean
# yes | /smake/smake --init
# /smake/smake -j 1
# cp -r sparrow/binutils/strip-new /benchmark/smake-out/strip || exit 1

# ### Program: binutils-2.28
# cd /benchmark
# build_target binutils-2.28 clang clang++ " "
# cd /benchmark/RUNDIR-binutils-2.28/binutils-2.28
# make clean
# yes | /smake/smake --init
# /smake/smake -j 1
# cp -r sparrow/binutils/objdump /benchmark/smake-out/objdump || exit 1

# ### Program: binutils-2.28
# cd /benchmark
# build_target binutils-2.28 clang clang++ " "
# cd /benchmark/RUNDIR-binutils-2.28/binutils-2.28
# make clean
# yes | /smake/smake --init
# /smake/smake -j 1
# cp -r sparrow/binutils/objcopy /benchmark/smake-out/objcopy || exit 1

# ### Program: binutils-2.31.1
# cd /benchmark
# build_target binutils-2.31.1 clang clang++ " "
# cd /benchmark/RUNDIR-binutils-2.31.1/binutils-2.31.1
# make clean
# yes | /smake/smake --init
# /smake/smake -j 1
# cp -r sparrow/binutils/objdump /benchmark/smake-out/objdump-2.31.1 || exit 1

# ### Program: binutils-2.29
# cd /benchmark
# build_target binutils-2.29 clang clang++ " "
# cd /benchmark/RUNDIR-binutils-2.29/binutils-2.29
# make clean
# yes | /smake/smake --init
# /smake/smake -j 1
# cp -r sparrow/binutils/nm-new /benchmark/smake-out/nm || exit 1

# ### Program: binutils-2.29
# cd /benchmark
# build_target binutils-2.29 clang clang++ " "
# cd /benchmark/RUNDIR-binutils-2.29/binutils-2.29
# make clean
# yes | /smake/smake --init
# /smake/smake -j 1
# cp -r sparrow/binutils/readelf /benchmark/smake-out/readelf || exit 1

### Program: libjpeg-1.5.90
cd /benchmark
build_target libjpeg-1.5.90 clang clang++ " "
cd /benchmark/RUNDIR-libjpeg-1.5.90/libjpeg-turbo-1.5.90
make clean
yes | /smake/smake --init
sed -i 's|/usr/local/bin/clang++|clang++|g; s|/usr/local/bin/clang|clang|g' \
    CMakeFiles/Makefile.cmake \
    CMakeFiles/*/build.make \
    sharedlib/CMakeFiles/*/build.make \
    simd/CMakeFiles/*/build.make
/smake/smake -j 1
cp -r sparrow/cjpeg-static /benchmark/smake-out/cjpeg-1.5.90 || exit 1

### Program: libjpeg-2.0.4
cd /benchmark
build_target libjpeg-2.0.4 clang clang++ " "
cd /benchmark/RUNDIR-libjpeg-2.0.4/libjpeg-turbo-2.0.4
make clean
yes | /smake/smake --init
sed -i 's|/usr/local/bin/clang++|clang++|g; s|/usr/local/bin/clang|clang|g' \
    CMakeFiles/Makefile.cmake \
    CMakeFiles/*/build.make \
    sharedlib/CMakeFiles/*/build.make \
    simd/CMakeFiles/*/build.make
/smake/smake -j 1
cp -r sparrow/cjpeg-static /benchmark/smake-out/cjpeg-2.0.4 || exit 1


# ### Program: libxml2
# cd /benchmark
# build_target libxml2-2.9.4 clang clang++ " "
# cd /benchmark/RUNDIR-libxml2-2.9.4/libxml2-2.9.4
# make clean
# yes | /smake/smake --init
# /smake/smake -j 1
# cp -r sparrow/xmllint /benchmark/smake-out/xmllint || exit 1

# ### Program: lrzip-9de7ccb
# cd /benchmark
# build_target lrzip-9de7ccb clang clang++ " "
# cd /benchmark/RUNDIR-lrzip-9de7ccb/BUILD
# make clean
# yes | /smake/smake --init
# /smake/smake -j 1
# cp -r sparrow/lrzip /benchmark/smake-out/lrzip-9de7ccb || exit 1

# ### Program: lrzip-ed51e14
# cd /benchmark
# build_target lrzip-ed51e14 clang clang++ " "
# cd /benchmark/RUNDIR-lrzip-ed51e14/BUILD
# make clean
# yes | /smake/smake --init
# /smake/smake -j 1
# cp -r sparrow/lrzip /benchmark/smake-out/lrzip-ed51e14 || exit 1

