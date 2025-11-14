#!/bin/bash

build_lib() {
  rm -rf BUILD
  cp -rf SRC BUILD
  (cd BUILD && ./autogen.sh && ./configure --disable-shared --disable-freetype && make)
}

echo "*****************libming-4.7 file *************************"

GIT_URL="https://github.com/libming/libming.git"
TAG_NAME="ming-0_4_7"
RELEVANT_BINARIES="swftophp"

[ ! -e SRC ] && git clone $GIT_URL SRC
cd SRC
git checkout $TAG_NAME
cd ..

build_lib

echo "BUILD/util Directory :"

echo $(ls BUILD/util)

echo "CC : $CC"
echo "CXX : $CXX"
echo "LLVM_COMPILER : $LLVM_COMPILER"
echo "CFLAGS: $CFLAGS"

echo "**********************************************************************************"

#sleep 3600


for binary in $RELEVANT_BINARIES; do
  cp BUILD/util/$binary ./$binary
done
