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

cp -r /benchmark/project/libming-4.7/SRC ./

build_lib

echo "dir : $(pwd)"

for binary in $RELEVANT_BINARIES; do
  cp BUILD/util/$binary ./$binary
done
