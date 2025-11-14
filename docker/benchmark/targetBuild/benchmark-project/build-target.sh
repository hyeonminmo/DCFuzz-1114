#!/bin/bash

SCRIPT_DIR=$(dirname $(realpath $0))
BUILD=$SCRIPT_DIR/$1/build.sh

[ ! -e $BUILD ] && echo "NO SUCH FILE: $BUILD" && exit 1

#echo "*******************TAG_NAME : $TAG_NAME*******************"

RUNDIR="RUNDIR-$1"
mkdir -p $RUNDIR
cd $RUNDIR
$BUILD
