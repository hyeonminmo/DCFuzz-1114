#!/bin/bash
URL="http://ftp.gnu.org/gnu/binutils/binutils-2.29.tar.gz"
DIRNAME="binutils-2.29"
ARCHIVE=$DIRNAME".tar.gz"
CONFIG_OPTIONS="--disable-shared --disable-gdb \
                 --disable-libdecnumber --disable-readline \
                 --disable-sim --disable-ld"

# ===== DCFuzz target HIT injection =====
inject_hit_by_name_line() {
  local filename="$1"
  local line="$2"

  mapfile -t matches < <(find . -type f -name "$filename")

  local file="${matches[0]}"
  echo "[inject] inserting HIT at $file:$line"

  offset=0

  if ! grep -qE '^\s*#include\s*<stdio\.h>' "$file"; then
    sed -i '/^#include "sysdep\.h"/a #include <stdio.h>' "$file"
    offset=$((offset+1))
  fi
  if ! grep -qE '^\s*#include\s*<stdlib\.h>' "$file"; then
    sed -i '/^#include "sysdep\.h"/a #include <stdlib.h>' "$file"
    offset=$((offset+1))
  fi

  adjusted_line=$((line + offset))

  local indent
  local insert
  indent="$(sed -n "${adjusted_line}p" "$file" | sed -E 's/^([[:space:]]*).*/\1/')"
  
  insert="${indent}fprintf(stderr, \"[DCFuzz][HIT]\\\\n\"); fflush(stderr); _Exit(123);"
  sed -i "${adjusted_line}a\\$insert" "$file"
}

inject_from_line_file() {
  local line_file="$1"  
  echo "[inject] reading targets from: $line_file"
  
  IFS= read -r entry < "$line_file"

  local fname="${entry%%:*}"
  local lno="${entry##*:}"

  echo "fname : $fname, lno :$lno"

  inject_hit_by_name_line "$fname" "$lno" || return $?
}


echo "*********************binutils-2.29*************************"
wget $URL -O $ARCHIVE
rm -rf $DIRNAME
tar -xzf $ARCHIVE || exit 1
cd $DIRNAME

inject_from_line_file "/benchmark/target/line/$1/$2"

./configure $CONFIG_OPTIONS || exit 1
## Insert prints in nm in order to catch memory over consumption that does not crash with ASAN
if [[ $BIN_NAME == "nm" && $TOOL_NAME == "ASAN" ]]; then
    sed -i '8203 s/^.*$/fprintf(stderr, \"@@@ start\\n\");&/' bfd/elf.c
    sed -i '8206 s/^.*$/fprintf(stderr, \"@@@ end\\n\");&/' bfd/elf.c
fi
## Parallel building according to https://github.com/aflgo/aflgo/issues/59
## Altohough an issue with parallel building is observed in libxml (https://github.com/aflgo/aflgo/issues/41), 
## We have not yet encountered a problem with binutils.
make -j || exit 1
cd ../
cp $DIRNAME/binutils/nm-new ./nm || exit 1
cp $DIRNAME/binutils/readelf ./readelf || exit 1
