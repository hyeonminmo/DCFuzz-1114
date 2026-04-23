#!/bin/bash

# ===== DCFuzz target HIT injection =====
inject_hit_by_name_line() {
  local filename="$1"
  local line="$2"

  mapfile -t matches < <(find . -type f -name "$filename")

  local file="${matches[0]}"
  echo "[inject] inserting HIT at $file:$line"

  offset=0

  if ! grep -qE '^\s*#include\s*<stdlib\.h>' "$file"; then
    sed -i '1i #include <stdlib.h>' "$file"
    offset=$((offset+1))
  fi

  if ! grep -qE '^\s*#include\s*<stdio\.h>' "$file"; then
    sed -i '1i #include <stdio.h>' "$file"
    offset=$((offset+1))
  fi
  adjusted_line=$((line + offset))

  local indent
  indent="$(sed -n "${adjusted_line}p" "$file" | sed -E 's/^([[:space:]]*).*/\1/')"

  sed -i "${adjusted_line}i\\
  ${indent}fprintf(stderr, \"[DCFuzz][HIT]\\\\n\"); fflush(stderr); _Exit(123);\
  " "$file"
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

build_lib() {
  rm -rf BUILD
  cp -rf SRC BUILD
  cd BUILD 
  inject_from_line_file "/benchmark/target/line/$1/$2"
  (./autogen.sh && ./configure --disable-shared --disable-freetype && make)
}

echo "*****************libming-4.8.1 file *************************"

GIT_URL="https://github.com/libming/libming.git"
TAG_NAME="50098023446a5412efcfbd40552821a8cba983a6"
RELEVANT_BINARIES="swftophp"

[ ! -e SRC ] && git clone $GIT_URL SRC
cd SRC
git checkout $TAG_NAME
cd ..

build_lib $1 $2

cd ..

for binary in $RELEVANT_BINARIES; do
  cp BUILD/util/$binary ./$binary
done

