#!/bin/bash

URL="https://github.com/libjpeg-turbo/libjpeg-turbo/archive/refs/tags/2.0.4.zip"
DIRNAME="libjpeg-turbo-2.0.4"
ARCHIVE=$DIRNAME".zip"

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
${indent}{\\
${indent}  fprintf(stderr, \"[DCFuzz][HIT]\\\\n\"); fflush(stderr); _Exit(123);\
" "$file"
  
  sed -i "$((adjusted_line + 2))a\\
${indent}}\
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


echo "*********************libjpeg-2.0.4*************************"

cp -a /benchmark/project/libjpeg-2.0.4/libjpeg-turbo-2.0.4 ./
cd $DIRNAME

echo "BIN_NAME : $1, BUG_NAME : $2"

inject_from_line_file "/benchmark/target/line/$1/$2"

cmake -G"Unix Makefiles" || exit 1
make || exit 1
cd ../
cp $DIRNAME/cjpeg-static ./cjpeg || exit 1
