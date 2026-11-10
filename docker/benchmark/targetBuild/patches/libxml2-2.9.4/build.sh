#!/bin/bash

URL="https://github.com/GNOME/libxml2/archive/refs/tags/v2.9.4.zip"
DIRNAME="libxml2-2.9.4"
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


echo "*********************binutils-2.26*************************"

cp -a /benchmark/project/libxml2-2.9.4/libxml2-2.9.4 ./
cd $DIRNAME

echo "BIN_NAME : $1, BUG_NAME : $2"

inject_from_line_file "/benchmark/target/line/$1/$2"

./autogen.sh --disable-shared || exit 1
make || exit 1

cd ../
cp $DIRNAME/xmllint ./xmllint || exit 1
