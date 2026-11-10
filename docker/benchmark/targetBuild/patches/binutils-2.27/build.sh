#!/bin/bash
URL="https://gcc.gnu.org/ftp/binutils/releases/binutils-2.27.tar.gz"
DIRNAME="binutils-2.27"
ARCHIVE=$DIRNAME".tar.gz"
CONFIG_OPTIONS="--disable-shared --disable-gdb \
                 --disable-libdecnumber --disable-readline \
                 --disable-sim --disable-ld"

# ===== DCFuzz target HIT injection =====
inject_hit_by_name_line() {
  local filename="$1"
  local line="$2"
  local file include_line inserted=0 adjusted_line

  if [[ ! "$line" =~ ^[0-9]+$ ]] || (( line < 1 )); then
    echo "[inject][ERROR] invalid target line: $line" >&2
    return 1
  fi

  local -a matches
  mapfile -t matches < <(find . -type f -name "$filename" | sort)

  if (( ${#matches[@]} != 1 )); then
    echo "[inject][ERROR] expected exactly one '$filename', found ${#matches[@]}" >&2
    printf '  %s\n' "${matches[@]}" >&2
    return 1
  fi

  file="${matches[0]}"
  echo "[inject] inserting HIT at $file:$line"

  if (( line > $(wc -l < "$file") )); then
    echo "[inject][ERROR] line $line exceeds file length" >&2
    return 1
  fi

  # GNU binutils requires config.h to be loaded before system headers.
  # sysdep.h loads config.h, so add any missing system headers after it.
  include_line="$(grep -nEm1 '^[[:space:]]*#[[:space:]]*include[[:space:]]*["<](sysdep\.h|config\.h)[">]' "$file" | cut -d: -f1)"
  if [[ -z "$include_line" ]] || (( include_line >= line )); then
    echo "[inject][ERROR] cannot safely insert headers before target $file:$line" >&2
    return 1
  fi

  # Insert in reverse order at the same line, preserving stdio/stdlib order.
  if ! grep -qE '^[[:space:]]*#[[:space:]]*include[[:space:]]*<stdlib\.h>' "$file"; then
    sed -i "${include_line}a\\#include <stdlib.h>" "$file" || return 1
    inserted=$((inserted + 1))
  fi
  if ! grep -qE '^[[:space:]]*#[[:space:]]*include[[:space:]]*<stdio\.h>' "$file"; then
    sed -i "${include_line}a\\#include <stdio.h>" "$file" || return 1
    inserted=$((inserted + 1))
  fi

  adjusted_line=$((line + inserted))

  # Place the HIT immediately BEFORE the target line. Putting multiple
  # statements AFTER an unbraced 'if' changes program control flow.
  # A single compound statement keeps the marker together.
  sed -i "${adjusted_line}i\\  do { fprintf(stderr, \"[DCFuzz][HIT]\\\\n\"); fflush(stderr); _Exit(123); } while (0);" "$file" || return 1

  echo "[inject] done: $file (target original line $line, +$inserted headers)"
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



echo "*********************binutils-2.27*************************"
cp -a /benchmark/project/binutils-2.27/binutils-2.27 ./
cd $DIRNAME

echo "BIN_NAME : $1, BUG_NAME : $2"

inject_from_line_file "/benchmark/target/line/$1/$2"

./configure $CONFIG_OPTIONS || exit 1
## Parallel building according to https://github.com/aflgo/aflgo/issues/59
## Altohough an issue with parallel building is observed in libxml (https://github.com/aflgo/aflgo/issues/41), 
## We have not yet encountered a problem with binutils.
make -j1 V=1 || exit 1
cd ../
cp $DIRNAME/binutils/strip-new ./strip || exit 1
