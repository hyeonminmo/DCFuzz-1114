#!/bin/bash
URL="https://gcc.gnu.org/ftp/binutils/releases/binutils-2.31.1.tar.gz"
DIRNAME="binutils-2.31.1"
ARCHIVE=$DIRNAME".tar.gz"
CONFIG_OPTIONS="--build=i686-linux --disable-shared --disable-gdb \
                 --disable-libdecnumber --disable-readline \
                 --disable-sim --disable-ld"

# ===== DCFuzz target HIT injection =====
inject_hit_by_name_line() {
  local filename="$1"
  local line="$2"

  mapfile -t matches < <(find . -type f -name "$filename")

  if [ "${#matches[@]}" -eq 0 ]; then
    echo "[ERROR] File not found: $filename"
    return 1
  fi

  local file="${matches[0]}"

  echo "[inject] inserting HIT at $file:$line"

  # 헤더를 추가하지 않으므로 line offset 불필요
  local indent
  indent="$(sed -n "${line}p" "$file" | sed -E 's/^([[:space:]]*).*/\1/')"

  sed -i "${line}a\\
${indent}fprintf(stderr, \"[DCFuzz][HIT]\\\\n\"); fflush(stderr); _Exit(123);
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


echo "*********************binutils-2.31.1*************************"
cp -a /benchmark/project/binutils-2.31.1/binutils-2.31.1 ./
cd $DIRNAME

echo "BIN_NAME : $1, BUG_NAME : $2"

inject_from_line_file "/benchmark/target/line/$1/$2"

./configure $CONFIG_OPTIONS || exit 1
## Parallel building according to https://github.com/aflgo/aflgo/issues/59
## Altohough an issue with parallel building is observed in libxml (https://github.com/aflgo/aflgo/issues/41), 
## We have not yet encountered a problem with binutils.
make -j || exit 1
cd ../
cp $DIRNAME/binutils/objdump ./objdump || exit 1
