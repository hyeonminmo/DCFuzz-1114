ARG PREFIX
FROM $PREFIX/base

RUN mkdir -p /fuzzer/distance

WORKDIR /fuzzer/distance

RUN git clone https://github.com/aflgo/aflgo.git AFLGo && \
    cd /fuzzer/distance/AFLGo && \
    git checkout b170fad54396f376160befd87adbba28b27c15d9 && \
    sed -i '/q->distance = cur_distance;/a \  printf("seed_file:%s cur_distance:%.2f\\n", q->fname, cur_distance);' \
      ./afl-fuzz.c && \
    make clean all && \
    cd llvm_mode && make clean all && \
    cd ../distance_calculator && \
    cmake -GNinja ./ && \
    cmake --build ./

ENV CC=afl-clang-fast \
    CXX=afl-clang-fast++



