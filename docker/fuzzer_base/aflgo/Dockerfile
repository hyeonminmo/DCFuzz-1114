ARG PREFIX
FROM $PREFIX/base

WORKDIR /fuzzer

RUN git clone https://github.com/aflgo/aflgo.git AFLGo && \
    cd /fuzzer/AFLGo && \
    git checkout b170fad54396f376160befd87adbba28b27c15d9 && \
    make clean all && \
    cd llvm_mode && make clean all && \
    cd ../distance_calculator && \
    cmake -GNinja ./ && \
    cmake --build ./

ENV CC=afl-clang-fast \
    CXX=afl-clang-fast++
