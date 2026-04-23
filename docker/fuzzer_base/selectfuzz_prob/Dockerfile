ARG PREFIX
FROM $PREFIX/base

WORKDIR /fuzzer

COPY fuzzer_base/selectfuzz_prob/SelectFuzz.tar.gz /fuzzer/
COPY fuzzer_base/selectfuzz_prob/llvm4.tar.gz.aa /fuzzer/
COPY fuzzer_base/selectfuzz_prob/llvm4.tar.gz.ab /fuzzer/
COPY fuzzer_base/selectfuzz_prob/llvm4.tar.gz.ac /fuzzer/
COPY fuzzer_base/selectfuzz_prob/llvm4.tar.gz.ad /fuzzer/


RUN tar -xzf SelectFuzz.tar.gz && \
    rm SelectFuzz.tar.gz && \
    cd /fuzzer/SelectFuzz

RUN cd /fuzzer && \
    cat llvm4.tar.gz* > llvm4.tar.gz

RUN mv ./llvm4.tar.gz /fuzzer/SelectFuzz/ && \
    cd /fuzzer/SelectFuzz && \
    tar -zxf llvm4.tar.gz && \
    rm llvm4.tar.gz

RUN rm llvm4.tar.gz.aa && \
    rm llvm4.tar.gz.ab && \
    rm llvm4.tar.gz.ac && \
    rm llvm4.tar.gz.ad