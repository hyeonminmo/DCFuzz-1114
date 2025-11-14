ARG PREFIX
FROM $PREFIX/base

WORKDIR /fuzzer


RUN git clone https://github.com/prosyslab/DAFL.git DAFL && \
    cd DAFL && make && cd llvm_mode && make



