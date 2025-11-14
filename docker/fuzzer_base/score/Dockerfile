ARG PREFIX
FROM $PREFIX/base

RUN mkdir -p /fuzzer/distance

WORKDIR /fuzzer/distance

RUN cd /fuzzer/distance && \
    git clone https://github.com/prosyslab/DAFL.git DAFL && \
    cd /fuzzer/distance/DAFL && \
    sed -i '/q->cal_failed  = 0;/a \  printf("[PROX_SCORE] seed_file:%s prox_score:%llu\\n", q->fname, q->prox_score);' \ 
      ./afl-fuzz.c && \
     make && cd llvm_mode && make







