ARG PREFIX
FROM $PREFIX/base

WORKDIR /fuzzer

COPY fuzzer_base/selectfuzz/SelectFuzz.tar.gz /fuzzer/
COPY fuzzer_base/selectfuzz/llvm4.tar.gz.aa /fuzzer/
COPY fuzzer_base/selectfuzz/llvm4.tar.gz.ab /fuzzer/
COPY fuzzer_base/selectfuzz/llvm4.tar.gz.ac /fuzzer/
COPY fuzzer_base/selectfuzz/llvm4.tar.gz.ad /fuzzer/

RUN cd /fuzzer && \
    cat llvm4.tar.gz* > llvm4.tar.gz

RUN tar -xzf SelectFuzz.tar.gz && \
    rm SelectFuzz.tar.gz

RUN mv ./llvm4.tar.gz /fuzzer/SelectFuzz/ && \
    cd /fuzzer/SelectFuzz && \
    tar -zxf llvm4.tar.gz && \
    rm llvm4.tar.gz

RUN rm llvm4.tar.gz.aa && \
    rm llvm4.tar.gz.ab && \
    rm llvm4.tar.gz.ac && \
    rm llvm4.tar.gz.ad

RUN export PATH=/fuzzer/SelectFuzz/llvm4/bin:$PATH && \
    export PATH=/fuzzer/SelectFuzz/llvm4/lib:$PATH && \
    cd /fuzzer/SelectFuzz &&\
    make clean && \
    sed -i '/perform_dry_run(use_argv);/a \  FILE *sl=fopen("initial_seed_prob.txt","w"); if(sl){ fprintf(sl,"Seed_ID,Filename,prob,Exec_US,Bitmap_Size\\n"); struct queue_entry *q=queue; u32 seed_id=0; while(q){ u8 *fn=q->fname ? q->fname : (u8*)"unknown"; double prob = (q->distance > 0.0) ? (1.0 / q->distance) : 0.0; fprintf(sl,"%u,%s,%.6f,%llu,%u\\n", seed_id, fn, prob, q->exec_us, q->bitmap_size); q=q->next; seed_id++; } fclose(sl); exit(0); }' afl-fuzz.c && \
    sed -i 's/std::string funcName = F.getName();/std::string funcName = F.getName().str();/' llvm_mode/afl-llvm-pass.so.cc && \
    sed -i 's/BB.setValueName(ValueName::Create(NameRef));/BB.setName(NameRef);/' llvm_mode/afl-llvm-pass.so.cc && \
    make && cd llvm_mode && make clean all || true

# RUN tar -xzf SelectFuzz.tar.gz && \
#     rm SelectFuzz.tar.gz && \
#     cd /fuzzer/SelectFuzz &&\
#     make clean && \
#     sed -i '/perform_dry_run(use_argv);/a \  FILE *sl=fopen("initial_seed_prob.txt","w"); if(sl){ fprintf(sl,"Seed_ID,Filename,prob,Exec_US,Bitmap_Size\\n"); struct queue_entry *q=queue; u32 seed_id=0; while(q){ u8 *fn=q->fname ? q->fname : (u8*)"unknown"; double prob = (q->distance > 0.0) ? (1.0 / q->distance) : 0.0; fprintf(sl,"%u,%s,%.6f,%llu,%u\\n", seed_id, fn, prob, q->exec_us, q->bitmap_size); q=q->next; seed_id++; } fclose(sl); exit(0); }' afl-fuzz.c && \
#     sed -i 's/std::string funcName = F.getName();/std::string funcName = F.getName().str();/' llvm_mode/afl-llvm-pass.so.cc && \
#     sed -i 's/BB.setValueName(ValueName::Create(NameRef));/BB.setName(NameRef);/' llvm_mode/afl-llvm-pass.so.cc && \
#     make && cd llvm_mode && make clean all || true

