ARG PREFIX
FROM $PREFIX/base

WORKDIR /fuzzer

COPY fuzzer_base/selectfuzz/SelectFuzz.tar.gz /fuzzer/

RUN tar -xzf SelectFuzz.tar.gz && \
    rm SelectFuzz.tar.gz && \
    cd /fuzzer/SelectFuzz && \
    make clean && \
    sed -i '/double distance;[[:space:]]*\/\* Distance to targets[[:space:]]*\*\//a\
  u64 debug_total_distance,           /* Debug: raw total_distance        */\
      debug_total_count;              /* Debug: raw total_count           */' afl-fuzz.c && \
    sed -i '/q->distance = cur_distance;/a\
      q->debug_total_distance = *(u64*)(trace_bits + MAP_SIZE);\
      q->debug_total_count = *(u64*)(trace_bits + MAP_SIZE + 8);\
      fprintf(stderr, "[DIST-DEBUG] seed=%s cur_distance=%f total_distance=%llu total_count=%llu\\n",\
        q->fname ? (char*)q->fname : "unknown",\
        cur_distance,\
        (unsigned long long)q->debug_total_distance,\
        (unsigned long long)q->debug_total_count);' afl-fuzz.c && \
    sed -i '/perform_dry_run(use_argv);/a\
  do {\
    FILE *sl = fopen("initial_seed_prob.txt", "w");\
    if (sl) {\
      fprintf(sl, "Seed_ID,Filename,distance,prob,Exec_US,Bitmap_Size,total_distance,total_count\\n");\
      struct queue_entry *qq = queue;\
      u32 seed_id = 0;\
      while (qq) {\
        u8 *fn = qq->fname ? qq->fname : (u8*)"unknown";\
        double prob = (qq->distance > 0.0) ? (1.0 / qq->distance) : 0.0;\
        fprintf(sl, "%u,%s,%.6f,%.6f,%llu,%u,%llu,%llu\\n",\
          seed_id,\
          fn,\
          qq->distance,\
          prob,\
          qq->exec_us,\
          qq->bitmap_size,\
          (unsigned long long)qq->debug_total_distance,\
          (unsigned long long)qq->debug_total_count);\
        qq = qq->next;\
        seed_id++;\
      }\
      fclose(sl);\
      exit(0);\
    }\
  } while (0);' afl-fuzz.c && \
    sed -i 's/std::string funcName = F.getName();/std::string funcName = F.getName().str();/' llvm_mode/afl-llvm-pass.so.cc && \
    sed -i 's/BB.setValueName(ValueName::Create(NameRef));/BB.setName(NameRef);/' llvm_mode/afl-llvm-pass.so.cc && \
    make && \
    cd llvm_mode && make clean all || true


# RUN tar -xzf SelectFuzz.tar.gz && \
#     rm SelectFuzz.tar.gz && \
#     mv SelectFuzz prob && \
#     cd /fuzzer/prob && \
#     make clean && \
#     sed -i '/perform_dry_run(use_argv);/a \  FILE *sl=fopen("initial_seed_prob.txt","w"); if(sl){ fprintf(sl,"Seed_ID,Filename,prob,Exec_US,Bitmap_Size\\n"); struct queue_entry *q=queue; u32 seed_id=0; while(q){ u8 *fn=q->fname ? q->fname : (u8*)"unknown"; double prob = (q->distance > 0.0) ? (1.0 / q->distance) : 0.0; fprintf(sl,"%u,%s,%.6f,%llu,%u\\n", seed_id, fn, prob, q->exec_us, q->bitmap_size); q=q->next; seed_id++; } fclose(sl); exit(0); }' afl-fuzz.c && \
#     sed -i 's/std::string funcName = F.getName();/std::string funcName = F.getName().str();/' llvm_mode/afl-llvm-pass.so.cc && \
#     sed -i 's/BB.setValueName(ValueName::Create(NameRef));/BB.setName(NameRef);/' llvm_mode/afl-llvm-pass.so.cc && \
#     make && cd llvm_mode && make clean all || true