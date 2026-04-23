ARG PREFIX
FROM $PREFIX/base

RUN mkdir -p /fuzzer

WORKDIR /fuzzer

RUN cd /fuzzer && \
    git clone https://github.com/prosyslab/DAFL.git score && \
    cd /fuzzer/score && \
    sed -i '/perform_dry_run(use_argv);/a \    FILE *sl=fopen("initial_seed_scores.txt","w"); if(sl){fprintf(sl,"Seed_ID,Filename,Prox_Score,Exec_US,Bitmap_Size\\n"); struct queue_entry *q=queue; while(q){ u8 *fn=q->fname?q->fname:(u8*)"unknown"; fprintf(sl,"%u,%s,%llu,%llu,%u\\n",q->entry_id,fn,q->prox_score,q->exec_us,q->bitmap_size); q=q->next; } fclose(sl); exit(0); }' afl-fuzz.c && \
    make && cd llvm_mode && make
