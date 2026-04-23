ARG PREFIX
FROM $PREFIX/base

WORKDIR /fuzzer


RUN git clone https://github.com/prosyslab/DAFL.git DAFL && \
    cd /fuzzer/DAFL && \
    sed -i ':a;N;$!ba;s|fn = alloc_printf("%s/queue/id:%06u,%llu,%s", out_dir, queued_paths,[[:space:]]*prox_score,[[:space:]]*describe_op(hnb));|fn = alloc_printf("%s/queue/id:%06u,%llu,%llu,%s", out_dir, queued_paths, prox_score, get_cur_time() - start_time, describe_op(hnb));|g;s|fn = alloc_printf("%s/hangs/id:%06llu,%s", out_dir,[[:space:]]*unique_hangs,[[:space:]]*describe_op(0));|fn = alloc_printf("%s/hangs/id:%06llu,%llu,%s", out_dir, unique_hangs, get_cur_time() - start_time, describe_op(0));|g;s|fn = alloc_printf("%s/crashes/id:%06llu,%llu,sig:%02u,%s", out_dir,[[:space:]]*unique_crashes,[[:space:]]*prox_score,[[:space:]]*kill_signal,[[:space:]]*describe_op(0));|fn = alloc_printf("%s/crashes/id:%06llu,%llu,%llu,sig:%02u,%s", out_dir, unique_crashes, prox_score, get_cur_time() - start_time, kill_signal, describe_op(0));|g' afl-fuzz.c && \
    make && \
    cd llvm_mode && make



