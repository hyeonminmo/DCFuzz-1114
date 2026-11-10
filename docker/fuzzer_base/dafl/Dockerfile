ARG PREFIX
FROM $PREFIX/base

WORKDIR /fuzzer

RUN git clone https://github.com/prosyslab/DAFL.git DAFL && \
    cd /fuzzer/DAFL 


RUN cd /fuzzer/DAFL && \
  cat > /tmp/ctodcfuzzer_dafl_import.sed <<'SED'
# includes: after #include <sys/time.h>
0,/^[[:space:]]*#include[[:space:]]*<sys\/time\.h>[[:space:]]*$/{
/^[[:space:]]*#include[[:space:]]*<sys\/time\.h>[[:space:]]*$/a\
#include <dirent.h>\
#include <sys/stat.h>\
#include <fcntl.h>\
#include <unistd.h>
}

# declare flag before save_if_interesting() definition (so it is visible there)
/^[[:space:]]*static[[:space:]]\+u8[[:space:]]\+save_if_interesting[[:space:]]*[(]/i\
static u8 ctodcfuzzer_importing; /* 0=normal, 1=import(maybe_import_queue) */\
\

0,/^[[:space:]]*int[[:space:]]\+main[[:space:]]*[(]/{ 
/^[[:space:]]*int[[:space:]]\+main[[:space:]]*[(]/i\
/* === ctodcfuzzer runtime import (no env) === */\
static u8*  import_dir; \
static u64  import_interval_us = 30000000; /* 30s */\
static u64  last_import_us;\
\
/* minimal file reader (avoid DAFL helper deps) */\
static u8* dcf_read_file(const char* path, u32* out_len) {\
  int fd = open(path, O_RDONLY);\
  if (fd < 0) return NULL;\
  struct stat st;\
  if (fstat(fd, &st)) { close(fd); return NULL; }\
  if (st.st_size <= 0 || st.st_size > (1<<26)) { close(fd); return NULL; }\
  u32 len = (u32)st.st_size;\
  u8* buf = ck_alloc(len);\
  u32 off = 0;\
  while (off < len) {\
    ssize_t r = read(fd, buf + off, len - off);\
    if (r <= 0) { ck_free(buf); close(fd); return NULL; }\
    off += (u32)r;\
  }\
  close(fd);\
  *out_len = len;\
  return buf;\
}\
\
static void maybe_import_queue(char** argv) {\
  u64 now = get_cur_time_us();\
  if (last_import_us && now - last_import_us < import_interval_us) return;\
  last_import_us = now;\
  if (!import_dir) return;\
\
  DIR* d = opendir((char*)import_dir);\
  if (!d) return;\
\
  u8 done_dir[4096];\
  snprintf((char*)done_dir, sizeof(done_dir), \"%s/.done\", import_dir);\
  mkdir((char*)done_dir, 0700);\
\
  struct dirent* de;\
  while ((de = readdir(d))) {\
    if (de->d_name[0] == '.') continue;\
    if (strstr(de->d_name, "-sync")) continue;\
\
    u8 src_path[4096];\
    snprintf((char*)src_path, sizeof(src_path), \"%s/%s\", import_dir, de->d_name);\
\
    struct stat st;\
    if (stat(src_path, &st)) continue;\
    if (!S_ISREG(st.st_mode)) continue;\
\
    u32 len = 0;\
    u8* mem = dcf_read_file((char*)src_path, &len);\
    if (!mem || !len) {\
      if (mem) ck_free(mem);\
      continue;\
    }\
\
    write_to_testcase(mem, len);\
\
    u8 fault = run_target(argv, exec_tmout);\
\
    classify_counts((u64*)trace_bits);\
    u32 before_q = queued_paths; \
\
    ctodcfuzzer_importing=1;\
    save_if_interesting(argv, mem, len, fault);\
    ctodcfuzzer_importing=0;\
    const char* saved_base = NULL;\
    char saved_short[512];\
\
    if (queued_paths > before_q && queue_last && queue_last->fname) {\
      const char* saved = (const char*)queue_last->fname;\
      const char* base  = strrchr(saved, \'/\');\
      base = base ? base + 1 : saved;\
      snprintf(saved_short, sizeof(saved_short), \"%s\", base);\
      saved_base = saved_short;\
    }\
\
    {\
      u8 dst1[4096];\
      if (saved_base) {\
        snprintf((char*)dst1, sizeof(dst1), \"%s/.done/%s-%s\", import_dir, de->d_name, saved_base);\
      } else {\
        if (fault) {\
          snprintf((char*)dst1, sizeof(dst1), \"%s/.done/%s-bad\", import_dir, de->d_name);\
        } else {\
          snprintf((char*)dst1, sizeof(dst1), \"%s/.done/%s\", import_dir, de->d_name);\
        }\
      }\
      rename((char*)src_path, (char*)dst1);\
    }\
\
    ck_free(mem);\
  }\
  closedir(d);\
}\

}



0,/^[[:space:]]*setup_dirs_fds[[:space:]]*[(][[:space:]]*[)][[:space:]]*;[[:space:]]*$/{
/^[[:space:]]*setup_dirs_fds[[:space:]]*[(][[:space:]]*[)][[:space:]]*;[[:space:]]*$/a\
\
  /* === ctodcfuzzer import dir setup (no env) === */\
  {\
    u8* ctodcfuzzer_dir = alloc_printf(\"%s/ctodcfuzzer\", out_dir);\
    import_dir     = alloc_printf(\"%s/queue\", ctodcfuzzer_dir);\
    ck_free(ctodcfuzzer_dir);\
    last_import_us = 0;\
  }\

}


/^[[:space:]]*fn = alloc_printf("%s\/queue\/id:%06u,%llu,%s", out_dir, queued_paths,$/{
N
N
c\
    fn = alloc_printf("%s/queue/id:%06u,%llu,%llu,%s%s", out_dir, queued_paths, prox_score,\
                      get_cur_time() - start_time,\
                      describe_op(hnb), ctodcfuzzer_importing ? "-sync" : "");
}


0,/^[[:space:]]*skipped_fuzz[[:space:]]*=[[:space:]]*fuzz_one[[:space:]]*[(][[:space:]]*use_argv[[:space:]]*[)][[:space:]]*;[[:space:]]*$/{
/^[[:space:]]*skipped_fuzz[[:space:]]*=[[:space:]]*fuzz_one[[:space:]]*[(][[:space:]]*use_argv[[:space:]]*[)][[:space:]]*;[[:space:]]*$/i\
    if(import_dir) maybe_import_queue(use_argv);\

}
SED


RUN cd /fuzzer/DAFL && \
    sed -i -f /tmp/ctodcfuzzer_dafl_import.sed afl-fuzz.c

RUN cd /fuzzer/DAFL && \ 
    sed -i ':a;N;$!ba;s|fn = alloc_printf("%s/queue/id:%06u,%llu,%s", out_dir, queued_paths,[[:space:]]*prox_score,[[:space:]]*describe_op(hnb));|fn = alloc_printf("%s/queue/id:%06u,%llu,%llu,%s", out_dir, queued_paths, prox_score, get_cur_time() - start_time, describe_op(hnb));|g;s|fn = alloc_printf("%s/hangs/id:%06llu,%s", out_dir,[[:space:]]*unique_hangs,[[:space:]]*describe_op(0));|fn = alloc_printf("%s/hangs/id:%06llu,%llu,%s", out_dir, unique_hangs, get_cur_time() - start_time, describe_op(0));|g;s|fn = alloc_printf("%s/crashes/id:%06llu,%llu,sig:%02u,%s", out_dir,[[:space:]]*unique_crashes,[[:space:]]*prox_score,[[:space:]]*kill_signal,[[:space:]]*describe_op(0));|fn = alloc_printf("%s/crashes/id:%06llu,%llu,%llu,sig:%02u,%s", out_dir, unique_crashes, prox_score, get_cur_time() - start_time, kill_signal, describe_op(0));|g' afl-fuzz.c && \
    make && \
    cd llvm_mode && make

