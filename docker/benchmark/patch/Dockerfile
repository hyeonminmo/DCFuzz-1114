ARG FUZZER_PREFIX
FROM $FUZZER_PREFIX/aflgo

COPY targetBuild/benchmark-project /benchmark/project
COPY targetBuild/target/line /benchmark/target/line
COPY targetBuild/build_bench_common.sh /benchmark/build_bench_common.sh
COPY targetBuild/seed/cxxfilt /benchmark/seed/cxxfilt
COPY targetBuild/triage /benchmark/triage

ENV ASAN_OPTIONS=allocator_may_return_null=1,detect_leaks=0
WORKDIR /benchmark

COPY targetBuild/build_patched.sh /benchmark/build_patched.sh
RUN ./build_patched.sh

