ARG FUZZER_PREFIX
FROM $FUZZER_PREFIX/aflgo

# Install dependencies for building Binutils
RUN apt-get update && \
    apt-get install -y --no-install-recommends texinfo 

COPY targetBuild/benchmark-project-build /benchmark/project
COPY targetBuild/target/line /benchmark/target/line
COPY targetBuild/build_bench_common.sh /benchmark/build_bench_common.sh
COPY targetBuild/seed /benchmark/seed
COPY targetBuild/triage /benchmark/triage

ENV ASAN_OPTIONS=allocator_may_return_null=1,detect_leaks=0
WORKDIR /benchmark


RUN echo "****************build ASAN********************"

COPY targetBuild/build_bench_ASAN.sh /benchmark/build_bench_ASAN.sh
RUN ./build_bench_ASAN.sh
RUN rm /benchmark/build_bench_ASAN.sh
