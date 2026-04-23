ARG FUZZER_PREFIX
FROM $FUZZER_PREFIX/aflgo

COPY targetBuild/benchmark-project /benchmark/project
COPY targetBuild/target/line /benchmark/target/line
COPY targetBuild/build_bench_common.sh /benchmark/build_bench_common.sh
COPY targetBuild/seed/cxxfilt /benchmark/seed/cxxfilt
COPY targetBuild/triage /benchmark/triage
COPY targetBuild/patches /benchmark/patches

WORKDIR /benchmark


RUN echo "****************build native********************"

COPY native/build_bench_native.sh /benchmark/build_bench_native.sh
RUN ./build_bench_native.sh
RUN rm /benchmark/build_bench_native.sh
