ARG FUZZER_PREFIX
FROM $FUZZER_PREFIX/score

COPY targetBuild/benchmark-project /benchmark/project
COPY targetBuild/target/line /benchmark/target/line
COPY targetBuild/build_bench_common.sh /benchmark/build_bench_common.sh
COPY targetBuild/seed/cxxfilt /benchmark/seed/cxxfilt
COPY targetBuild/triage /benchmark/triage

ENV ASAN_OPTIONS=allocator_may_return_null=1,detect_leaks=0
WORKDIR /benchmark

RUN echo "****************build smake********************"

COPY dafl/build_smake.sh /benchmark/build_smake.sh
RUN ./build_smake.sh


RUN echo "****************setup sparrow********************"

COPY dafl/setup_sparrow.sh /benchmark/setup_sparrow.sh
RUN ./setup_sparrow.sh

RUN echo "****************build dafl**************************"

COPY score/script /benchmark/scripts
COPY score/build_bench_dafl.sh /benchmark/build_bench_dafl.sh
RUN ./build_bench_dafl.sh

RUN rm /benchmark/build_bench_dafl.sh && \
    rm /benchmark/build_smake.sh && \
    rm /benchmark/setup_sparrow.sh


