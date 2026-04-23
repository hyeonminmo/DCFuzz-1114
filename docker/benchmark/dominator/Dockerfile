ARG FUZZER_PREFIX

FROM $FUZZER_PREFIX/dominator AS dominator_fuzzer
FROM $FUZZER_PREFIX/aflgo

COPY --from=dominator_fuzzer /fuzzer/Dominator /fuzzer/Dominator

COPY targetBuild/benchmark-project /benchmark/project
COPY targetBuild/target/line /benchmark/target/line
COPY targetBuild/build_bench_common.sh /benchmark/build_bench_common.sh
COPY targetBuild/seed/cxxfilt /benchmark/seed/cxxfilt
COPY targetBuild/triage /benchmark/triage


WORKDIR /benchmark


RUN echo "****************build dominator********************"

COPY dominator/build_bench_dominator.sh /benchmark/build_bench_dominator.sh
COPY dominator/script /benchmark/script
RUN mkdir -p /info/dominator
RUN ./build_bench_dominator.sh
RUN rm /benchmark/build_bench_dominator.sh


