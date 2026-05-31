ARG FUZZER_PREFIX

FROM $FUZZER_PREFIX/dominator AS dominator_fuzzer
FROM $FUZZER_PREFIX/aflgo

COPY --from=dominator_fuzzer /fuzzer/Dominator /fuzzer/Dominator

COPY --from=dominator_fuzzer /opt/SVF /opt/SVF
COPY --from=dominator_fuzzer /usr/local/bin/wpa /usr/local/bin/wpa

COPY --from=dominator_fuzzer /usr/lib/llvm-12 /usr/lib/llvm-12
COPY --from=dominator_fuzzer /usr/bin/llvm-config-12 /usr/bin/llvm-config-12
COPY --from=dominator_fuzzer /usr/bin/llvm-dis-12 /usr/bin/llvm-dis-12
COPY --from=dominator_fuzzer /usr/bin/opt-12 /usr/bin/opt-12
COPY --from=dominator_fuzzer /usr/bin/clang-12 /usr/bin/clang-12
COPY --from=dominator_fuzzer /usr/bin/clang++-12 /usr/bin/clang++-12

ENV PATH="/usr/lib/llvm-12/bin:/opt/SVF/Release-build/bin:/usr/local/bin:${PATH}"


COPY targetBuild/benchmark-project-build /benchmark/project
COPY targetBuild/target/line /benchmark/target/line
COPY targetBuild/build_bench_common.sh /benchmark/build_bench_common.sh
COPY targetBuild/seed/cxxfilt /benchmark/seed/cxxfilt
COPY targetBuild/triage /benchmark/triage


WORKDIR /benchmark


RUN echo "****************build dominator********************"

COPY dominator/extract_dominator.sh /benchmark/extract_dominator.sh
COPY dominator/script /benchmark/script

RUN mkdir -p /info/dominator
RUN ./extract_dominator.sh

# COPY dominator/extract_valid_path.sh /benchmark/extract_valid_path.sh
# RUN ./extract_valid_path.sh

# COPY dominator/build_bench_dominator.sh /benchmark/build_bench_dominator.sh
# RUN ./build_bench_dominator.sh

# RUN rm /benchmark/build_bench_dominator.sh
# RUN rm /benchmark/extract_dominator.sh
# RUN rm /benchmark/extract_valid_path.sh


