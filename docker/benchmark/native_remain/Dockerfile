ARG FUZZER_PREFIX
FROM $FUZZER_PREFIX/aflgo

# Install dependencies for building Binutils
RUN apt-get update && \
    apt-get install -y --no-install-recommends texinfo 

COPY targetBuild/benchmark-project-build /benchmark/project
COPY targetBuild/target/line /benchmark/target/line
COPY targetBuild/build_bench_common.sh /benchmark/build_bench_common.sh
COPY targetBuild/seed/ /benchmark/seed/
COPY targetBuild/triage /benchmark/triage
COPY targetBuild/patches /benchmark/patches

WORKDIR /benchmark


RUN echo "****************build native********************"

COPY native_remain/build_bench_native.sh /benchmark/build_bench_native.sh
RUN ./build_bench_native.sh
RUN rm /benchmark/build_bench_native.sh
