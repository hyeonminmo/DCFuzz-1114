#FROM fuzzer_base3/aflgo AS aflgo
FROM fuzzer_base3/aflgo_dup_test AS aflgo
#FROM fuzzer_base3/windranger AS windranger
FROM fuzzer_base3/windranger_dup_test AS windranger
#FROM fuzzer_base3/dafl2 AS dafl
FROM fuzzer_base3/dafl_dup_test AS dafl
FROM fuzzer_base3/dominator AS dominator
FROM fuzzer_base3/score AS score

FROM dcfuzz_bench/aflgo AS bench_aflgo
FROM dcfuzz_bench2/windranger AS bench_windranger
FROM dcfuzz_bench2/dafl AS bench_dafl
FROM dcfuzz_bench/dominator AS bench_dominator
FROM dcfuzz_bench/asan AS bench_asan
FROM dcfuzz_bench/native AS bench_native


#FROM dcfuzz_bench/patch AS bench_patch

FROM ubuntu:20.04

ARG USER
ARG UID
ARG GID

SHELL ["/bin/bash", "-c"]

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONIOENCODING=utf8 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8


## Install proper tools

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential cmake git curl wget unzip tree  \
    autoconf automake libtool bison flex \
    zlib1g-dev libssl-dev python3 python3-pip \
    clang-format clang-tidy \
    ninja-build pkg-config lcov python3-setuptools \
    python3-dev libglib2.0-dev libxml2-dev libclang-12-dev llvm-12-dev \
    libncurses5-dev libsqlite3-dev \
    tzdata sudo vim tmux htop zsh


RUN apt-get update && \
    apt-get install -yy \
    git build-essential bc \
    golang binutils-gold \
    libncurses5 libpng16-16 \
    libfreetype6 libfreetype6-dev \
    python-dev \
    nasm \
    libbz2-dev liblzo2-dev


RUN apt update && apt install -y protobuf-compiler cgroup-tools lcov


### Copy fuzzer and builded program docker image 


## Copy fuzzer image

COPY --chown=$UID:$GID --from=aflgo /fuzzer /fuzzer
COPY --chown=$UID:$GID --from=windranger /fuzzer /fuzzer
COPY --chown=$UID:$GID --from=dafl /fuzzer /fuzzer
COPY --chown=$UID:$GID --from=score /fuzzer /fuzzer
COPY --chown=$UID:$GID --from=dominator /fuzzer /fuzzer


## Copy program with each fuzzer image 

#COPY --chown=$UID:$GID --from=bench_aflgo /benchmark/bin /benchmark/bin
COPY --chown=$UID:$GID --from=bench_asan /benchmark/bin /benchmark/bin
COPY --chown=$UID:$GID --from=bench_native /benchmark/bin /benchmark/bin
COPY --chown=$UID:$GID --from=bench_native /benchmark/patches /benchmark/patches

COPY --chown=$UID:$GID --from=bench_windranger /benchmark/bin /benchmark/bin
COPY --chown=$UID:$GID --from=bench_dominator /benchmark/bin /benchmark/bin
#COPY --chown=$UID:$GID --from=bench_patch /benchmark/bin /benchmark/bin
#COPY --chown=$UID:$GID --from=bench_dafl /benchmark /benchmark
#COPY --chown=$UID:$GID --from=bench_dafl /sparrow /sparrow
#COPY --chown=$UID:$GID --from=bench_dafl /smake /smake


# Copy 
COPY --chown=$UID:$GID --from=bench_aflgo /benchmark /benchmark
COPY --chown=$UID:$GID --from=bench_dafl /benchmark /benchmark
COPY --chown=$UID:$GID --from=bench_dafl /benchmark /benchmark

#COPY --chown=$UID:$GID --from=bench_aflgo /benchmark/poc /benchmark/
#COPY --chown=$UID:$GID --from=bench_aflgo /benchmark/seed /benchmark/seed
#COPY --chown=$UID:$GID --from=bench_aflgo /benchmark/target /benchmark/target
#COPY --chown=$UID:$GID --from=bench_aflgo /benchmark/triage /benchmark/triage



### 


USER root

## install newer python3 
RUN apt install -y --no-install-recommends make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl libncurses5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev tk-dev ca-certificates

RUN wget https://www.python.org/ftp/python/3.9.4/Python-3.9.4.tgz \
    && tar xf Python-3.9.4.tgz \
    && cd Python-3.9.4 \
    && ./configure \
    && make -j8 install

RUN curl https://bootstrap.pypa.io/get-pip.py -o /get-pip.py && python3 /get-pip.py
RUN rm /Python-3.9.4.tgz

# set timezone
ENV TZ=America/New_York
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# some useful tools
RUN apt-get install -y zsh locales direnv highlight jq
RUN locale-gen en_US.UTF-8


COPY init.sh /
COPY dcfuzz/ /dcfuzz/dcfuzz
COPY setup.py /dcfuzz/
COPY requirements.txt /dcfuzz/

RUN pip install /dcfuzz

RUN groupadd -g $GID -o $USER

RUN adduser --disabled-password --gecos '' -u $UID -gid $GID ${USER}
RUN adduser ${USER} sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER $USER

WORKDIR /home/$USER
