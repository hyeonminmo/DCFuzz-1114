FROM fuzzer_base2/aflgo as aflgo
FROM fuzzer_base/windranger as windranger
FROM fuzzer_base/dafl as dafl

FROM dcfuzz_bench2/aflgo as bench_aflgo
FROM dcfuzz_bench/windranger as bench_windranger
FROM dcfuzz_bench/dafl as bench_dafl
FROM dcfuzz_bench/asan as bench_asan
FROM dcfuzz_bench/patch as bench_patch

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
    build-essential cmake git curl wget unzip \
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
    libncurses5 \
    libfreetype6 libfreetype6-dev \
    python-dev \
    nasm \
    libbz2-dev liblzo2-dev





### Copy fuzzer and builded program docker image 


## Copy fuzzer image

COPY --chown=$UID:$GID --from=aflgo /fuzzer /fuzzer
COPY --chown=$UID:$GID --from=windranger /fuzzer /fuzzer
COPY --chown=$UID:$GID --from=dafl /fuzzer /fuzzer

## Copy program with each fuzzer image 

#COPY --chown=$UID:$GID --from=bench_aflgo /benchmark/bin /benchmark/bin
COPY --chown=$UID:$GID --from=bench_asan /benchmark/bin /benchmark/bin
COPY --chown=$UID:$GID --from=bench_patch /benchmark/bin /benchmark/bin
COPY --chown=$UID:$GID --from=bench_windranger /benchmark/bin /benchmark/bin
COPY --chown=$UID:$GID --from=bench_dafl /benchmark /benchmark
COPY --chown=$UID:$GID --from=bench_dafl /sparrow /sparrow
COPY --chown=$UID:$GID --from=bench_dafl /smake /smake




# Copy 
COPY --chown=$UID:$GID --from=bench_aflgo /benchmark /benchmark
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



