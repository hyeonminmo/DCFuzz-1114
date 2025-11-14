FROM ubuntu:20.04

SHELL ["/bin/bash", "-c"]

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONIOENCODING=utf8 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8

# Install environment package
RUN apt-get update && apt-get upgrade -y
RUN apt-get install -yy libc6-dev binutils libgcc-9-dev
RUN apt-get install -yy \
    wget apt-transport-https git unzip \
    build-essential libtool libtool-bin gdb \
    automake autoconf bison flex python python3 sudo vim

ENV OUT=/out
ENV SRC=/src
ENV WORK=/work
ENV PATH="$PATH:/out"
RUN mkdir -p $OUT $SRC $WORK
ENV CMAKE_VERSION 3.21.1
RUN wget https://github.com/Kitware/CMake/releases/download/v$CMAKE_VERSION/cmake-$CMAKE_VERSION-Linux-x86_64.sh && \
    chmod +x cmake-$CMAKE_VERSION-Linux-x86_64.sh && \
    ./cmake-$CMAKE_VERSION-Linux-x86_64.sh --skip-license --prefix="/usr/local" && \
    rm cmake-$CMAKE_VERSION-Linux-x86_64.sh && \
    rm -rf /usr/local/doc/cmake /usr/local/bin/cmake-gui
COPY fuzzer_base/base/checkout_build_install_llvm.sh /root/
RUN /root/checkout_build_install_llvm.sh
RUN rm /root/checkout_build_install_llvm.sh


# Install fuzzer package
RUN apt-get update && \
    apt-get install -y \
    python3 python3-dev python3-pip \
    libboost-all-dev \
    cmake ninja-build \
    git curl \
    build-essential golang \
    nano pkg-config libtinfo5\
    opam libclang-cpp12-dev libgmp-dev \
    libclang-12-dev llvm-12-dev libmpfr-dev \
    make autoconf automake libtool bison flex \
    --no-install-recommends

#RUN apt-get update && \
#    apt-get install -yy \
#    git build-essential bc \
#    libfreetype6 libfreetype6-dev \
#    python-dev \
#    nasm \
#    libbz2-dev liblzo2-dev 
RUN apt-get update && \
    apt-get install -yy \
    git build-essential bc \
    golang binutils-gold \
    libncurses5 \
    libfreetype6 libfreetype6-dev \
    python-dev \
    nasm \
    libbz2-dev liblzo2-dev
# For parmeSan
#golang
# For Beacon
# libncurses5

RUN mkdir -p /benchmark/bin && \
    mkdir -p /benchmark/seed && \
    mkdir -p /benchmark/runtime && \
    mkdir -p /benchmark/poc &&\
    mkdir -p /benchmark/dict



# Install pip
RUN pip3 install --upgrade pip && \
    pip3 install networkx==2.5 pydot==1.4.1 pydotplus wllvm  && \
                lifelines==0.27.4 pandas==1.5.3 && \
                matplotlib==3.2.2 && \
                numpy==1.21.6 && \
                scipy==1.7.3

RUN mkdir -p /fuzzer







