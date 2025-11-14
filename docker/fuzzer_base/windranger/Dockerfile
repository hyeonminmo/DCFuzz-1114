ARG PREFIX
FROM $PREFIX/base

WORKDIR /fuzzer

COPY fuzzer_base/windranger/windranger.tar.gz /fuzzer/

RUN tar -xzf windranger.tar.gz && \
    rm windranger.tar.gz && \
    mv windranger WindRanger

# Install LLVM-10
RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0/clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz && \
    tar -xf clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz && \
    rm clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz && \
    mv clang+llvm-10.0.0-x86_64-linux-gnu-ubuntu-18.04 /fuzzer/WindRanger/clang+llvm

# Set environment variables instead of symbolic linking
ENV LLVM_PATH=/fuzzer/WindRanger/clang+llvm
ENV PATH=$LLVM_PATH/bin:$PATH
#ENV GOPATH=/root/go
#ENV PATH=$LLVM_PATH/bin:$GOPATH/bin:$PATH
ENV CC=$LLVM_PATH/bin/clang
ENV CXX=$LLVM_PATH/bin/clang++
ENV LLVM_COMPILER=clang
#ENV WLLVM_CONFIGURE_ONLY=1


# Install wllvm
RUN pip3 install --upgrade pip==9.0.3 && \
    pip3 install wllvm


# Install Go 1.20
RUN wget https://golang.org/dl/go1.20.7.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.20.7.linux-amd64.tar.gz && \
    rm go1.20.7.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:$PATH"


# Install gclang(gllvm)
ENV GOPATH=/root/go
ENV PATH=$GOPATH/bin:$PATH

RUN mkdir -p /root/go && \
    go install github.com/SRI-CSL/gllvm/cmd/...@v1.3.0

#RUN mkdir -p /root/go && \
#    go get github.com/SRI-CSL/gllvm/cmd/... && \
#    cd /root/go/src/github.com/SRI-CSL/gllvm && \
#    git checkout v1.3.0 && \
#    cd - && \
#    go get github.com/SRI-CSL/gllvm/cmd/...


# Install gclang
#RUN mkdir -p $GOPATH && \
#    go install github.com/SRI-CSL/gllvm/cmd/gclang@v1.3.0 && \
#    go install github.com/SRI-CSL/gllvm/cmd/get-bc@v1.3.0 && \
#    go install github.com/SRI-CSL/gllvm/cmd/llvm-link-whole@v1.3.0
