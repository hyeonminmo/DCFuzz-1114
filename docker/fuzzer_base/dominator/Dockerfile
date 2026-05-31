ARG PREFIX
FROM $PREFIX/base

WORKDIR /fuzzer

# 1) deps + llvm12
RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      git cmake ninja-build build-essential python3 zlib1g-dev libz3-dev \
      clang-12 llvm-12 llvm-12-dev llvm-12-tools graphviz; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    cd /opt; \
    git clone https://github.com/SVF-tools/SVF.git; \
    cd SVF; \
    git checkout -b svf-llvm12 SVF-2.2; \
    git submodule update --init --recursive; \
    cmake -S . -B Release-build \
      -DCMAKE_BUILD_TYPE=Release \
      -DLLVM_DIR=/usr/lib/llvm-12/cmake; \
    cmake --build Release-build -j"$(nproc)"; \
    ln -sf /opt/SVF/Release-build/bin/wpa /usr/local/bin/wpa


COPY fuzzer_base/dominator/pass /fuzzer/Dominator
COPY fuzzer_base/dominator/script /fuzzer/Dominator/script

RUN set -eux; \
    cd /fuzzer/Dominator; \
    /usr/bin/clang++-12 -fPIC -shared -O2 \
      $(/usr/bin/llvm-config-12 --cxxflags) \
      -o /fuzzer/Dominator/libDominatorCoveragePass.so \
      /fuzzer/Dominator/DominatorCoveragePass.cpp \
      $(/usr/bin/llvm-config-12 --ldflags --libs core ipo support analysis passes)