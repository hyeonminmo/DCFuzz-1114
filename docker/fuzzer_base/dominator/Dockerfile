ARG PREFIX
FROM $PREFIX/base

WORKDIR /fuzzer

COPY fuzzer_base/dominator/pass /fuzzer/Dominator
COPY fuzzer_base/dominator/script /fuzzer/Dominator/script

RUN set -eux; \
    cd /fuzzer/Dominator; \
    clang++ -fPIC -shared -O2 \
      $(llvm-config --cxxflags) \
      -o /fuzzer/Dominator/libDominatorCoveragePass.so \
      /fuzzer/Dominator/DominatorCoveragePass.cpp