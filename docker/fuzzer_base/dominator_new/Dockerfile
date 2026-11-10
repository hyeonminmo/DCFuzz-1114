ARG PREFIX
FROM $PREFIX/base

WORKDIR /fuzzer

# 1) deps + LLVM 12 (SVF / dominator instrumentation)
RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      git cmake ninja-build build-essential python3 zlib1g-dev libz3-dev \
      clang-12 llvm-12 llvm-12-dev llvm-12-tools graphviz; \
    rm -rf /var/lib/apt/lists/*

# 2) SVF 2.2 + LLVM 12
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

# 3) Dominator instrumentation pass
COPY fuzzer_base/dominator_new/pass /fuzzer/Dominator



RUN set -eux; \
    cd /fuzzer/Dominator; \
    /usr/bin/clang++-12 -fPIC -shared -O2 \
      $(/usr/bin/llvm-config-12 --cxxflags) \
      -o /fuzzer/Dominator/libDominatorCoveragePass.so \
      /fuzzer/Dominator/DominatorCoveragePass.cpp \
      $(/usr/bin/llvm-config-12 --ldflags --libs core ipo support analysis passes)

# 4) LLVM 15 dependencies for DeepType
RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      libxml2-dev \
      libedit-dev \
      libncurses5-dev \
      libncursesw5-dev \
      libzstd-dev \
      zlib1g-dev; \
    rm -rf /var/lib/apt/lists/*

# 5) LLVM 15 for DeepType
RUN set -eux; \
    git clone \
      --branch release/15.x \
      --depth 1 \
      https://github.com/llvm/llvm-project.git \
      /opt/llvm-project-15; \
    mkdir -p /opt/llvm-project-15/build; \
    cd /opt/llvm-project-15/build; \
    cmake \
      -DLLVM_TARGET_ARCH="X86" \
      -DCMAKE_BUILD_TYPE=Release \
      -DLLVM_ENABLE_PROJECTS="clang;lldb;lld" \
      -DLLVM_TARGETS_TO_BUILD="ARM;X86;AArch64" \
      -G "Unix Makefiles" \
      ../llvm; \
    cmake --build . -j"$(nproc)"

# 6) Clone DeepType first. Phase-5 source patch is applied in the next layer.
RUN set -eux; \
    git clone \
      https://github.com/s3team/DeepType.git \
      /opt/DeepType; \
    cd /opt/DeepType; \
    sed -i \
      's#^LLVM_BUILD := .*#LLVM_BUILD := /opt/llvm-project-15/build#' \
      Makefile
RUN python3 - <<'PY'
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(
            f"DeepType Phase-5 patch failed for {label}: "
            f"expected exactly one anchor, found {count}"
        )
    return text.replace(old, new, 1)


# -------------------------------------------------------------------------
# A. CallGraph.cc
#    Keep the final SMLTA target set for every indirect callsite.
#    The assignment is intentionally outside the TargetLookupMap cache
#    if/else, so cache-hit callsites are exported as well.
# -------------------------------------------------------------------------
callgraph_path = Path("/opt/DeepType/src/lib/CallGraph.cc")
callgraph = callgraph_path.read_text(encoding="utf-8")

old_callgraph = """\t// Statistics
\terrs() << "\\n";
\tPrintResults(CI, FS, MLTypeName);"""

new_callgraph = """\t// DCFuzz Phase 5: preserve the final SMLTA target set.
\t// This is outside the TargetLookupMap cache branch so cache hits are kept.
\tCtx->Callees[CI] = FS;

\t// Statistics
\terrs() << "\\n";
\tPrintResults(CI, FS, MLTypeName);"""

callgraph = replace_once(
    callgraph,
    old_callgraph,
    new_callgraph,
    "CallGraph.cc / final SMLTA FuncSet",
)
callgraph_path.write_text(callgraph, encoding="utf-8")


# -------------------------------------------------------------------------
# B. Analyzer.cc includes
# -------------------------------------------------------------------------
analyzer_path = Path("/opt/DeepType/src/lib/Analyzer.cc")
analyzer = analyzer_path.read_text(encoding="utf-8")

old_includes = "#include <iostream>\n"
new_includes = """#include <iostream>
#include <algorithm>
#include <fstream>
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Support/raw_ostream.h"
"""

analyzer = replace_once(
    analyzer,
    old_includes,
    new_includes,
    "Analyzer.cc / includes",
)


# -------------------------------------------------------------------------
# C. Analyzer.cc command-line option
# -------------------------------------------------------------------------
old_global_ctx = "GlobalContext GlobalCtx;\n"
new_global_ctx = """// DCFuzz Phase 5: machine-readable SMLTA target output.
cl::opt<std::string> DeepTypeTargetsOutput(
    "targets-out",
    cl::desc("Write SMLTA indirect-call targets to TSV"),
    cl::init(""));

GlobalContext GlobalCtx;
"""

analyzer = replace_once(
    analyzer,
    old_global_ctx,
    new_global_ctx,
    "Analyzer.cc / -targets-out option",
)


# -------------------------------------------------------------------------
# D. Analyzer.cc TSV exporter
# -------------------------------------------------------------------------
main_anchor = "int main(int argc, char **argv) {\n"

exporter = r'''static std::string TSVSafe(std::string S) {
    for (char &C : S) {
        if (C == 9 || C == 10 || C == 13)
            C = 32;
    }
    return S;
}


struct DeepTypeCallsiteRecord {
    CallInst *CI;
    std::string CallerName;
    std::string SrcFile;
    unsigned SrcLine;
    unsigned SrcCol;
    uint64_t InstructionOrder;
    uint64_t FuncIndirectOrdinal;
    std::string CallIR;
};


static uint64_t GetInstructionOrderInFunction(const CallInst *Needle) {
    if (!Needle)
        return 0;

    const Function *F = Needle->getFunction();
    if (!F)
        return 0;

    uint64_t Index = 0;
    for (const BasicBlock &BB : *F) {
        for (const Instruction &I : BB) {
            if (&I == Needle)
                return Index;
            ++Index;
        }
    }
    return Index;
}


static bool IsIndirectCallForOrdinal(const CallInst *CI) {
    if (!CI || CI->isInlineAsm())
        return false;

    const Value *Called = CI->getCalledOperand();
    if (!Called)
        return false;

    Called = Called->stripPointerCasts();
    return !isa<Function>(Called);
}


static uint64_t GetIndirectCallOrdinalInFunction(const CallInst *Needle) {
    if (!Needle)
        return 0;

    const Function *F = Needle->getFunction();
    if (!F)
        return 0;

    uint64_t Ordinal = 0;

    for (const BasicBlock &BB : *F) {
        for (const Instruction &I : BB) {
            const CallInst *CI = dyn_cast<CallInst>(&I);
            if (!CI || !IsIndirectCallForOrdinal(CI))
                continue;

            if (CI == Needle)
                return Ordinal;

            ++Ordinal;
        }
    }

    return Ordinal;
}


static std::string GetCallIR(const CallInst *CI) {
    if (!CI)
        return "";

    std::string S;
    raw_string_ostream OS(S);
    CI->print(OS);
    OS.flush();
    return S;
}


static bool SameStableBase(const DeepTypeCallsiteRecord &A,
                           const DeepTypeCallsiteRecord &B) {
    return A.CallerName == B.CallerName &&
           A.SrcFile == B.SrcFile &&
           A.SrcLine == B.SrcLine &&
           A.SrcCol == B.SrcCol;
}


static bool ExportDeepTypeTargets(GlobalContext *GCtx,
                                  const std::string &OutputPath) {
    if (OutputPath.empty())
        return true;

    std::ofstream Out(OutputPath);
    if (!Out.is_open()) {
        errs() << "[DeepType] ERROR: cannot open target output: "
               << OutputPath << "\n";
        return false;
    }

    Out << "caller_func"
        << "\t" << "src_file"
        << "\t" << "src_line"
        << "\t" << "src_col"
        << "\t" << "call_ordinal"
        << "\t" << "func_indirect_ordinal"
        << "\t" << "target_func"
        << "\t" << "call_ir"
        << "\n";

    std::vector<DeepTypeCallsiteRecord> Callsites;
    Callsites.reserve(GCtx->IndirectCallInsts.size());

    for (CallInst *CI : GCtx->IndirectCallInsts) {
        if (!CI)
            continue;

        Function *Caller = CI->getFunction();
        if (!Caller)
            continue;

        DeepTypeCallsiteRecord R;
        R.CI = CI;
        R.CallerName = Caller->getName().str();
        R.SrcLine = 0;
        R.SrcCol = 0;
        R.InstructionOrder = GetInstructionOrderInFunction(CI);
        R.FuncIndirectOrdinal = GetIndirectCallOrdinalInFunction(CI);
        R.CallIR = GetCallIR(CI);

        const DebugLoc &DL = CI->getDebugLoc();
        if (DL) {
            const DILocation *Loc = DL.get();
            if (Loc) {
                R.SrcFile = Loc->getFilename().str();
                R.SrcLine = Loc->getLine();
                R.SrcCol = Loc->getColumn();
            }
        }

        std::replace(R.SrcFile.begin(), R.SrcFile.end(), '\\', '/');
        while (R.SrcFile.size() >= 2 &&
               R.SrcFile[0] == '.' && R.SrcFile[1] == '/') {
            R.SrcFile.erase(0, 2);
        }

        Callsites.push_back(R);
    }

    std::sort(
        Callsites.begin(),
        Callsites.end(),
        [](const DeepTypeCallsiteRecord &A,
           const DeepTypeCallsiteRecord &B) {
            if (A.CallerName != B.CallerName)
                return A.CallerName < B.CallerName;
            if (A.SrcFile != B.SrcFile)
                return A.SrcFile < B.SrcFile;
            if (A.SrcLine != B.SrcLine)
                return A.SrcLine < B.SrcLine;
            if (A.SrcCol != B.SrcCol)
                return A.SrcCol < B.SrcCol;
            return A.InstructionOrder < B.InstructionOrder;
        });

    uint64_t NumRows = 0;
    uint64_t NumCallsitesWithTargets = 0;
    uint64_t NumExportedCallsites = 0;
    unsigned CallOrdinal = 0;
    bool HavePrevious = false;
    DeepTypeCallsiteRecord Previous;

    for (const DeepTypeCallsiteRecord &R : Callsites) {
        if (!HavePrevious || !SameStableBase(Previous, R))
            CallOrdinal = 0;
        else
            ++CallOrdinal;

        Previous = R;
        HavePrevious = true;
        ++NumExportedCallsites;

        // Diagnostic identity independent of source location.  If SVF and
        // DeepType report the same caller + function-wide indirect ordinal
        // but different source locations, Phase 6 can report that explicitly.
        errs() << "[DeepType][SMLTA-CALLSITE] caller="
               << R.CallerName
               << " func_indirect_ordinal="
               << R.FuncIndirectOrdinal
               << " call_ordinal="
               << CallOrdinal
               << " loc="
               << (R.SrcFile.empty() ? "<unknown>" : R.SrcFile)
               << ":"
               << R.SrcLine
               << ":"
               << R.SrcCol
               << " ir="
               << R.CallIR
               << "\n";

        auto It = GCtx->Callees.find(R.CI);
        if (It == GCtx->Callees.end())
            continue;

        const FuncSet &Targets = It->second;
        if (!Targets.empty())
            ++NumCallsitesWithTargets;

        std::vector<std::string> TargetNames;
        for (Function *Target : Targets) {
            if (Target)
                TargetNames.push_back(Target->getName().str());
        }
        std::sort(TargetNames.begin(), TargetNames.end());
        TargetNames.erase(
            std::unique(TargetNames.begin(), TargetNames.end()),
            TargetNames.end());

        for (const std::string &TargetName : TargetNames) {
            Out << TSVSafe(R.CallerName) << "\t"
                << TSVSafe(R.SrcFile) << "\t";

            if (R.SrcLine != 0)
                Out << R.SrcLine;

            Out << "\t";

            if (R.SrcLine != 0)
                Out << R.SrcCol;

            Out << "\t"
                << CallOrdinal
                << "\t"
                << R.FuncIndirectOrdinal
                << "\t"
                << TSVSafe(TargetName)
                << "\t"
                << TSVSafe(R.CallIR)
                << "\n";

            ++NumRows;
        }
    }

    Out.close();

    errs() << "[DeepType] wrote "
           << NumRows
           << " target rows for "
           << NumCallsitesWithTargets
           << " indirect callsites with targets ("
           << NumExportedCallsites
           << " indirect callsites total) to "
           << OutputPath
           << "\n";

    return true;
}


'''

analyzer = replace_once(
    analyzer,
    main_anchor,
    exporter + main_anchor,
    "Analyzer.cc / TSV exporter",
)


# -------------------------------------------------------------------------
# E. Analyzer.cc main(): export after CallGraphPass finishes.
# -------------------------------------------------------------------------
old_main_tail = """\t// Print final results
\tPrintResults(&GlobalCtx);
\t
\tauto end = std::chrono::system_clock::now();"""

new_main_tail = """\t// Print final results
\tPrintResults(&GlobalCtx);

\t// DCFuzz Phase 5: export the final SMLTA call targets.
\tif (!DeepTypeTargetsOutput.empty()) {
\t\tif (!ExportDeepTypeTargets(&GlobalCtx, DeepTypeTargetsOutput)) {
\t\t\treturn 2;
\t\t}
\t}
\t
\tauto end = std::chrono::system_clock::now();"""

analyzer = replace_once(
    analyzer,
    old_main_tail,
    new_main_tail,
    "Analyzer.cc / export call",
)

analyzer_path.write_text(analyzer, encoding="utf-8")

print("[DeepType Phase 5] source patch applied successfully")
PY

# 7) Verify that the Phase-5 patch really exists, then build DeepType.
RUN set -eux; \
    grep -Fq 'Ctx->Callees[CI] = FS;' /opt/DeepType/src/lib/CallGraph.cc; \
    grep -Fq '"targets-out"' /opt/DeepType/src/lib/Analyzer.cc; \
    grep -Fq 'ExportDeepTypeTargets' /opt/DeepType/src/lib/Analyzer.cc; \
    grep -Fq '"call_ordinal"' /opt/DeepType/src/lib/Analyzer.cc; \
    grep -Fq '"func_indirect_ordinal"' /opt/DeepType/src/lib/Analyzer.cc; \
    grep -Fq '"call_ir"' /opt/DeepType/src/lib/Analyzer.cc; \
    grep -Fq 'GetIndirectCallOrdinalInFunction' /opt/DeepType/src/lib/Analyzer.cc; \
    cd /opt/DeepType; \
    make; \
    test -x /opt/DeepType/build/lib/kanalyzer

ENV DEEPTYPE_HOME=/opt/DeepType
ENV LLVM15_HOME=/opt/llvm-project-15/build
