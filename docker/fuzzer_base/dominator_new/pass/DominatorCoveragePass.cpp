#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace llvm;

static cl::opt<std::string> DominatorMapPath(
    "dominator-map",
    cl::desc(
        "Path to dominator manifest TSV: "
        "<id>\\t<function>\\t<original_bb>\\t<representative_line>\\t<source_lines_csv>"),
    cl::init(""));

// When the dominator analysis and instrumentation consume the exact same
// whole-program bitcode module, function + basic-block identity is stable.
// In this mode we deliberately do NOT use source-line/fingerprint fallbacks:
// a missing exact BB is treated as a pipeline mismatch and is reported.
static cl::opt<bool> DominatorExactModule(
    "dominator-exact-module",
    cl::desc(
        "Match dominators only by exact function/basic-block identity; "
        "intended for instrumentation of the same module.bc used for analysis"),
    cl::init(false));

namespace {

struct DominatorCoveragePass : public ModulePass {
  static char ID;
  DominatorCoveragePass() : ModulePass(ID) {}

  using DomKey = std::pair<std::string, std::string>;

  struct DomEntry {
    uint64_t ID = 0;
    std::string Function;
    std::string OriginalBB;
    unsigned RepresentativeLine = 0;
    bool HasRepresentativeLine = false;
    std::set<unsigned> SourceLines;
  };

  struct ModuleBBInfo {
    BasicBlock *BB = nullptr;
    std::string BBName;
    unsigned RepresentativeLine = 0;
    bool HasRepresentativeLine = false;
    std::set<unsigned> SourceLines;
  };

  std::vector<DomEntry> DomEntries;
  uint64_t NumDominators = 0;

  static std::string normalizeFunctionName(StringRef Name) {
    return Name.str();
  }

  static std::string normalizeBasicBlockName(const BasicBlock &BB) {
    const Function *F = BB.getParent();

    if (F && &BB == &F->getEntryBlock())
      return "entry";

    if (BB.hasName())
      return BB.getName().str();

    std::string S;
    raw_string_ostream OS(S);
    BB.printAsOperand(OS, false);
    OS.flush();

    if (!S.empty() && S[0] == '%')
      S.erase(0, 1);

    return S;
  }

  static std::set<unsigned> getAllSourceLines(const BasicBlock &BB) {
    std::set<unsigned> Lines;

    for (const Instruction &I : BB) {
      DebugLoc DL = I.getDebugLoc();
      if (!DL)
        continue;

      unsigned Line = DL.getLine();
      if (Line != 0)
        Lines.insert(Line);
    }

    return Lines;
  }

  static bool getRepresentativeSourceLine(const std::set<unsigned> &Lines,
                                          unsigned &LineOut) {
    if (Lines.empty())
      return false;

    LineOut = *Lines.begin();
    return true;
  }

  static uint64_t intersectionSize(const std::set<unsigned> &A,
                                   const std::set<unsigned> &B) {
    uint64_t Count = 0;
    auto IA = A.begin();
    auto IB = B.begin();

    while (IA != A.end() && IB != B.end()) {
      if (*IA < *IB) {
        ++IA;
      } else if (*IB < *IA) {
        ++IB;
      } else {
        ++Count;
        ++IA;
        ++IB;
      }
    }
    return Count;
  }

  static std::string lineSetToString(const std::set<unsigned> &Lines) {
    if (Lines.empty())
      return "?";

    std::string S;
    raw_string_ostream OS(S);
    bool First = true;
    for (unsigned Line : Lines) {
      if (!First)
        OS << ',';
      OS << Line;
      First = false;
    }
    OS.flush();
    return S;
  }

  static void parseSourceLineCSV(StringRef Text,
                                 std::set<unsigned> &Out) {
    Text = Text.trim();
    if (Text.empty() || Text == "?")
      return;

    SmallVector<StringRef, 16> Tokens;
    Text.split(Tokens, ',', -1, false);

    for (StringRef Tok : Tokens) {
      Tok = Tok.trim();
      if (Tok.empty())
        continue;

      uint64_t Value = 0;
      if (!Tok.getAsInteger(10, Value) &&
          Value > 0 &&
          Value <= std::numeric_limits<unsigned>::max()) {
        Out.insert(static_cast<unsigned>(Value));
      }
    }
  }

  bool loadManifest() {
    DomEntries.clear();
    NumDominators = 0;

    if (DominatorMapPath.empty()) {
      errs() << "[dominator-pass] ERROR: -dominator-map is empty\n";
      return false;
    }

    auto MBOrErr = MemoryBuffer::getFile(DominatorMapPath);
    if (!MBOrErr) {
      errs() << "[dominator-pass] ERROR: failed to open manifest: "
             << DominatorMapPath << "\n";
      return false;
    }

    StringRef Content = MBOrErr.get()->getBuffer();
    SmallVector<StringRef, 128> Lines;
    Content.split(Lines, '\n', -1, false);

    uint64_t MaxID = 0;
    bool SawAny = false;

    for (StringRef Line : Lines) {
      Line = Line.trim();
      if (Line.empty())
        continue;

      SmallVector<StringRef, 6> Parts;
      Line.split(Parts, '\t', -1, false);

      // Backward-compatible with the old 3/4-column manifests.
      if (Parts.size() < 3) {
        errs() << "[dominator-pass] WARNING: malformed line: "
               << Line << "\n";
        continue;
      }

      uint64_t EntryID = 0;
      if (Parts[0].trim().getAsInteger(10, EntryID)) {
        errs() << "[dominator-pass] WARNING: invalid ID in line: "
               << Line << "\n";
        continue;
      }

      std::string FuncName = Parts[1].trim().str();
      std::string BBName = Parts[2].trim().str();

      if (FuncName.empty() || BBName.empty()) {
        errs() << "[dominator-pass] WARNING: empty function/bb in line: "
               << Line << "\n";
        continue;
      }

      DomEntry Entry;
      Entry.ID = EntryID;
      Entry.Function = FuncName;
      Entry.OriginalBB = BBName;

      if (Parts.size() >= 4) {
        StringRef RepText = Parts[3].trim();
        if (!RepText.empty() && RepText != "?") {
          uint64_t Parsed = 0;
          if (!RepText.getAsInteger(10, Parsed) &&
              Parsed > 0 &&
              Parsed <= std::numeric_limits<unsigned>::max()) {
            Entry.RepresentativeLine = static_cast<unsigned>(Parsed);
            Entry.HasRepresentativeLine = true;
          }
        }
      }

      if (Parts.size() >= 5)
        parseSourceLineCSV(Parts[4], Entry.SourceLines);

      // Backward compatibility: old v2 manifest has only representative line.
      if (Entry.SourceLines.empty() && Entry.HasRepresentativeLine)
        Entry.SourceLines.insert(Entry.RepresentativeLine);

      if (!Entry.HasRepresentativeLine && !Entry.SourceLines.empty()) {
        Entry.RepresentativeLine = *Entry.SourceLines.begin();
        Entry.HasRepresentativeLine = true;
      }

      DomEntries.push_back(Entry);

      if (!SawAny || EntryID > MaxID)
        MaxID = EntryID;
      SawAny = true;
    }

    if (!SawAny) {
      errs() << "[dominator-pass] ERROR: no valid dominator entries loaded\n";
      return false;
    }

    NumDominators = MaxID + 1;

    uint64_t WithRep = 0;
    uint64_t WithSets = 0;
    for (const DomEntry &Entry : DomEntries) {
      if (Entry.HasRepresentativeLine)
        ++WithRep;
      if (!Entry.SourceLines.empty())
        ++WithSets;
    }

    errs() << "[dominator-pass] loaded " << DomEntries.size()
           << " dominator entries, NumDominators=" << NumDominators
           << ", with_representative_line=" << WithRep
           << ", with_source_line_sets=" << WithSets
           << "\n";

    return true;
  }

  GlobalVariable *getOrCreateCountsArray(Module &M, LLVMContext &Ctx) {
    Type *I64Ty = Type::getInt64Ty(Ctx);
    ArrayType *CountsTy = ArrayType::get(I64Ty, NumDominators);

    GlobalVariable *GV = M.getNamedGlobal("__dominator_counts");
    if (GV)
      return GV;

    GV = new GlobalVariable(
        M, CountsTy, false, GlobalValue::ExternalLinkage, nullptr,
        "__dominator_counts");
    GV->setAlignment(MaybeAlign(8));
    return GV;
  }

  GlobalVariable *getOrCreateSeenArray(Module &M, LLVMContext &Ctx) {
    Type *I8Ty = Type::getInt8Ty(Ctx);
    ArrayType *SeenTy = ArrayType::get(I8Ty, NumDominators);

    GlobalVariable *GV = M.getNamedGlobal("__dominator_seen");
    if (GV)
      return GV;

    GV = new GlobalVariable(
        M, SeenTy, false, GlobalValue::ExternalLinkage, nullptr,
        "__dominator_seen");
    GV->setAlignment(MaybeAlign(1));
    return GV;
  }

  GlobalVariable *getOrCreateNumDominators(Module &M, LLVMContext &Ctx) {
    Type *I64Ty = Type::getInt64Ty(Ctx);

    GlobalVariable *GV = M.getNamedGlobal("__dominator_num");
    if (GV)
      return GV;

    GV = new GlobalVariable(
        M, I64Ty, true, GlobalValue::ExternalLinkage, nullptr,
        "__dominator_num");
    GV->setAlignment(MaybeAlign(8));
    return GV;
  }

  bool instrumentBasicBlock(BasicBlock &BB,
                            GlobalVariable *CountsGV,
                            GlobalVariable *SeenGV,
                            uint64_t EntryID,
                            uint64_t &InstrumentedCount) {
    Instruction *InsertPt = BB.getFirstNonPHI();
    if (!InsertPt)
      return false;

    LLVMContext &Ctx = BB.getContext();
    IRBuilder<> IRB(InsertPt);

    Type *I32Ty = Type::getInt32Ty(Ctx);
    Type *I64Ty = Type::getInt64Ty(Ctx);
    Type *I8Ty = Type::getInt8Ty(Ctx);

    auto *CountsArrTy = cast<ArrayType>(CountsGV->getValueType());
    auto *SeenArrTy = cast<ArrayType>(SeenGV->getValueType());

    Value *Zero32 = ConstantInt::get(I32Ty, 0);
    Value *Idx32 = ConstantInt::get(I32Ty, static_cast<uint32_t>(EntryID));

    Value *CountPtr = IRB.CreateInBoundsGEP(
        CountsArrTy, CountsGV, {Zero32, Idx32}, "dom_count_ptr");
    LoadInst *OldCount = IRB.CreateLoad(I64Ty, CountPtr, "dom_old_count");
    Value *NewCount = IRB.CreateAdd(
        OldCount, ConstantInt::get(I64Ty, 1), "dom_new_count");
    IRB.CreateStore(NewCount, CountPtr);

    Value *SeenPtr = IRB.CreateInBoundsGEP(
        SeenArrTy, SeenGV, {Zero32, Idx32}, "dom_seen_ptr");
    IRB.CreateStore(ConstantInt::get(I8Ty, 1), SeenPtr);

    ++InstrumentedCount;
    return true;
  }

  bool runOnModule(Module &M) override {
    if (!loadManifest())
      return false;

    // Build module-side indexes before adding any coverage globals/instructions.
    // This is especially important in -dominator-exact-module mode: every
    // function/BB key is captured from the pristine analysis module.
    std::map<std::string, std::vector<ModuleBBInfo>> FunctionBBs;
    std::map<DomKey, BasicBlock *> ModuleBBIndex;

    for (Function &F : M) {
      if (F.isDeclaration())
        continue;

      std::string FuncName = normalizeFunctionName(F.getName());
      for (BasicBlock &BB : F) {
        ModuleBBInfo Info;
        Info.BB = &BB;
        Info.BBName = normalizeBasicBlockName(BB);
        Info.SourceLines = getAllSourceLines(BB);
        Info.HasRepresentativeLine =
            getRepresentativeSourceLine(Info.SourceLines, Info.RepresentativeLine);

        FunctionBBs[FuncName].push_back(Info);
        ModuleBBIndex[{FuncName, Info.BBName}] = &BB;
      }
    }

    LLVMContext &Ctx = M.getContext();
    GlobalVariable *CountsGV = getOrCreateCountsArray(M, Ctx);
    GlobalVariable *SeenGV = getOrCreateSeenArray(M, Ctx);
    (void)getOrCreateNumDominators(M, Ctx);

    errs() << "[dominator-pass] mode: exact_module="
           << (DominatorExactModule ? "yes" : "no") << "\n";

    bool Modified = false;
    uint64_t MatchedManifestEntries = 0;
    uint64_t InstrumentedCount = 0;
    uint64_t ExactBBMatches = 0;
    uint64_t SourceSetExactMatches = 0;
    uint64_t SourceOverlapMatches = 0;
    uint64_t BBFallbackMatches = 0;
    uint64_t FunctionAbsentEntries = 0;
    uint64_t NoSourceLineEntries = 0;
    uint64_t NoSourceOverlapEntries = 0;
    uint64_t AmbiguousSourceEntries = 0;
    uint64_t UnmatchedEntries = 0;

    for (const DomEntry &Entry : DomEntries) {
      BasicBlock *MatchedBB = nullptr;
      std::string MatchMethod;
      std::string SourceFailureReason;
      uint64_t BestOverlap = 0;
      std::vector<const ModuleBBInfo *> BestCandidates;

      if (DominatorExactModule) {
        // Same-BC mode: the dominator was extracted from this exact module.bc.
        // Therefore function + original BB identity must match directly.
        // Source lines remain diagnostics only and are never used to guess.
        auto FuncIt = FunctionBBs.find(Entry.Function);
        if (FuncIt == FunctionBBs.end()) {
          ++FunctionAbsentEntries;
          SourceFailureReason = "function-not-present-in-exact-module";
        } else {
          DomKey BBKey = {Entry.Function, Entry.OriginalBB};
          auto BBIt = ModuleBBIndex.find(BBKey);
          if (BBIt != ModuleBBIndex.end()) {
            MatchedBB = BBIt->second;
            MatchMethod = "exact-bb";
          } else {
            SourceFailureReason = "exact-bb-not-found";
          }
        }
      } else {
        // Legacy/recompile mode: source-line sets are preferred because BB
        // numbers and BB boundaries may change across separate compilations.
        auto FuncIt = FunctionBBs.find(Entry.Function);
        if (FuncIt == FunctionBBs.end()) {
          ++FunctionAbsentEntries;
          SourceFailureReason = "function-not-present";
        } else if (Entry.SourceLines.empty()) {
          ++NoSourceLineEntries;
          SourceFailureReason = "manifest-source-lines-unavailable";
        } else {
          // Strongest legacy match: identical complete line set.
          std::vector<const ModuleBBInfo *> ExactCandidates;
          for (const ModuleBBInfo &Info : FuncIt->second) {
            if (!Info.SourceLines.empty() &&
                Info.SourceLines == Entry.SourceLines) {
              ExactCandidates.push_back(&Info);
            }
          }

          if (ExactCandidates.size() == 1) {
            MatchedBB = ExactCandidates.front()->BB;
            MatchMethod = "source-set-exact";
          } else {
            // Recompilation may split/merge BBs. Use the BB with the unique
            // maximum source-line overlap. Ties are deliberately not guessed.
            for (const ModuleBBInfo &Info : FuncIt->second) {
              uint64_t Overlap = intersectionSize(Entry.SourceLines,
                                                  Info.SourceLines);
              if (Overlap == 0)
                continue;

              if (Overlap > BestOverlap) {
                BestOverlap = Overlap;
                BestCandidates.clear();
                BestCandidates.push_back(&Info);
              } else if (Overlap == BestOverlap) {
                BestCandidates.push_back(&Info);
              }
            }

            if (BestOverlap == 0) {
              ++NoSourceOverlapEntries;
              SourceFailureReason = "no-source-line-overlap";
            } else if (BestCandidates.size() == 1) {
              MatchedBB = BestCandidates.front()->BB;
              MatchMethod = "source-set-overlap";
            } else {
              ++AmbiguousSourceEntries;
              SourceFailureReason = "ambiguous-source-line-overlap";
            }
          }
        }

        // Conservative compatibility fallback for separately recompiled IR.
        if (!MatchedBB) {
          DomKey BBKey = {Entry.Function, Entry.OriginalBB};
          auto BBIt = ModuleBBIndex.find(BBKey);
          if (BBIt != ModuleBBIndex.end()) {
            MatchedBB = BBIt->second;
            MatchMethod = "bb-fallback";
          }
        }
      }

      if (!MatchedBB) {
        ++UnmatchedEntries;

        errs() << "[dominator-pass] unmatched: module="
               << M.getModuleIdentifier()
               << " function=" << Entry.Function
               << " original_bb=" << Entry.OriginalBB
               << " representative_line=";
        if (Entry.HasRepresentativeLine)
          errs() << Entry.RepresentativeLine;
        else
          errs() << "?";

        errs() << " source_lines=" << lineSetToString(Entry.SourceLines)
               << " reason=";
        if (DominatorExactModule) {
          if (SourceFailureReason.empty())
            errs() << "exact-bb-match-failed";
          else
            errs() << SourceFailureReason;
        } else {
          if (SourceFailureReason.empty())
            errs() << "source-match-failed-and-bb-fallback-miss";
          else
            errs() << SourceFailureReason << "+bb-fallback-miss";
        }
        errs() << " best_overlap=" << BestOverlap;

        if (BestCandidates.size() > 1) {
          errs() << " candidates=";
          bool First = true;
          for (const ModuleBBInfo *Info : BestCandidates) {
            if (!First)
              errs() << ',';
            errs() << Info->BBName << '[' << lineSetToString(Info->SourceLines)
                   << ']';
            First = false;
          }
        }

        errs() << " id=" << Entry.ID << "\n";
        continue;
      }

      ++MatchedManifestEntries;
      if (MatchMethod == "exact-bb")
        ++ExactBBMatches;
      else if (MatchMethod == "source-set-exact")
        ++SourceSetExactMatches;
      else if (MatchMethod == "source-set-overlap")
        ++SourceOverlapMatches;
      else if (MatchMethod == "bb-fallback")
        ++BBFallbackMatches;

      std::string CurrentBBName = normalizeBasicBlockName(*MatchedBB);
      std::set<unsigned> CurrentLines = getAllSourceLines(*MatchedBB);

      errs() << "[dominator-pass] match: module="
             << M.getModuleIdentifier()
             << " function=" << Entry.Function
             << " original_bb=" << Entry.OriginalBB
             << " current_bb=" << CurrentBBName
             << " representative_line=";
      if (Entry.HasRepresentativeLine)
        errs() << Entry.RepresentativeLine;
      else
        errs() << "?";

      errs() << " source_lines=" << lineSetToString(Entry.SourceLines)
             << " current_source_lines=" << lineSetToString(CurrentLines)
             << " overlap=" << intersectionSize(Entry.SourceLines, CurrentLines)
             << " method=" << MatchMethod
             << " id=" << Entry.ID << "\n";

      if (instrumentBasicBlock(
              *MatchedBB, CountsGV, SeenGV, Entry.ID, InstrumentedCount)) {
        Modified = true;
        errs() << "[dominator-pass] instrumented: function="
               << Entry.Function
               << " current_bb=" << CurrentBBName
               << " id=" << Entry.ID << "\n";
      } else {
        errs() << "[dominator-pass] WARNING: could not instrument function="
               << Entry.Function
               << " current_bb=" << CurrentBBName
               << " id=" << Entry.ID << "\n";
      }
    }

    errs() << "[dominator-pass] summary: module="
           << M.getModuleIdentifier()
           << ", exact_module=" << (DominatorExactModule ? "yes" : "no")
           << ", matched=" << MatchedManifestEntries
           << ", instrumented=" << InstrumentedCount
           << ", exact_bb_matches=" << ExactBBMatches
           << ", source_set_exact_matches=" << SourceSetExactMatches
           << ", source_overlap_matches=" << SourceOverlapMatches
           << ", bb_fallback_matches=" << BBFallbackMatches
           << ", function_absent_entries=" << FunctionAbsentEntries
           << ", no_source_line_entries=" << NoSourceLineEntries
           << ", no_source_overlap_entries=" << NoSourceOverlapEntries
           << ", ambiguous_source_entries=" << AmbiguousSourceEntries
           << ", unmatched=" << UnmatchedEntries
           << ", manifest_entries=" << DomEntries.size()
           << "\n";

    if (MatchedManifestEntries == 0) {
      errs() << "[dominator-pass] WARNING: no manifest entries matched this module\n";
    }

    return Modified;
  }
};

} // namespace

char DominatorCoveragePass::ID = 0;

static RegisterPass<DominatorCoveragePass>
    X("dominator-cov",
      "Instrument dominator BBs (exact same-module or legacy source-line matching)",
      false,
      false);

static void registerDominatorCoveragePass(
    const PassManagerBuilder &,
    legacy::PassManagerBase &PM) {
  PM.add(new DominatorCoveragePass());
}

static RegisterStandardPasses
    RegisterDominatorCoveragePassOpt(
        PassManagerBuilder::EP_OptimizerLast,
        registerDominatorCoveragePass);

static RegisterStandardPasses
    RegisterDominatorCoveragePassO0(
        PassManagerBuilder::EP_EnabledOnOptLevel0,
        registerDominatorCoveragePass);
