#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <map>
#include <string>
#include <utility>

using namespace llvm;

static cl::opt<std::string> DominatorMapPath(
    "dominator-map",
    cl::desc("Path to dominator manifest TSV: <id>\\t<function>\\t<bb>"),
    cl::init(""));

namespace {

struct DominatorCoveragePass : public ModulePass {
  static char ID;
  DominatorCoveragePass() : ModulePass(ID) {}

  using DomKey = std::pair<std::string, std::string>;

  std::map<DomKey, uint64_t> DomMap;
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
    BB.printAsOperand(OS, false);   // e.g. %13
    OS.flush();

    if (!S.empty() && S[0] == '%')
      S.erase(0, 1);                // %13 -> 13

    return S;
  }

  bool loadManifest() {
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

      SmallVector<StringRef, 4> Parts;
      Line.split(Parts, '\t', -1, false);

      if (Parts.size() < 3) {
        errs() << "[dominator-pass] WARNING: malformed line: " << Line << "\n";
        continue;
      }

      uint64_t ID = 0;
      if (Parts[0].trim().getAsInteger(10, ID)) {
        errs() << "[dominator-pass] WARNING: invalid ID in line: " << Line
               << "\n";
        continue;
      }

      std::string FuncName = Parts[1].trim().str();
      std::string BBName = Parts[2].trim().str();

      if (FuncName.empty() || BBName.empty()) {
        errs() << "[dominator-pass] WARNING: empty function/bb in line: "
               << Line << "\n";
        continue;
      }

      DomKey Key = {FuncName, BBName};
      DomMap[Key] = ID;

      if (!SawAny || ID > MaxID)
        MaxID = ID;

      SawAny = true;
    }

    if (!SawAny) {
      errs() << "[dominator-pass] ERROR: no valid dominator entries loaded\n";
      return false;
    }

    NumDominators = MaxID + 1;

    errs() << "[dominator-pass] loaded " << DomMap.size()
           << " dominator entries, NumDominators=" << NumDominators << "\n";

    return true;
  }

  GlobalVariable *getOrCreateCountsArray(Module &M, LLVMContext &Ctx) {
    Type *I64Ty = Type::getInt64Ty(Ctx);
    ArrayType *CountsTy = ArrayType::get(I64Ty, NumDominators);

    GlobalVariable *GV = M.getNamedGlobal("__dominator_counts");
    if (GV)
      return GV;

    GV = new GlobalVariable(
        M,
        CountsTy,
        false,
        GlobalValue::ExternalLinkage,
        nullptr,
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
        M,
        SeenTy,
        false,
        GlobalValue::ExternalLinkage,
        nullptr,
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
        M,
        I64Ty,
        true,
        GlobalValue::ExternalLinkage,
        nullptr,
        "__dominator_num");

    GV->setAlignment(MaybeAlign(8));
    return GV;
  }

  bool instrumentBasicBlock(BasicBlock &BB,
                            GlobalVariable *CountsGV,
                            GlobalVariable *SeenGV,
                            uint64_t ID,
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
    Value *Idx32 = ConstantInt::get(I32Ty, static_cast<uint32_t>(ID));

    Value *CountPtr = IRB.CreateInBoundsGEP(
        CountsArrTy, CountsGV, {Zero32, Idx32}, "dom_count_ptr");

    LoadInst *OldCount = IRB.CreateLoad(I64Ty, CountPtr, "dom_old_count");
    Value *NewCount =
        IRB.CreateAdd(OldCount, ConstantInt::get(I64Ty, 1), "dom_new_count");
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

    LLVMContext &Ctx = M.getContext();

    GlobalVariable *CountsGV = getOrCreateCountsArray(M, Ctx);
    GlobalVariable *SeenGV = getOrCreateSeenArray(M, Ctx);
    (void)getOrCreateNumDominators(M, Ctx);

    bool Modified = false;
    uint64_t InstrumentedCount = 0;
    uint64_t MatchedManifestEntries = 0;

    for (Function &F : M) {
      if (F.isDeclaration())
        continue;

      std::string FuncName = normalizeFunctionName(F.getName());

      for (BasicBlock &BB : F) {
        std::string BBName = normalizeBasicBlockName(BB);

        DomKey Key = {FuncName, BBName};

        auto It = DomMap.find(Key);
        if (It == DomMap.end()) {
          continue;
        }

        uint64_t ID = It->second;
        ++MatchedManifestEntries;

        errs() << "[dominator-pass] match: function=" << FuncName
               << " bb=" << BBName
               << " id=" << ID << "\n";

        if (instrumentBasicBlock(BB, CountsGV, SeenGV, ID, InstrumentedCount)) {
          Modified = true;
        } else {
          errs() << "[dominator-pass] WARNING: could not instrument function="
                 << FuncName << " bb=" << BBName << "\n";
        }
      }
    }

    errs() << "[dominator-pass] summary: matched=" << MatchedManifestEntries
           << ", instrumented=" << InstrumentedCount
           << ", manifest_entries=" << DomMap.size() << "\n";

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
      "Instrument dominator basic blocks only",
      false,
      false);

static void registerDominatorCoveragePass(const PassManagerBuilder &,
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
