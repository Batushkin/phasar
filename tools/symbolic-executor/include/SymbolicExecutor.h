#ifndef SYMBOLICEXECUTOR_H
#define SYMBOLICEXECUTOR_H

#include "phasar/PhasarLLVM/DataFlow/PathSensitivity/LLVMPathConstraints.h"
#include "phasar/PhasarLLVM/DB/LLVMProjectIRDB.h"
#include "phasar/DataFlow/PathSensitivity/FlowPath.h"

#include "include/FTAResultsParser.h"
#include "include/Utils.h"
#include "include/ConfigGenerator.h"

#include "llvm/IR/Instructions.h"

class SymbolicExecutor
{
protected:
  std::unique_ptr<psr::LLVMProjectIRDB> IRDB;
  psr::LLVMPathConstraints LPC;
  Utils Utils;

public:
  void doAnalysis(
    const std::string &llvmFilePath,
    std::vector<struct FTAResultsParser::taintedInst> taintedInsts,
    std::vector<std::string> configOptions,
    size_t MaxDAGDepth = SIZE_MAX);

private:
  void printPath(psr::FlowPath<const llvm::Instruction*> path);

  // Paths which are always traversed do not change an application's
  // performance and are filtered out with this function
  psr::FlowPathSequence<const llvm::Instruction *>
  filterOutNonConditionalPaths(
    psr::FlowPathSequence<const llvm::Instruction *> paths);

}; // end of class SymbolicExecutor

#endif