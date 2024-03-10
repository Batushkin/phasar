/******************************************************************************
 * Copyright (c) 2023 Hristo Klechorov.
 * All rights reserved. This program and the accompanying materials are made
 * available under the terms of LICENSE.txt.
 *
 * Contributors:
 *     Hristo Klechorov and others
 *****************************************************************************/

#include "phasar/DataFlow/IfdsIde/Solver/PathAwareIDESolver.h"
#include "phasar/DataFlow/PathSensitivity/FlowPath.h"
#include "phasar/DataFlow/PathSensitivity/PathSensitivityManager.h"
#include "phasar/PhasarLLVM/ControlFlow/LLVMBasedICFG.h"
#include "phasar/PhasarLLVM/DB/LLVMProjectIRDB.h"
#include "phasar/PhasarLLVM/DataFlow/IfdsIde/Problems/IDEExtendedTaintAnalysis.h"
#include "phasar/PhasarLLVM/DataFlow/IfdsIde/Problems/IDELinearConstantAnalysis.h"
#include "phasar/PhasarLLVM/DataFlow/PathSensitivity/LLVMPathConstraints.h"
#include "phasar/PhasarLLVM/DataFlow/PathSensitivity/Z3BasedPathSensitivityConfig.h"
#include "phasar/PhasarLLVM/DataFlow/PathSensitivity/Z3BasedPathSensitvityManager.h"
#include "phasar/PhasarLLVM/Passes/ValueAnnotationPass.h"
#include "phasar/PhasarLLVM/Pointer/LLVMAliasSet.h"
#include "phasar/PhasarLLVM/TaintConfig/LLVMTaintConfig.h"
#include "phasar/PhasarLLVM/TypeHierarchy/LLVMTypeHierarchy.h"
#include "phasar/PhasarLLVM/Utils/LLVMShorthands.h"
#include "phasar/Utils/AdjacencyList.h"
#include "phasar/Utils/DFAMinimizer.h"
#include "phasar/Utils/DebugOutput.h"
#include "phasar/Utils/GraphTraits.h"
#include "phasar/Utils/Logger.h"
#include "phasar/Utils/Utilities.h"
#include "phasar/DataFlow/IfdsIde/SolverResults.h"

#include "include/FTAResultsParser.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/raw_ostream.h"

#include "z3++.h"
#include "yaml-cpp/yaml.h"

#include <cassert>
#include <fstream>
#include <memory>
#include <new>
#include <string>
#include <system_error>
#include <vector>

namespace {

class SymbolicExecutor {

protected:
  std::unique_ptr<psr::LLVMProjectIRDB> IRDB;
  psr::LLVMPathConstraints LPC;

public:
  psr::FlowPathSequence<const llvm::Instruction *>
  doAnalysis(const std::string &llvmFilePath,
                  size_t MaxDAGDepth = SIZE_MAX) {
    IRDB = std::make_unique<psr::LLVMProjectIRDB>(llvmFilePath);
    psr::LLVMTypeHierarchy TH(*IRDB);
    psr::LLVMAliasSet PT(IRDB.get());
    psr::LLVMBasedICFG ICFG(IRDB.get(), psr::CallGraphAnalysisType::OTF,
                            {"main"}, &TH, &PT, psr::Soundness::Soundy,
                            /*includedGlobals*/ false);

    psr::LLVMTaintConfig Config(*IRDB);
    psr::IDEExtendedTaintAnalysis<3, false> Analysis(IRDB.get(), &ICFG, &PT,
                                                     Config, {"main"});

    psr::PathAwareIDESolver Solver(Analysis, &ICFG);
    Solver.solve();

    //IRDB->print();
    //ICFG.print();
    //Solver.dumpResults();
    //Solver.emitTextReport();

    /*
    // Print the exploded Graph as DOT
    std::error_code EC;
    llvm::raw_fd_ostream ROS(llvmFilePath + "_explicit_esg_dot", EC);
    assert(!EC);
    Solver.getExplicitESG().printAsDot(ROS);
    */

    psr::Z3BasedPathSensitivityManager<psr::IDEExtendedTaintAnalysisDomain> PSM(
        &Solver.getExplicitESG(),
        psr::Z3BasedPathSensitivityConfig().withDAGDepthThreshold(MaxDAGDepth),
        &LPC);

    /*llvm::Module mod = IRDB->getModule();
    auto functionsList = mod.getFunctionList();
      for (llvm::Function func : functionsList) {
      assert(func);

    }*/

    // get llvm function main
    auto *Main = IRDB->getFunctionDefinition("main");
    assert(Main);
    // get the last instruction of the last basic block in the main function
    auto *LastInst = &Main->back().back();
    
    //z3::expr constraint = LPC.getConstraintFromEdge(LastInst->getPrevNonDebugInstruction(), LastInst).value();
    //std::cout << "Edge Constraint Test: " << constraint;

    llvm::outs() << "Target instruction: " << psr::llvmIRToString(LastInst)
                 << '\n';

    auto result = PSM.pathsTo(LastInst, Analysis.getZeroValue());
    return result;
  }

}; // end of class SymbolicExecutor

} // close namespace

int main(int argc, char **argv) {
  SymbolicExecutor executor;
  std::string filePath = argv[1];
  std::string fileFTA = argv[2];

  FTAResultsParser parser;
  std::vector<struct FTAResultsParser::taintedInst> taintedInsts = parser.parseFTAResults(fileFTA);

  for(int i = 0; i < taintedInsts.size(); i++) {
    struct FTAResultsParser::taintedInst currInst = taintedInsts[i];
    std::cout << currInst.inst << currInst.loc << currInst.func << "\n";
  }
  
  std::vector<psr::FlowPath<const llvm::Instruction *>> result = executor.doAnalysis(filePath);

  // print the paths vector
  for (psr::FlowPath<const llvm::Instruction *> path : result) {
    z3::model Model = path.getModel();
    z3::expr Constraint = path.getConstraint();

    llvm::ArrayRef<const llvm::Instruction *> arrayRefPath = path;
    std::cout << "Path: ";
    for (auto it = arrayRefPath.begin(); it != arrayRefPath.end(); ++it) {
      std::cout << psr::getMetaDataID(*it) << " ";
    }

    std::cout << "PC: " << Constraint;
    //std::cout << "Eval Res: " << Model.eval(Constraint, true) << "\n";

  }
  
  return 0;
}