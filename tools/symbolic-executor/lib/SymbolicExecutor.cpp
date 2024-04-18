#include "phasar/DataFlow/IfdsIde/Solver/PathAwareIDESolver.h"
#include "phasar/DataFlow/PathSensitivity/PathSensitivityManager.h"
#include "phasar/PhasarLLVM/ControlFlow/LLVMBasedICFG.h"
#include "phasar/PhasarLLVM/DataFlow/IfdsIde/Problems/IDEExtendedTaintAnalysis.h"
#include "phasar/PhasarLLVM/DataFlow/IfdsIde/Problems/IDELinearConstantAnalysis.h"
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

#include "llvm/ADT/STLExtras.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instruction.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/raw_ostream.h"

#include "include/ConfigGenerator.h"
#include "include/SymbolicExecutor.h"

#include "z3++.h"
#include "yaml-cpp/yaml.h"

#include <cassert>
#include <fstream>
#include <memory>
#include <new>
#include <string>
#include <system_error>
#include <vector>

void SymbolicExecutor::doAnalysis(const std::string &llvmFilePath,
                   std::vector<struct FTAResultsParser::taintedInst> taintedInsts,
                   std::vector<std::string> configOptions,
                   size_t MaxDAGDepth) {
  // Set up path tracing
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

  //ICFG.print();
  //Solver.dumpResults();  // Prints instructions with their IDs
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

  ConfigGenerator CG(taintedInsts, configOptions);

  // For each tainted instruction
  for (struct FTAResultsParser::taintedInst currInst : taintedInsts) {
    // print the instruction location and its taints
    llvm::outs() << "Loop br instruction at " << currInst.loc << " is tainted by [";
    std::vector<std::string> taints = currInst.taints;
    for (unsigned long i = 0; i < taints.size(); ++i) {
      if (i == taints.size() - 1) {
        llvm::outs() <<  taints[i] << "]\n";
      } else {
        llvm::outs() << taints[i] << ", ";
      }  
    }
    llvm::outs().flush();

    // get the llvm::Function
    llvm::outs() << currInst.func << "\n";
    llvm::outs().flush();
    //Utils.printSymbolTable(*IRDB->getModule());
    llvm::Function *func = IRDB->getFunction(currInst.func);
    //llvm::outs() << func;
    assert(func);
    // get the llvm::Instruction
    llvm::Instruction *currLLVMInst = Utils.getInstFromFunc(*func, currInst.inst);
    //llvm::outs() << inst->getName();

    // get the loop condition BB
    llvm::BasicBlock *currBB = currLLVMInst->getParent();

    // get the variables in the loop condition
    std::vector<std::string> condVars = CG.getConditionVars(currBB);
    //llvm::outs() << "BB: " << currBB->getName() << "\n";
    //llvm::outs().flush();

    // the first destination BB is the loop body BB
    llvm::BasicBlock *loopBodyBB = Utils.getFirstDestinationBB(currLLVMInst);
      
    // Compute the paths to the first inst in the loop body BB
    llvm::Instruction* I = loopBodyBB->getFirstNonPHIOrDbg();
    //llvm::outs() << "Instruction: " << *I << "\n";
    //llvm::outs().flush();
    psr::FlowPathSequence<const llvm::Instruction*> pathsToCurrInst = PSM.pathsTo(I, Analysis.getZeroValue());
    pathsToCurrInst = filterOutNonConditionalPaths(pathsToCurrInst);
    
    if (!pathsToCurrInst.empty()) {
      int numValueRanges = 0;
      std::vector<std::vector<ConfigGenerator::ValueRange>> knownPathValRanges;

      for (psr::FlowPath<const llvm::Instruction *> path : pathsToCurrInst) {
        //printPath(path);
        z3::model model = path.getModel();
        z3::expr pc = path.getConstraint();

        // split the path constraint into individual constraints
        std::vector<z3::expr> constraints;
        CG.getAndOperands(pc, constraints);

        // Generate value ranges only if the condition variable has multiple assignments
        if (!CG.checkForConstEq(constraints, condVars)) {
          // print the value ranges for the relevant taints
          CG.generateValueRanges(pc, taints, numValueRanges, knownPathValRanges);
        } 
      }

      // print the path constraint
      // llvm::outs() << "PC: " << pc.to_string() << "\n";

      // output the unique value ranges
      for (unsigned long i = 0; i < knownPathValRanges.size(); i++) {
        std::vector<ConfigGenerator::ValueRange> pathValRanges = knownPathValRanges[i];
        llvm::outs() << "Unique Value Ranges Set " << std::to_string(i + 1) << "\n";

        for (ConfigGenerator::ValueRange valRange : pathValRanges) {
          llvm::outs() << valRange.co << " in [" << valRange.min <<
          ", " << valRange.max << "]\n";

          numValueRanges++;
        }

        llvm::outs().flush();
      }
      
      // for evaluation
      llvm::outs() << "Number of Paths: " << std::to_string(pathsToCurrInst.size()) << "\n";
      llvm::outs() << "Number of ValueRanges: " << std::to_string(numValueRanges) << "\n";
      llvm::outs().flush();
    } else {
      llvm::outs() << "No paths found by the path tracing!\n";
      llvm::outs().flush();
    }    
  }
}

void SymbolicExecutor::printPath(psr::FlowPath<const llvm::Instruction*> path) {
  llvm::ArrayRef<const llvm::Instruction *> arrayRefPath = path;
  std::cout << "Path: ";

  for (auto it = arrayRefPath.begin(); it != arrayRefPath.end(); ++it) {
    std::cout << psr::getMetaDataID(*it) << " ";
  }
}

psr::FlowPathSequence<const llvm::Instruction *>
SymbolicExecutor::filterOutNonConditionalPaths(
  psr::FlowPathSequence<const llvm::Instruction *> paths) {
    
  psr::FlowPathSequence<const llvm::Instruction *> filteredPaths;
    
  for (psr::FlowPath<const llvm::Instruction *> path : paths) {
    z3::model Model = path.getModel();
    z3::expr Constraint = path.getConstraint();

    // filter out insts that are always executed
    if (Constraint.to_string().compare("true") != 0) {
      filteredPaths.push_back(path);
    }
  }

  return filteredPaths;
}
