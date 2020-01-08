/******************************************************************************
 * Copyright (c) 2017 Philipp Schubert.
 * All rights reserved. This program and the accompanying materials are made
 * available under the terms of LICENSE.txt.
 *
 * Contributors:
 *     Philipp Schubert and others
 *****************************************************************************/

#ifndef PHASAR_CONTROLLER_ANALYSIS_CONTROLLER_H_
#define PHASAR_CONTROLLER_ANALYSIS_CONTROLLER_H_

#include <iosfwd>
#include <set>
#include <string>
#include <vector>

#include <phasar/DB/ProjectIRDB.h>
#include <phasar/PhasarLLVM/AnalysisStrategy/Strategies.h>
#include <phasar/PhasarLLVM/ControlFlow/LLVMBasedICFG.h>
#include <phasar/PhasarLLVM/Pointer/LLVMPointsToInfo.h>
#include <phasar/PhasarLLVM/TypeHierarchy/LLVMTypeHierarchy.h>
#include <phasar/PhasarLLVM/Utils/DataFlowAnalysisType.h>

namespace psr {

class AnalysisController {
private:
  ProjectIRDB &IRDB;
  LLVMTypeHierarchy TH;
  LLVMPointsToInfo PT;
  LLVMBasedICFG ICF;
  std::vector<DataFlowAnalysisType> DataFlowAnalyses;
  std::vector<std::string> AnalysisConfigs;
  std::set<std::string> EntryPoints;
  AnalysisStrategy Strategy;

  void executeDemandDriven();
  void executeIncremental();
  void executeModuleWise();
  void executeVariational();
  void executeWholeProgram();

public:
  AnalysisController(ProjectIRDB &IRDB,
                     std::vector<DataFlowAnalysisType> DataFlowAnalyses,
                     std::vector<std::string> AnalysisConfigs,
                     std::set<std::string> EntryPoints,
                     AnalysisStrategy Strategy);
  ~AnalysisController() = default;
  AnalysisController(const AnalysisController &) = delete;
  AnalysisController(AnalysisController &&) = delete;

  void executeAs(AnalysisStrategy Strategy);
};

} // namespace psr

#endif
