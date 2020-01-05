/******************************************************************************
 * Copyright (c) 2017 Philipp Schubert.
 * All rights reserved. This program and the accompanying materials are made
 * available under the terms of LICENSE.txt.
 *
 * Contributors:
 *     Philipp Schubert and others
 *****************************************************************************/

#ifndef PHASAR_PHASARLLVM_IFDSIDE_PROBLEMS_IFDSTYPEANALYSIS_H_
#define PHASAR_PHASARLLVM_IFDSIDE_PROBLEMS_IFDSTYPEANALYSIS_H_

#include <map>
#include <set>
#include <string>

#include <phasar/PhasarLLVM/DataFlowSolver/IfdsIde/IFDSTabulationProblem.h>

namespace llvm {
class Instruction;
class Function;
class StructType;
class Value;
} // namespace llvm

namespace psr {

class LLVMBasedICFG;
class LLVMTypeHierarchy;
class LLVMPointsToInfo;

class IFDSTypeAnalysis
    : public IFDSTabulationProblem<const llvm::Instruction *,
                                   const llvm::Value *, const llvm::Function *,
                                   const llvm::StructType *,
                                   const llvm::Value *, LLVMBasedICFG> {
public:
  typedef const llvm::Value *d_t;
  typedef const llvm::Instruction *n_t;
  typedef const llvm::Function *m_t;
  typedef const llvm::StructType *t_t;
  typedef const llvm::Value *v_t;
  typedef LLVMBasedICFG i_t;

  IFDSTypeAnalysis(const ProjectIRDB *IRDB, const LLVMTypeHierarchy *TH,
                   const LLVMBasedICFG *ICF, const LLVMPointsToInfo *PT,
                   std::set<std::string> EntryPoints = {"main"});

  ~IFDSTypeAnalysis() override = default;

  FlowFunction<d_t> *getNormalFlowFunction(n_t curr, n_t succ) override;

  FlowFunction<d_t> *getCallFlowFunction(n_t callStmt, m_t destMthd) override;

  FlowFunction<d_t> *getRetFlowFunction(n_t callSite, m_t calleeMthd,
                                        n_t exitStmt, n_t retSite) override;

  FlowFunction<d_t> *getCallToRetFlowFunction(n_t callSite, n_t retSite,
                                              std::set<m_t> callees) override;

  FlowFunction<d_t> *getSummaryFlowFunction(n_t curr, m_t destMthd) override;

  std::map<n_t, std::set<d_t>> initialSeeds() override;

  d_t createZeroValue() const override;

  bool isZeroValue(d_t d) const override;

  void printNode(std::ostream &os, n_t n) const override;

  void printDataFlowFact(std::ostream &os, d_t d) const override;

  void printMethod(std::ostream &os, m_t m) const override;
};
} // namespace psr

#endif
