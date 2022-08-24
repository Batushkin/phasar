/******************************************************************************
 * Copyright (c) 2022 Philipp Schubert.
 * All rights reserved. This program and the accompanying materials are made
 * available under the terms of LICENSE.txt.
 *
 * Contributors:
 *     Fabian Schiebel and others
 *****************************************************************************/

#ifndef PHASAR_PHASARLLVM_DATAFLOWSOLVER_PATHSENSITIVITY_EXPLODEDSUPERGRAPH_H
#define PHASAR_PHASARLLVM_DATAFLOWSOLVER_PATHSENSITIVITY_EXPLODEDSUPERGRAPH_H

#include "phasar/PhasarLLVM/Utils/Printer.h"
#include "phasar/Utils/LLVMIRToSrc.h"
#include "phasar/Utils/StableVector.h"
#include "phasar/Utils/Utilities.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/TinyPtrVector.h"
#include "llvm/ADT/iterator_range.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_os_ostream.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdio>
#include <memory_resource>
#include <numeric>
#include <set>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>

namespace psr {

/// An explicit representation of the ExplodedSuperGraph (ESG) of an IFDS/IDE
/// analysis.
///
/// Not all covered instructions of a BasicBlock might be present; however, it
/// is guaranteed that for each BasicBlock covered by the analysis there is at
/// least one node in the ExplicitESG containing an instruction from that BB.
template <typename AnalysisDomainTy> class ExplodedSuperGraph {
public:
  using n_t = typename AnalysisDomainTy::n_t;
  using d_t = typename AnalysisDomainTy::d_t;

  struct Node {
    d_t Value{};
    n_t Source{};
    Node *Predecessor = nullptr;
    llvm::TinyPtrVector<Node *> Neighbors;
  };

  explicit ExplodedSuperGraph(
      d_t ZeroValue, const psr::NodePrinter<AnalysisDomainTy> &NPrinter,
      const psr::DataFlowFactPrinter<AnalysisDomainTy>
          &DPrinter) noexcept(std::is_nothrow_move_constructible_v<d_t>)
      : ZeroValue(std::move(ZeroValue)), NPrinter(NPrinter),
        DPrinter(DPrinter) {}

  [[nodiscard]] Node *getNodeOrNull(n_t Inst, d_t Fact) const {
    auto It = FlowFactVertexMap.find(
        std::make_pair(std::move(Inst), std::move(Fact)));
    if (It != FlowFactVertexMap.end()) {
      return It->second;
    }
    return nullptr;
  }

  [[nodiscard]] const d_t &getZeroValue() const noexcept { return ZeroValue; }

  template <typename Container>
  void saveEdges(n_t Curr, d_t CurrNode, n_t Succ, const Container &SuccNodes,
                 bool /*IsInterProc*/) {
    auto Pred = getNodeOrNull(Curr, std::move(CurrNode));
    for (const d_t &SuccNode : SuccNodes) {
      saveEdge(Pred, Curr, CurrNode, Succ, SuccNode);
    }
  }

  // NOLINTNEXTLINE(readability-identifier-naming)
  [[nodiscard]] auto node_begin() const noexcept { return NodeOwner.cbegin(); }
  // NOLINTNEXTLINE(readability-identifier-naming)
  [[nodiscard]] auto node_end() const noexcept { return NodeOwner.cend(); }
  [[nodiscard]] auto nodes() const noexcept {
    return llvm::make_range(node_begin(), node_end());
  }

  [[nodiscard]] size_t size() const noexcept { return NodeOwner.size(); }

  // LLVM_DUMP_METHOD void dump() const { node_owner.dump(llvm::errs()); }

  void validate(Node *Vtx) const noexcept {

    // NOLINTNEXTLINE(readability-identifier-naming)
    auto toHexString = [](void *ptr) {
      std::string Ret(2 + 2 * sizeof(void *), '\0');
      Ret.resize(snprintf(Ret.data(), Ret.size() + 1, "%p", ptr));
      return Ret;
    };

    if (!NodeOwner.member(Vtx)) {
      llvm::report_fatal_error(llvm::StringRef("Vtx ") + toHexString(Vtx) +
                               " is no member of the NodeOwner!");
    }

    for (auto *NB : Vtx->Neighbors) {
      if (!NodeOwner.member(NB)) {
        llvm::report_fatal_error(llvm::StringRef("NB ") + toHexString(Vtx) +
                                 " of Vtx " + toHexString(Vtx) +
                                 " is no member of the NodeOwner!");
      }
    }

    if (Vtx->Predecessor && !NodeOwner.member(Vtx->Predecessor)) {
      llvm::report_fatal_error(
          llvm::StringRef("Pred ") + toHexString(Vtx->Predecessor) +
          " of Vtx " + toHexString(Vtx) + " is no member of the NodeOwner!");
    }
  }

  /// Printing:

  void printAsDot(llvm::raw_ostream &OS) const {
    OS << "digraph ESG{\n";
    psr::scope_exit ClosingBrace = [&OS] { OS << '}'; };

    for (const auto &Nod : NodeOwner) {

      OS << intptr_t(&Nod) << "[label=\"";
      OS.write_escaped(DPrinter.DtoString(Nod.value)) << "\"];\n";

      OS << intptr_t(&Nod) << "->" << intptr_t(Nod.predecessor)
         << R"([style="bold" label=")";
      OS.write_escaped(NPrinter.NtoString(Nod.source)) << "\"];\n";
      for (auto *NB : Nod.neighbors) {
        OS << intptr_t(&Nod) << "->" << intptr_t(NB) << "[color=\"red\"];\n";
      }
    }
  }

  void printAsDot(std::ostream &OS) const {
    llvm::raw_os_ostream ROS(OS);
    printAsDot(ROS);
  }

  void printESGNodes(llvm::raw_ostream &OS) const {
    for (const auto &[Node, Vtx] : FlowFactVertexMap) {
      OS << "( " << NPrinter.NtoString(Node.first) << "; "
         << DPrinter.DtoString(Node.second) << " )\n";
    }
  }

private:
  struct PathInfoHash {
    size_t operator()(const std::pair<n_t, d_t> &ND) const {
      return std::hash<n_t>()(ND.first) * 31 + std::hash<d_t>()(ND.second);
    }
  };

  struct PathInfoEq {
    bool operator()(const std::pair<n_t, d_t> &Lhs,
                    const std::pair<n_t, d_t> &Rhs) const {
      return Lhs.first == Rhs.first && Lhs.second == Rhs.second;
    }
  };

  void saveEdge(Node *Pred, n_t Curr, d_t CurrNode, n_t Succ, d_t SuccNode,
                bool DontSkip = false) {
    auto &SuccVtx = FlowFactVertexMap[std::make_pair(Succ, SuccNode)];

    // NOLINTNEXTLINE(readability-identifier-naming)
    auto makeNode = [this, Pred, Curr,
                     SuccNode{std::move(SuccNode)}]() mutable {
      auto Ret = &NodeOwner.emplace_back();
      Ret->Value = std::move(SuccNode);
      Ret->Predecessor = Pred;

      Ret->Source = Curr;
      return Ret;
    };

    if (!DontSkip && Pred && Pred->Value == SuccNode &&
        Pred->Source->getParent() == Succ->getParent() &&
        SuccNode != ZeroValue) {

      if (!SuccVtx) {
        SuccVtx = Pred;
        return;
      }

      if (Pred == SuccVtx) {
        return;
      }
    }

    if (!SuccVtx) {
      SuccVtx = makeNode();
      return;
    }

    /// Check for meaningless loop:
    if (auto Br = llvm::dyn_cast<llvm::BranchInst>(Curr);
        SuccNode != ZeroValue && Br && !Br->isConditional()) {
      auto Nod = Pred;
      llvm::SmallPtrSet<Node *, 4> VisitedNodes;
      while (Nod && Nod->Value == SuccNode) {
        if (LLVM_UNLIKELY(!VisitedNodes.insert(Nod).second)) {
          printAsDot(llvm::errs());
          llvm::errs().flush();
          abort();
        }
        if (Nod == SuccVtx) {
          llvm::errs() << "> saveEdge -- skip meaningless loop: ("
                       << NPrinter.NtoString(Curr) << ", "
                       << DPrinter.DtoString(CurrNode) << ") --> ("
                       << NPrinter.NtoString(Succ) << ", "
                       << DPrinter.DtoString(SuccNode) << ")\n";
          return;
        }
        Nod = Nod->Predecessor;
      }
    }

    if (SuccVtx->Predecessor != Pred &&
        llvm::none_of(SuccVtx->Neighbors, [Pred](const Node *Nd) {
          return Nd->Predecessor == Pred;
        })) {
      SuccVtx->Neighbors.push_back(makeNode());
      return;
    }
  }

  std::pmr::unsynchronized_pool_resource MRes;
  psr::StableVector<Node> NodeOwner;
  std::pmr::unordered_map<std::pair<n_t, d_t>, Node *, PathInfoHash, PathInfoEq>
      FlowFactVertexMap{&MRes};

  // ZeroValue
  d_t ZeroValue;
  // References to Node and DataFlowFactPrinters required for visualizing the
  // results
  const psr::NodePrinter<AnalysisDomainTy> &NPrinter;
  const psr::DataFlowFactPrinter<AnalysisDomainTy> &DPrinter;
};

} // namespace psr

#endif // PHASAR_PHASARLLVM_DATAFLOWSOLVER_PATHSENSITIVITY_EXPLODEDSUPERGRAPH_H