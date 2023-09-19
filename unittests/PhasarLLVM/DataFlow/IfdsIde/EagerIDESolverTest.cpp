#include "phasar/DataFlow/IfdsIde/Solver/EagerIDESolver.h"

#include "phasar/DataFlow/IfdsIde/Solver/IDESolver.h"
#include "phasar/DataFlow/IfdsIde/Solver/SolverStrategy.h"
#include "phasar/PhasarLLVM/ControlFlow/LLVMBasedICFG.h"
#include "phasar/PhasarLLVM/DB/LLVMProjectIRDB.h"
#include "phasar/PhasarLLVM/DataFlow/IfdsIde/Problems/IDELinearConstantAnalysis.h"
#include "phasar/PhasarLLVM/HelperAnalyses.h"
#include "phasar/PhasarLLVM/SimpleAnalysisConstructor.h"
#include "phasar/Utils/Logger.h"
#include "phasar/Utils/Printer.h"
#include "phasar/Utils/TypeTraits.h"

#include "TestConfig.h"
#include "gtest/gtest.h"

#include <memory>
#include <tuple>

using namespace psr;

namespace {

/* ============== TEST FIXTURE ============== */
class LinearConstant : public ::testing::TestWithParam<std::string_view> {
protected:
  static constexpr auto PathToLlFiles =
      PHASAR_BUILD_SUBFOLDER("linear_constant/");
  const std::vector<std::string> EntryPoints = {"main"};

}; // Test Fixture

TEST_P(LinearConstant, ResultsEquivalentPropagateOnto) {
  HelperAnalyses HA(PathToLlFiles + GetParam(), EntryPoints);

  // Compute the ICFG to possibly create the runtime model
  auto &ICFG = HA.getICFG();

  auto HasGlobalCtor = HA.getProjectIRDB().getFunctionDefinition(
                           LLVMBasedICFG::GlobalCRuntimeModelName) != nullptr;

  auto LCAProblem = createAnalysisProblem<IDELinearConstantAnalysis>(
      HA,
      std::vector{HasGlobalCtor ? LLVMBasedICFG::GlobalCRuntimeModelName.str()
                                : "main"});

  auto PropagateOverResults = IDESolver(LCAProblem, &ICFG).solve();
  {
    // psr::Logger::initializeStderrLogger(SeverityLevel::DEBUG);

    auto PropagateOntoResults =
        IDESolver(LCAProblem, &ICFG, PropagateOntoStrategy{}).solve();

    // PropagateOntoResults.dumpResults(ICFG);

    for (auto &&Cell : PropagateOntoResults.getAllResultEntries()) {
      const auto *Stmt = Cell.getRowKey();
      if (Stmt->isTerminator()) {
        continue;
      }
      const auto *NextStmt = Stmt->getNextNonDebugInstruction();
      assert(NextStmt != nullptr);

      auto PropagateOverRes =
          PropagateOverResults.resultAt(NextStmt, Cell.getColumnKey());
      EXPECT_EQ(PropagateOverRes, Cell.getValue())
          << "The Incoming results of the eager IDE solver should match the "
             "outgoing results of the default solver. Expected: ("
          << NToString(NextStmt) << ", " << DToString(Cell.getColumnKey())
          << ") --> " << LToString(PropagateOverRes) << "; got "
          << LToString(Cell.getValue());
    }
  }
}

static constexpr std::string_view LCATestFiles[] = {
    "basic_01_cpp_dbg.ll",
    "basic_02_cpp_dbg.ll",
    "basic_03_cpp_dbg.ll",
    "basic_04_cpp_dbg.ll",
    "basic_05_cpp_dbg.ll",
    "basic_06_cpp_dbg.ll",
    "basic_07_cpp_dbg.ll",
    "basic_08_cpp_dbg.ll",
    "basic_09_cpp_dbg.ll",
    "basic_10_cpp_dbg.ll",
    "basic_11_cpp_dbg.ll",
    "basic_12_cpp_dbg.ll",

    "branch_01_cpp_dbg.ll",
    "branch_02_cpp_dbg.ll",
    "branch_03_cpp_dbg.ll",
    "branch_04_cpp_dbg.ll",
    "branch_05_cpp_dbg.ll",
    "branch_06_cpp_dbg.ll",
    "branch_07_cpp_dbg.ll",

    "while_01_cpp_dbg.ll",
    "while_02_cpp_dbg.ll",
    "while_03_cpp_dbg.ll",
    "while_04_cpp_dbg.ll",
    "while_05_cpp_dbg.ll",
    "for_01_cpp_dbg.ll",

    "call_01_cpp_dbg.ll",
    "call_02_cpp_dbg.ll",
    "call_03_cpp_dbg.ll",
    "call_04_cpp_dbg.ll",
    "call_05_cpp_dbg.ll",
    "call_06_cpp_dbg.ll",
    "call_07_cpp_dbg.ll",
    "call_08_cpp_dbg.ll",
    "call_09_cpp_dbg.ll",
    "call_10_cpp_dbg.ll",
    "call_11_cpp_dbg.ll",

    "recursion_01_cpp_dbg.ll",
    "recursion_02_cpp_dbg.ll",
    "recursion_03_cpp_dbg.ll",

    "global_01_cpp_dbg.ll",
    "global_02_cpp_dbg.ll",
    "global_03_cpp_dbg.ll",
    "global_04_cpp_dbg.ll",
    "global_05_cpp_dbg.ll",
    "global_06_cpp_dbg.ll",
    "global_07_cpp_dbg.ll",
    "global_08_cpp_dbg.ll",
    "global_09_cpp_dbg.ll",
    "global_10_cpp_dbg.ll",
    "global_11_cpp_dbg.ll",
    "global_12_cpp_dbg.ll",
    "global_13_cpp_dbg.ll",
    "global_14_cpp_dbg.ll",
    "global_15_cpp_dbg.ll",
    "global_16_cpp_dbg.ll",

    "overflow_add_cpp_dbg.ll",
    "overflow_sub_cpp_dbg.ll",
    "overflow_mul_cpp_dbg.ll",
    "overflow_div_min_by_neg_one_cpp_dbg.ll",

    "ub_division_by_zero_cpp_dbg.ll",
    "ub_modulo_by_zero_cpp_dbg.ll",
};

INSTANTIATE_TEST_SUITE_P(InteractiveIDESolverTest, LinearConstant,
                         ::testing::ValuesIn(LCATestFiles));
} // namespace

// main function for the test case
int main(int Argc, char **Argv) {
  ::testing::InitGoogleTest(&Argc, Argv);
  return RUN_ALL_TESTS();
}
