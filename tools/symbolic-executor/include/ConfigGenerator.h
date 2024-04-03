#ifndef CONFIGGENERATOR_H
#define CONFIGGENERATOR_H

#include <vector>

#include "include/FTAResultsParser.h"

#include "llvm/IR/Instructions.h"

#include "z3++.h"

class ConfigGenerator
{
public:
  ConfigGenerator(
    std::vector<FTAResultsParser::taintedInst> taintedInsts,
    std::vector<std::string> configOptions);

  /*
    Generates value ranges for the relevant taints of for a given
    path constraint and prints them.
  */
  void generateValueRanges(z3::expr pc, std::vector<std::string> taints);

  /*
   Returns the condition variables of a branching instruction in
   the given basic block. Assumes a loop condition basic block is
   being passed.
  */
  std::vector<std::string> getConditionVars(llvm::BasicBlock* BB);

  /*
    Extract the operands from a z3::expr with and operand
  */
  void getAndOperands(z3::expr expr, std::vector<z3::expr>& operands);

  // Returns true if there is a constraint of the following form:
  // (= condVar constant)
  bool checkForConstEq(std::vector<z3::expr> constraints,
                       std::vector<std::string> condVars);

  /*
    Returns the function declaration which corresponds to the given configuration option.
    Returns an empty func_decl if no match is found.
  */
  z3::func_decl getFuncDeclFromModel(std::string co, z3::model m);

  // Returns the maximum assignment for a configuration option
  std::string getMaxAssignment(std::string co, z3::expr pc);

  // Returns the minimum assignment for a configuration option
  std::string getMinAssignment(std::string co, z3::expr pc);

private:
  int upperBound = 1000000;
  int lowerBound = -1000000;

  std::vector<std::string> configOptions;
  std::vector<FTAResultsParser::taintedInst> taintedInsts;

  std::vector<z3::expr> filterTainted(std::vector<z3::expr>& constraints,
                                      std::vector<std::string> taints);

  // Remove brackets from a negative result
  // so later it can be used for the creation of a new constraint
  std::string fixNeg(std::string neg);

};

#endif