#ifndef CONFIGGENERATOR_H
#define CONFIGGENERATOR_H

#include <vector>

#include "include/FTAResultsParser.h"
#include "include/Utils.h"

#include "llvm/IR/Instructions.h"

#include "z3++.h"

class ConfigGenerator
{
public:
  struct ValueRange
  { 
    std::string co;
    std::string max;
    std::string min;

    bool operator==(const ValueRange& other) const {
      return co == other.co && max == other.max && min == other.min;
    }
  };
  
  ConfigGenerator(
    std::vector<FTAResultsParser::taintedInst> taintedInsts,
    std::vector<std::string> configOptions);

  /*
    Generates value ranges for the relevant taints of for a given
    path constraint and prints them.
  */
  void generateValueRanges(
    z3::expr pc,
    std::vector<std::string> taints,
    int& numValueRanges,
    std::vector<std::vector<ConfigGenerator::ValueRange>>& knownPathValRanges);

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

  /*
    If all value ranges for path 1 are found for path 2, return true.
    Otherwise, return false
  */
  bool pathValRangesAreEqual(
    std::vector<ConfigGenerator::ValueRange> pathValRanges1,
    std::vector<ConfigGenerator::ValueRange> pathValRanges2);

private:
  int upperBound = 1000000;
  int lowerBound = -1000000;
  Utils utils;

  std::vector<std::string> configOptions;
  std::vector<FTAResultsParser::taintedInst> taintedInsts;

  std::vector<z3::expr> filterTainted(std::vector<z3::expr>& constraints,
                                      std::vector<std::string> taints);

  // Remove brackets from a negative result
  // so later it can be used for the creation of a new constraint
  std::string fixNeg(std::string neg);

  /*
    Adds a new unknown value range to the known value ranges.
    Returns true if a new unknown value range was added.
    Returns false if the new value range is already known.
  */
  bool addValRangeToKnown(
    std::vector<std::vector<ConfigGenerator::ValueRange>>& knownPathValRanges,
    std::vector<ConfigGenerator::ValueRange> newPathValRanges);

};

namespace std {
  template<>
  struct hash<ConfigGenerator::ValueRange> {
    size_t operator()(const ConfigGenerator::ValueRange& valRange) const {
      return hash<string>()(valRange.co) ^ 
             hash<string>()(valRange.min) ^
             hash<string>()(valRange.max);
    }
  };
} // end of namespace std

#endif