#ifndef UTILS_H
#define UTILS_H

#include "llvm/IR/Instructions.h"

class Utils
{
public:
  // Returns the first destination basic block of a br instruction
  llvm::BasicBlock* getFirstDestinationBB(llvm::Instruction* inst);

  // Returns the llvm::instruction object for an llvm::instruction passed
  // as a string
  llvm::Instruction* getInstFromFunc(llvm::Function& func, std::string& inst);

  // Helper function to remove metadata from a string representation of an
  // llvm::Instruction
  void removeMetadataFromString(std::string& inst);

  // Helper function to remove spaces from beginning of
  // a string representation of an llvm::instruction
  std::string removeSpacesFromBeginning(std::string& inst);

  // Returns all destination basic blocks for a br instruction
  std::vector<llvm::BasicBlock*> getAllDestinationBBs(llvm::Instruction* inst);

  // returns true if the co is contained in the taints vector
  bool isTaint(std::string co, std::vector<std::string> taints);
};

#endif