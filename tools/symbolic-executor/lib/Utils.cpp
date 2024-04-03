#include "include/Utils.h"

llvm::BasicBlock*
Utils::getFirstDestinationBB(llvm::Instruction* inst) {
  if (inst->getOpcode() == llvm::Instruction::Br) {
    return inst->getSuccessor(0);
  }
}

llvm::Instruction*
Utils::getInstFromFunc(llvm::Function& func, std::string& inst) {
  for (auto& BB : func) {
    for (auto& I : BB) {
      std::string local; 
      llvm::raw_string_ostream(local) << I;
      std::string external;
      llvm::raw_string_ostream(external) << inst;
      removeMetadataFromString(local);
      local = removeSpacesFromBeginning(local);
      removeMetadataFromString(external);

      if (external.compare(local) == 0) {
        return &I;
      }
    }
  }
}

void Utils::removeMetadataFromString(std::string& inst) {
  size_t delimiter = inst.find('!');

  if (delimiter != std::string::npos) {
    inst.erase(delimiter);
  }
}

std::string Utils::removeSpacesFromBeginning(std::string& inst) {
  size_t firstNonSpace = inst.find_first_not_of(' ');

  if (firstNonSpace == std::string::npos) {
    return "";
  }

  return inst.substr(firstNonSpace);
}

std::vector<llvm::BasicBlock*>
Utils::getAllDestinationBBs(llvm::Instruction* inst) {
  std::vector<llvm::BasicBlock*> destBBs;

  if (inst->getOpcode() == llvm::Instruction::Br) {
    unsigned numSucc = inst->getNumSuccessors();
    for (unsigned i = 0; i < numSucc; ++i) {
      llvm::BasicBlock* succ = inst->getSuccessor(i);
      destBBs.push_back(succ);
    }
  }

  return destBBs;
}

bool Utils::isTaint(std::string co, std::vector<std::string> taints) {
  for (std::string taint : taints) {
    if (co == taint) {
      return true;
    }
  }

  return false;
}