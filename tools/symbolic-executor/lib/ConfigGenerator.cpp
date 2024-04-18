#include "include/ConfigGenerator.h"
#include "include/Utils.h"

#include <fstream>

ConfigGenerator::ConfigGenerator(
  std::vector<FTAResultsParser::taintedInst> tis,
  std::vector<std::string> cos) {
    taintedInsts = tis;
    configOptions = cos;
  }

void ConfigGenerator::generateValueRanges(
  z3::expr pc,
  std::vector<std::string> taints,
  int& numValueRanges,
  std::vector<std::vector<ConfigGenerator::ValueRange>>& knownPathValRanges) {
  
  std::vector<ConfigGenerator::ValueRange> newPathValRanges;
  z3::context& ctx = pc.ctx();
  //z3::solver s(ctx);
  //s.add(pc);
  //s.check();
  std::vector<z3::expr> constraints;
  getAndOperands(pc, constraints);

  Utils u;

  // for each configuration option
  for (std::string co : configOptions) {
    // check if it's a taint
    if (u.isTaint(co, taints)) {
      // add upper and lower constraints
      z3::expr upper = ctx.int_const(co.c_str()) <= upperBound;
      z3::expr lower = ctx.int_const(co.c_str()) >= lowerBound;
      pc = pc && upper;
      pc = pc && lower;

      // if it is a relevant taint
      if (!checkForConstEq(constraints, {co})) {
        std::string max = getMaxAssignment(co, pc);
        std::string min = getMinAssignment(co, pc);

        ConfigGenerator::ValueRange currValRange;
        currValRange.co = co;
        currValRange.max = fixNeg(max);
        currValRange.min = fixNeg(min);
        newPathValRanges.push_back(currValRange);
      }
    } 
  }

  // Don't output the value ranges if the same value ranges tuple already exists for another path
  for (std::vector<ConfigGenerator::ValueRange> pathValRanges : knownPathValRanges) {
    if (pathValRangesAreEqual(newPathValRanges, pathValRanges)) {
      return;
    }
  }

  // Add the new path value ranges to the known ones
  knownPathValRanges.push_back(newPathValRanges);
  
  // code for generating assignments for all relevant taints
  // it is now very old. I changed how this function works a lot
  /*for (int i = 0; i < n; ++i) {
    llvm::outs() << "Configuration " << i+1 << ":\n";

    if (s.check() == z3::sat) {
      // create SMT-LIB2 file
      std::string fileName = "solver_state.smt2"; + std::to_string(i+1)
      std::ofstream out(fileName);
      out << s.to_smt2();
      out.close();

      z3::model m = s.get_model();
      for (std::string co : configOptions) {
        for (unsigned i = 0; i < m.size(); ++i) {
          z3::func_decl decl = m[i];
          std::string declName = decl.name().str();

          if (co == declName) {
            std::string assignment = m.get_const_interp(decl).to_string();
            assignment = fixNeg(assignment);
            llvm::outs() << co << " = " << assignment << "\n";
            llvm::outs().flush();

            // if the co is a taint
            for (std::string taint : taints) {
              if (co == taint) {
                // add a constraint that excludes the current assignment
                if (!checkForConstEq(constraints, {co})) {
                  int val = std::stoi(assignment);
                  z3::expr var = ctx.int_const(co.c_str());
                  s.add(var != val);
                }
              }
            }       
          }
        }

      }
    } else {
      llvm::outs() << "Exhausted the variations for one of the taints. No further models will be found.\n";
      llvm::outs().flush();
    }
  }*/
}

bool ConfigGenerator::addValRangeToKnown(
  std::vector<std::vector<ConfigGenerator::ValueRange>>& knownPathValRanges,
  std::vector<ConfigGenerator::ValueRange> newPathValRanges) {
  
  for (std::vector<ConfigGenerator::ValueRange> pathValRanges : knownPathValRanges) {
    if (pathValRangesAreEqual(pathValRanges, newPathValRanges)) {
      return false;
    }
  }

  knownPathValRanges.push_back(newPathValRanges);
  return true;
}

bool ConfigGenerator::pathValRangesAreEqual(
  std::vector<ConfigGenerator::ValueRange> pathValRanges1,
  std::vector<ConfigGenerator::ValueRange> pathValRanges2) {
  
  if (pathValRanges1.size() != pathValRanges2.size()) {
    return false;
  }

  // Use unordered map to count occurances of valueRange in pathValRanges1
  std::unordered_map<ConfigGenerator::ValueRange, int> countMap;
  for (ConfigGenerator::ValueRange valRange : pathValRanges1) {
    countMap[valRange]++;
  }

  for (ConfigGenerator::ValueRange valRange : pathValRanges2) {
    auto it = countMap.find(valRange);
    if (it == countMap.end() || it->second == 0) {
      return false;
    }

    it->second--;
  }

  return true;
}

std::string ConfigGenerator::getMaxAssignment(std::string co, z3::expr pc) {
  z3::optimize opt(pc.ctx());
  opt.add(pc);
  z3::expr coExpr = opt.ctx().int_const(co.c_str());
  opt.maximize(coExpr);
  
  if (opt.check() == z3::sat) {
    z3::model mMax = opt.get_model();
    z3::func_decl decl = getFuncDeclFromModel(co, mMax);
    return mMax.get_const_interp(decl).to_string();
  } else {
    return "The Z3 optimizer could not find a maximum assignment";
  }
}

std::string ConfigGenerator::getMinAssignment(std::string co, z3::expr pc) {
  z3::optimize opt(pc.ctx());
  opt.add(pc);
  z3::expr coExpr = opt.ctx().int_const(co.c_str());
  opt.minimize(coExpr);
  
  if (opt.check() == z3::sat) {
    z3::model mMax = opt.get_model();
    z3::func_decl decl = getFuncDeclFromModel(co, mMax);
    return mMax.get_const_interp(decl).to_string();
  } else {
    return "The Z3 optimizer could not find a minimum assignment";
  }
}

z3::func_decl ConfigGenerator::getFuncDeclFromModel(std::string co, z3::model m) {
  for (unsigned i = 0; i < m.size(); ++i) {
    z3::func_decl decl = m[i];
    std::string declName = decl.name().str();
    
    if (co == declName) {
      return decl;
    }
  }
  
  return z3::func_decl(m.ctx());
}

std::string ConfigGenerator::fixNeg(std::string neg) {
  if (neg.substr(0, 1) == "(") {
    neg.erase(0, 1);
    neg.erase(1, 1);
    neg.erase(neg.size()-1, 1);
  }

  return neg;
}

void ConfigGenerator::getAndOperands(z3::expr expr, std::vector<z3::expr>& operands) {
  if (expr.decl().name().str() == "and") {
    for (unsigned i = 0; i < expr.num_args(); ++i) {
      getAndOperands(expr.arg(i), operands);
    }
  } else {
    operands.push_back(expr);
  }
}

std::vector<z3::expr>
ConfigGenerator::filterTainted(
  std::vector<z3::expr>& constraints,
  std::vector<std::string> taints) {
  std::vector<z3::expr> res;

  for (z3::expr constr : constraints) {
    for (std::string taint : taints) {
      unsigned numArgs = constr.num_args();
      for (unsigned i = 0; i < numArgs; i++) {
        z3::expr arg = constr.arg(i);
        if (taint == arg.to_string()) {
          res.push_back(constr);
          break;
        }
      }
    }
  }

  return res;
}

std::vector<std::string> ConfigGenerator::getConditionVars(llvm::BasicBlock* BB) {
  std::vector<std::string> res;
  for (llvm::Instruction &I : *BB) {
    if (llvm::CmpInst *cmpInst = llvm::dyn_cast<llvm::CmpInst>(&I)) {
      llvm::Value *op1 = cmpInst->getOperand(0);
      llvm::Value *op2 = cmpInst->getOperand(1);

      if (llvm::LoadInst *loadInst1 = llvm::dyn_cast<llvm::LoadInst>(op1)) {
          llvm::Value *ptrOp1 = loadInst1->getPointerOperand();
          std::string name1 = ptrOp1->getName().str();
          llvm::outs() << name1 << "\n";
          res.push_back(name1);
      }

      if (llvm::LoadInst *loadInst2 = llvm::dyn_cast<llvm::LoadInst>(op2)) {
        llvm::Value *ptrOp2 = loadInst2->getPointerOperand();
        std::string name2 = ptrOp2->getName().str();
        llvm::outs() << name2 << "\n";
        res.push_back(name2);
      }

      llvm::outs().flush();
    }
  }

  return res;
}

bool ConfigGenerator::checkForConstEq(std::vector<z3::expr> constraints,
                                      std::vector<std::string> condVars) {
  for (std::string condVar : condVars) {
    for (z3::expr constraint : constraints) {
      if (constraint.is_eq()) {
        z3::expr arg1 = constraint.arg(0);
        z3::expr arg2 = constraint.arg(1);

        if (arg1.is_numeral()) {
          if (arg2.to_string() == condVar) {
            //llvm::outs() << "Found a const var: " << arg2.to_string() << "\n";
            return true;
          }
        } else if (arg2.is_numeral()) {
          if (arg1.to_string() == condVar) {
            //llvm::outs() << "Found a const var: " << arg1.to_string() << "\n";
            return true;
          }
        }
        //llvm::outs().flush();
      }
    }
  }

  return false;
}