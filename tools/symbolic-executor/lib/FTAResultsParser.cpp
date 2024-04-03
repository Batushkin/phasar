#include "yaml-cpp/yaml.h"

#include "include/FTAResultsParser.h"

#include <vector>
#include <iostream>


FTAResultsParser::FTAResultsParser() {};

std::vector<struct FTAResultsParser::taintedInst>
FTAResultsParser::parseFTAResults(std::string FTAresults){
  // parse YAML FTA results file
  std::vector<YAML::Node> FTAreport;
  YAML::Node root;

  try
  {
    FTAreport = YAML::LoadAllFromFile(FTAresults);
    root = FTAreport[2];
  }
  catch(const YAML::Exception& e)
  {
    std::cerr << "Error parsing YAML: " << e.what() << std::endl;
  }

  // Extract tainted instructions
  std::vector<std::string> functions;
  std::vector<struct taintedInst> taintedInsts;

  if (root["result-map"]) { 
    YAML::Node resultMap = root["result-map"].as<YAML::Node>();

    for (YAML::const_iterator it = resultMap.begin(); it != resultMap.end(); ++it) {
      YAML::Node currFunc = it->second.as<YAML::Node>();

      if (currFunc["feature-related-insts"]) {
        // should be a YAML sequence
        YAML::Node featureInsts = currFunc["feature-related-insts"].as<YAML::Node>();

        // YAML sequence contains YAML map nodes
        for (YAML::const_iterator ity = featureInsts.begin(); ity != featureInsts.end(); ++ity) {
          YAML::Node currInstNode = ity->as<YAML::Node>();
          std::string inst = currInstNode["inst"].as<std::string>();

          if (isBranchingInst(inst) && isLoopCondition(inst)) {
            struct taintedInst currInst;
            currInst.func = currFunc["demangled-name"].as<std::string>();

            currInst.inst = inst;
            currInst.loc = currInstNode["location"].as<std::string>();
            currInst.taints = currInstNode["taints"].as<std::vector<std::string>>();

            taintedInsts.push_back(currInst);
          }
        }
      }
    }
  }

  return taintedInsts;
}

/*
A function that checks whether the LLVM instruction is
one of the branching instructions.

resume, catchswitch and catchret are left out because
they handle exceptions and we are not interested in them
*/
bool FTAResultsParser::isBranchingInst(std::string inst) {
  if ((inst.rfind("br", 0) == 0) ||
                (inst.rfind("switch", 0) == 0) ||
                (inst.rfind("indirectbr", 0) == 0) ||
                (inst.rfind("invoke", 0) == 0) ||
                (inst.rfind("call", 0) == 0)) {
    return true;
  }

  return false;
}

/*
A function that checks whether the LLVM instruction is
a br instruction to a loop BB

we check for: for, while, do-while
*/
bool FTAResultsParser::isLoopCondition(std::string inst) {
  if (inst.find("for.body") != std::string::npos ||
      inst.find("while.body") != std::string::npos ||
      inst.find("do.body") != std::string::npos) {
    return true;
  }

  return false;
}