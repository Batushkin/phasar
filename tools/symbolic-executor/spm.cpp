/******************************************************************************
 * Copyright (c) 2023 Hristo Klechorov.
 * All rights reserved. This program and the accompanying materials are made
 * available under the terms of LICENSE.txt.
 *
 * Contributors:
 *     Hristo Klechorov and others
 *****************************************************************************/

#include "include/SymbolicExecutor.h"
#include "include/FTAResultsParser.h"

int main(int argc, char **argv) {
  std::vector<std::string> configOptions{ "x1", "x2", "x3" };

  SymbolicExecutor executor;
  std::string filePath = argv[1];
  std::string fileFTA = argv[2];

  // parse results from VaRA FTA
  FTAResultsParser parser;
  std::vector<struct FTAResultsParser::taintedInst> taintedInsts = parser.parseFTAResults(fileFTA);
  executor.doAnalysis(filePath, taintedInsts, configOptions);

  //ConfigGenerator CG(taintedInsts, configOptions);
  
  return 0;
}