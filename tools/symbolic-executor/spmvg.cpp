/******************************************************************************
 * Copyright (c) 2023 Hristo Klechorov.
 * All rights reserved. This program and the accompanying materials are made
 * available under the terms of LICENSE.txt.
 *
 * Contributors:
 *     Hristo Klechorov and others
 *****************************************************************************/

#include <bits/stdc++.h>
#include <chrono>

#include "include/SymbolicExecutor.h"
#include "include/FTAResultsParser.h"

int main(int argc, char **argv) {
  //start recording time
  auto start = std::chrono::high_resolution_clock::now();

  // unsync the I/O of C and C++.
  std::ios_base::sync_with_stdio(false);

  std::vector<std::string> configOptions{ "x1", "x2", "x3" };

  SymbolicExecutor executor;
  std::string filePath = argv[1];
  std::string fileFTA = argv[2];

  // parse results from VaRA FTA
  FTAResultsParser parser;
  std::vector<struct FTAResultsParser::taintedInst> taintedInsts = parser.parseFTAResults(fileFTA);
  executor.doAnalysis(filePath, taintedInsts, configOptions);
  
  // output time
  auto end = std::chrono::high_resolution_clock::now();
  double time_taken = 
      std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
  
  time_taken *= 1e-9;

  std::cout << "Time taken by program is : " << std::fixed 
         << time_taken << std::setprecision(9);
  std::cout << " sec" << std::endl;

  return 0;
}