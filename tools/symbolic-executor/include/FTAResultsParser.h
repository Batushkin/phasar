#ifndef FTARESULTSPARSER_H
#define FTARESULTSPARSER_H

#include <string>
#include <vector>

class FTAResultsParser {
  public:
    struct taintedInst {
      std::string inst;
      std::string loc;
      std::string func;
      std::vector<std::string> taints;
    };

    FTAResultsParser();

    std::vector<struct taintedInst> parseFTAResults(std::string FTAresults);
};

#endif