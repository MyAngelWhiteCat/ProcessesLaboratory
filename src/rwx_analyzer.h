#pragma once

#include "analyzer.h"
#include "domain.h"

#include <vector>
#include <string>

#include <Windows.h>

namespace proc_scan {

    namespace labaratory {

        class RWXAnalyzer : public Analyzer {

        private:
            AnalyzeResult StartAnalyze(domain::Scan&& scans) override;

            std::string AnalyzeProcessMemory(HANDLE hProcess);
            std::vector<HMODULE> GetProcModules(HANDLE hProcess);

        };

    }

}