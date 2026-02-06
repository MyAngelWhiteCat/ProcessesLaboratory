#pragma once

#include "analyzer.h"
#include "domain.h"

#include <vector>
#include <Windows.h>

namespace proc_scan {

    namespace labaratory {

        class RWXAnalyzer : public Analyzer {

        private:
            AnalyzeResult StartAnalyze(domain::Scan&& scans) override;

            void AnalyzeProcessMemory(domain::SPProcessInfo);
            std::vector<HMODULE> GetProcModules(HANDLE hProcess);

        };

    }

}