#pragma once

#include "analyzer.h"
#include "domain.h"

#include <vector>
#include <string>

#include <Windows.h>
#include <string_view>
#include <utility>

namespace proc_scan {

    namespace labaratory {

        const SIZE_T KB = 1024;
        const SIZE_T MB = KB * 1024;

        class RWXAnalyzer : public Analyzer {

        private:
            AnalyzeResult StartAnalyze(domain::Scan&& scans) override;

            std::string AnalyzeProcessMemory(HANDLE hProcess);
            std::vector<HMODULE> GetProcModules(HANDLE hProcess);

        };

    }

}