#pragma once

#include "../analyzer.h"
#include "../../domain.h"

#include <vector>
#include <string>

#include <Windows.h>
#include <string_view>
#include <utility>

namespace laboratory {

    namespace analyze {

        const SIZE_T KB = 1024;
        const SIZE_T MB = KB * 1024;

        class RWXAnalyzer : public Analyzer {

        private:
            AnalyzeResult StartAnalyze(const domain::Scan& scans) override;

            std::vector<domain::SuspiciousMemory> AnalyzeProcessMemory(HANDLE hProcess);
            std::vector<HMODULE> GetProcModules(HANDLE hProcess);

            void HandleSuspiciosMemory(std::vector<domain::SuspiciousMemory>& suspicious_memory,
                MEMORY_BASIC_INFORMATION& memory_info, domain::MemDetection detection) const;

            std::string TranslateResult(std::vector<domain::SuspiciousMemory> regions) const;
            std::pair<SIZE_T, std::string> ConvertBytesUpscale(SIZE_T bytes) const;
            std::string DetectionToString(domain::MemDetection detection) const;
        };

    }

}