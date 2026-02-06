#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

#include "domain.h"

namespace proc_scan {

    namespace labaratory {

        using Clock = std::chrono::high_resolution_clock;

        class Analyzer;
        using Analyzers = std::unordered_map<domain::AnalyzerType, std::unique_ptr<Analyzer>>;

        struct Analyzeresult {
            std::vector<domain::SPProcessInfo> suspicious_processes_;
            // ...
        };

        class Analyzer {
        public:
            virtual Analyzeresult Analyze(domain::Scan&& scans);
            virtual std::optional<Clock::time_point> GeLastAnalyzeTimestamp();
            virtual ~Analyzer() = default;

        private:
            std::optional<Clock::time_point> last_analyze_timestamp_;

            virtual Analyzeresult StartAnalyze(domain::Scan&& scans) = 0;
        };

    }

}