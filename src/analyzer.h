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

        struct AnalyzeResult {
            std::vector<domain::SuspiciousProcess> suspicious_processes_;

            // ...
        };

        class Analyzer {
        public:
            virtual AnalyzeResult Analyze(domain::Scan&& scans);
            virtual std::optional<Clock::time_point> GeLastAnalyzeTimestamp();
            virtual ~Analyzer() = default;

        protected:
            virtual AnalyzeResult StartAnalyze(domain::Scan&& scans) = 0;

        private:
            std::optional<Clock::time_point> last_analyze_timestamp_;

            virtual AnalyzeResult StartAnalyze(domain::Scan&& scans) = 0;
        };

    }

}