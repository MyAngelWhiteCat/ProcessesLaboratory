#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

#include "../domain.h"

namespace laboratory {

    namespace analyze {

        using Clock = std::chrono::high_resolution_clock;

        class Analyzer;
        using Analyzers = std::unordered_map<domain::AnalyzerType, std::unique_ptr<Analyzer>>;

        struct AnalyzeResult {
            std::vector<domain::SuspiciousProcess> suspicious_processes_;

            // ...
        };

        class Analyzer {
        public:
            virtual AnalyzeResult Analyze(const domain::Scan& scans) final;
            virtual std::optional<Clock::time_point> GeLastAnalyzeTimestamp();
            virtual ~Analyzer() = default;

        protected:
            virtual AnalyzeResult StartAnalyze(const domain::Scan& scans) = 0;

        private:
            std::optional<Clock::time_point> last_analyze_timestamp_;
        };

    }

}