#include "analyzer.h"

#include <optional>
#include <chrono>
#include <utility>

#include "../domain.h"


namespace laboratory {

    namespace analyze {

        AnalyzeResult Analyzer::Analyze(const domain::Scan& scans) {
            auto result = StartAnalyze(scans);
            last_analyze_timestamp_ = Clock::now();
            return result;
        }

        std::optional<Clock::time_point> Analyzer::GeLastAnalyzeTimestamp() {
            return last_analyze_timestamp_;
        }

    }

}