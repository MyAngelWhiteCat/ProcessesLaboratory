#include "analyzer.h"

#include <optional>
#include <chrono>
#include <utility>

#include "../domain.h"


namespace labaratory {

    namespace analyze {

        AnalyzeResult Analyzer::Analyze(domain::Scan&& scans) {
            auto result = StartAnalyze(std::move(scans));
            last_analyze_timestamp_ = Clock::now();
            return result;
        }

        std::optional<Clock::time_point> Analyzer::GeLastAnalyzeTimestamp() {
            return last_analyze_timestamp_;
        }

    }

}