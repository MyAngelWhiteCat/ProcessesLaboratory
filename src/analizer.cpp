#include "analizer.h"

#include <optional>
#include <chrono>


namespace proc_scan {

    namespace labaratory {

        AnalizeResult Analizer::Analize(domain::Scan&& scans) {
            auto result = StartAnalize(std::move(scans));
            last_analize_timestamp_ = Clock::now();
            return result;
        }

        std::optional<Clock::time_point> Analizer::GeLastAnalizeTimestamp() {
            return last_analize_timestamp_;
        }

    }

}