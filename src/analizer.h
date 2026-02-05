#pragma once

#include <chrono>
#include <optional>
#include <unordered_map>
#include <vector>

#include "domain.h"

namespace proc_scan {

    namespace labaratory {

        using Clock = std::chrono::high_resolution_clock;
        using ScanResult = std::unordered_map<proc_scan::domain::ScanMethod, domain::Snapshot>;

        class Analizer;
        using Analizers = std::unordered_map<domain::AnalizerType, std::unique_ptr<Analizer>>;

        struct AnalizeResult {
            std::vector<domain::SPProcessInfo> suspicious_processes_;
            // ...
        };

        class Analizer {
        public:
            virtual AnalizeResult Analize(domain::Scan&& scans);
            virtual std::optional<Clock::time_point> GeLastAnalizeTimestamp();
            virtual ~Analizer() = default;

        private:
            std::optional<Clock::time_point> last_analize_timestamp_;

            virtual AnalizeResult StartAnalize(domain::Scan&& scans) = 0;
        };

    }

}