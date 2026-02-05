#pragma once

#include <chrono>
#include <optional>
#include <unordered_map>

#include "domain.h"

namespace proc_scan {

    namespace labaratory {

        using Clock = std::chrono::high_resolution_clock;
        using ScanResult = std::unordered_map<proc_scan::domain::ScanMethod, domain::Snapshot>;

        class Analizer {
        public:
            virtual void Analize(ScanResult scans);
            virtual std::optional<Clock::time_point> GeLastAnalizeTimestamp();
            virtual ~Analizer() = default;

        private:
            std::optional<Clock::time_point> last_analize_timestamp_;

            virtual void StartAnalize(ScanResult scans) = 0;
        };

    }

}