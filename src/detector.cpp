#include "detector.h"

#include <optional>
#include <chrono>


namespace proc_scan {

    namespace labaratory {

        void Analizer::Analize(ScanResult scans) {
            StartAnalize(scans);
            last_analize_timestamp_ = Clock::now();
        }

        std::optional<Clock::time_point> Analizer::GeLastAnalizeTimestamp() {
            return last_analize_timestamp_;
        }

    }

}