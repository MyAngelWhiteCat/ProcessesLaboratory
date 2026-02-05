#include "detector.h"

#include <optional>
#include <chrono>


namespace detector {

    void Dectector::Scan() {
        StartScan();
        last_scan_ = Clock::now();
    }

    std::optional<Clock::time_point> Dectector::GetLastScan() {
        return last_scan_;
    }

}