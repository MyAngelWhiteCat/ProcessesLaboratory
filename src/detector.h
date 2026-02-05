#pragma once

#include <chrono>
#include <optional>

namespace detector {

    using Clock = std::chrono::high_resolution_clock;

    class Dectector {
    public:
        virtual void Scan();
        virtual std::optional<Clock::time_point> GetLastScan();
        virtual ~Dectector() = default;

    private:
        std::optional<Clock::time_point> last_scan_;

        virtual void StartScan() = 0;
    };

}