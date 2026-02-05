#pragma once

#include "analizer.h"
#include "domain.h"

namespace proc_scan {

    namespace labaratory {

        class HiddenProcessesAnalizer : public Analizer {
        public:


        private:
            AnalizeResult StartAnalize(ScanResult scan) override;
        };

    }

}