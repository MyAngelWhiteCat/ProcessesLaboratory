#pragma once

#include "../analyzer.h"
#include "../../domain.h"

namespace proc_scan {

    namespace analyze {

        class HiddenProcessesAnalyzer : public Analyzer {
        public:


        private:
            AnalyzeResult StartAnalyze(domain::Scan&& scan) override;
        };

    }

}