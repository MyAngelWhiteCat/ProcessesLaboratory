#pragma once

#include "analyzer.h"
#include "domain.h"

namespace proc_scan {

    namespace labaratory {

        class HiddenProcessesAnalyzer : public Analyzer {
        public:


        private:
            Analyzeresult StartAnalize(domain::Scan&& scan) override;
        };

    }

}