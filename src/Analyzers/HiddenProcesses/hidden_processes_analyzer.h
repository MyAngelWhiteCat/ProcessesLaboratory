#pragma once

#include "../analyzer.h"
#include "../../domain.h"

namespace labaratory {

    namespace analyze {

        class HiddenProcessesAnalyzer : public Analyzer {
        public:


        private:
            AnalyzeResult StartAnalyze(domain::Scan&& scan) override;
        };

    }

}