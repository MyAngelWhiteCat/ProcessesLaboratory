#pragma once

#include "../analyzer.h"
#include "../../domain.h"

namespace laboratory {

    namespace analyze {
        
        class AdminRightsAnalyzer : public Analyzer {
        private:
            AnalyzeResult StartAnalyze(const domain::Scan& scans) override;

        };

    }

}