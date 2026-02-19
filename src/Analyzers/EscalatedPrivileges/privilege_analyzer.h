#pragma once

#include "../analyzer.h"
#include "../../domain.h"

namespace laboratory {

    namespace analyze {

        class PrivilegeAnalyzer : public Analyzer {

        public:

        private:
            AnalyzeResult StartAnalyze(const domain::Scan& scan) override;

        };

    }

}