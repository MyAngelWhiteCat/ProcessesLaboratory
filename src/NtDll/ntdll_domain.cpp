#include "ntdll_domain.h"

#include <Windows.h>

#include <string_view>
#include <string>
#include <stdexcept>


namespace maltech {

    namespace ntdll {

        using namespace std::literals;

        HMODULE LoadModule(std::string_view module_name) {
            if (module_name.empty()) {
                return 0;
            }
            HMODULE hModule = GetModuleHandleA(module_name.data());
            if (!hModule) {
                throw std::runtime_error("Can't load " + std::string(module_name)
                    + ". error code:"s + std::to_string(GetLastError()));
            }
            return hModule;
        }

    }

}