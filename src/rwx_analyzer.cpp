#include "analyzer.h"
#include "domain.h"
#include "rwx_analyzer.h"
#include "logger.h"

#include <Psapi.h>
#include <Windows.h>

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace proc_scan {

    namespace labaratory {

        AnalyzeResult proc_scan::labaratory::RWXAnalyzer::StartAnalyze(domain::Scan&& scans) {
            auto& snapshot = scans.at(domain::ScanMethod::NtQSI);
            for (const auto& [pid, proc_info] : snapshot.pid_to_proc_info_) {
                std::cout << "Process [" << proc_info->GetPid()
                    << "] " << proc_info->GetProcessName() << ":\n";
                HANDLE hProcess = proc_info->Open(PROCESS_QUERY_INFORMATION);
                AnalyzeProcessMemory(hProcess);
            }
            return {};
            
        }

        void RWXAnalyzer::AnalyzeProcessMemory(HANDLE hProcess) {
            LOG_DEBUG("Start RWX analyze");
            MEMORY_BASIC_INFORMATION memory_info{ 0 };
            SIZE_T address = NULL;
            while (VirtualQueryEx(hProcess, &address, &memory_info, sizeof(MEMORY_BASIC_INFORMATION))) {
                std::cout
                    << "AllocBase:" << memory_info.AllocationBase
                    << "\n AllocProtect:- " << memory_info.AllocationProtect
                    << "\n BaseAddress:-- " << memory_info.BaseAddress
                    << "\n PartitionId:-- " << memory_info.PartitionId
                    << "\n Protect:------ " << memory_info.Protect
                    << "\n RegionSize:--- " << memory_info.RegionSize
                    << "\n State:-------- " << memory_info.State
                    << "\n Type:--------- " << memory_info.Type
                    << "\n";
                address += memory_info.RegionSize;
            }
        }

        std::vector<HMODULE> RWXAnalyzer::GetProcModules(HANDLE hProcess) {
            const size_t init_modules_count = 1024;
            std::vector<HMODULE> modules(init_modules_count);
            DWORD buffer_size = init_modules_count * sizeof(HMODULE);
            DWORD size_needed = 0;
            while (true) {
                if (EnumProcessModules(hProcess, modules.data(), buffer_size, &size_needed)) {
                    size_t modules_count = size_needed / sizeof(HMODULE);
                    modules.resize(modules_count);
                    break;
                }

                if (size_needed > buffer_size) {
                    buffer_size = size_needed;
                    modules.resize(buffer_size / sizeof(HMODULE));
                }
                else {
                    throw std::runtime_error("Can't get modules: " + std::to_string(GetLastError()));
                }

            }
            return modules;
        }

    }

}