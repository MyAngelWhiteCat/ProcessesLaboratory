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
            while (VirtualQueryEx(hProcess, (LPVOID)address, &memory_info, sizeof(memory_info))) {
                std::cout
                    <<   "AllocBase:---- " << memory_info.AllocationBase
                    << "\nAllocProtect:- " << memory_info.AllocationProtect
                    << "\nBaseAddress:-- " << memory_info.BaseAddress
                    << "\nPartitionId:-- " << memory_info.PartitionId
                    << "\nProtect:------ " << memory_info.Protect
                    << "\nRegionSize:--- " << memory_info.RegionSize
                    << "\nState:-------- " << memory_info.State
                    << "\nType:--------- " << memory_info.Type
                    << "\n";
                address += (SIZE_T)memory_info.BaseAddress + memory_info.RegionSize;
                if (address == 0) {
                    break;
                }
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