#include "../analyzer.h"
#include "../../domain.h"
#include "rwx_analyzer.h"
#include "../../Logger/logger.h"

#include <Psapi.h>
#include <Windows.h>

#include <stdexcept>
#include <string>
#include <vector>

namespace laboratory {

    namespace analyze {

        AnalyzeResult laboratory::analyze::RWXAnalyzer::StartAnalyze(const domain::Scan& scans) {
            auto& snapshot = scans.at(domain::ScanMethod::NtQSI);

            AnalyzeResult result;
            for (const auto& [pid, proc_info] : snapshot.pid_to_proc_info_) {
                LOG_DEBUG("Process ["s + std::to_string(proc_info->GetPid()) + "] "s
                    + std::string(proc_info->GetProcessName()));

                HANDLE hProcess = proc_info->Open(PROCESS_QUERY_INFORMATION);
                auto suspicious_memory = AnalyzeProcessMemory(hProcess);
                if (!suspicious_memory.empty()) {
                    result.suspicious_processes_
                        .emplace_back(proc_info, TranslateResult(suspicious_memory));
                }
            }
            return result;
        }

        std::vector<domain::SuspiciousMemory> RWXAnalyzer::AnalyzeProcessMemory(HANDLE hProcess) {
            LOG_DEBUG("Start RWX analyze");
            MEMORY_BASIC_INFORMATION memory_info{ 0 };
            SIZE_T address = NULL;

            std::vector<domain::SuspiciousMemory> suspicious_memory;
            while (VirtualQueryEx(hProcess, (LPVOID)address, &memory_info, sizeof(memory_info))) {
                address = (SIZE_T)memory_info.BaseAddress + memory_info.RegionSize;
                if (address == 0) {
                    throw std::runtime_error("Memory region can't be empty");
                }
                if (memory_info.State != MEM_COMMIT) {
                    continue;
                }

                if (memory_info.Protect == PAGE_EXECUTE_READWRITE) {
                    HandleSuspiciosMemory(suspicious_memory, memory_info, domain::MemDetection::RWX);
                }
                else if (memory_info.AllocationProtect == PAGE_EXECUTE_READ
                    && memory_info.Protect == PAGE_READWRITE) {
                    HandleSuspiciosMemory
                    (suspicious_memory, memory_info, domain::MemDetection::RX_TO_RW);
                }
                else if (memory_info.AllocationProtect == PAGE_READWRITE
                    && memory_info.Protect == PAGE_EXECUTE_READ) {
                    HandleSuspiciosMemory
                    (suspicious_memory, memory_info, domain::MemDetection::RW_TO_RX);
                }
            }

            return suspicious_memory;
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

        void RWXAnalyzer::HandleSuspiciosMemory(
            std::vector<domain::SuspiciousMemory>&
            suspicious_memory,
            MEMORY_BASIC_INFORMATION& memory_info,
            domain::MemDetection detection) const
        {
            if (!suspicious_memory.empty() &&
                suspicious_memory.back().detection_ == detection) {
                suspicious_memory.back().size_bytes_ += memory_info.RegionSize;
            }
            else {
                suspicious_memory.emplace_back(
                    detection,
                    (SIZE_T)memory_info.BaseAddress,
                    memory_info.RegionSize
                );
            }
        }

        std::string RWXAnalyzer::TranslateResult(std::vector<domain::SuspiciousMemory> regions) const {
            std::string result;
            for (auto& region : regions) {
                auto [count, mesure] = ConvertBytesUpscale(region.size_bytes_);
                result += std::to_string(count)
                    + ' ' + mesure + " of "
                    + DetectionToString(region.GetDetection()) + ".\n ";
            }
            return result;
        }

        std::pair<SIZE_T, std::string> RWXAnalyzer::ConvertBytesUpscale(SIZE_T bytes) const {
            int convertations = 0;
            while (bytes > KB) {
                bytes /= KB;
                ++convertations;
            }
            
            std::string mesure;
            if (convertations == 0) {
                mesure = "KB";
            }
            else if (convertations == 1) {
                mesure = "KB";
            }
            else if (convertations == 2) {
                mesure = "MB";
            }
            return { bytes, mesure };
        }

        std::string RWXAnalyzer::DetectionToString(domain::MemDetection detection) const {
            switch (detection) {
            case domain::MemDetection::RWX:
                return "RWX region";
            case domain::MemDetection::RW_TO_RX:
                return "RW to RX changed region";
            case domain::MemDetection::RX_TO_RW:
                return "RX to RW changed region";
            default:
                return "Translating Error";
            }
           
        }

    }

}