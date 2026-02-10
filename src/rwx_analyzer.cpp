#include "analyzer.h"
#include "domain.h"
#include "rwx_analyzer.h"
#include "logger.h"

#include <Psapi.h>
#include <Windows.h>

#include <stdexcept>
#include <string>
#include <vector>

namespace proc_scan {

    namespace labaratory {

        AnalyzeResult proc_scan::labaratory::RWXAnalyzer::StartAnalyze(domain::Scan&& scans) {
            auto& snapshot = scans.at(domain::ScanMethod::NtQSI);

            AnalyzeResult result;
            for (const auto& [pid, proc_info] : snapshot.pid_to_proc_info_) {
                LOG_DEBUG("Process ["s + std::to_string(proc_info->GetPid()) + "] "s
                    + std::string(proc_info->GetProcessName()));

                HANDLE hProcess = proc_info->Open(PROCESS_QUERY_INFORMATION);
                std::string comments = AnalyzeProcessMemory(hProcess);
                if (!comments.empty()) {
                    result.suspicious_processes_.emplace_back(proc_info, comments);
                }
            }
            return result;
        }

        std::string RWXAnalyzer::AnalyzeProcessMemory(HANDLE hProcess) {
            LOG_DEBUG("Start RWX analyze");
            std::string comments;
            MEMORY_BASIC_INFORMATION memory_info{ 0 };
            SIZE_T address = NULL;

            std::vector<SIZE_T> rwx_regions{ 0 };
            std::vector<SIZE_T> rx_to_rw_regions{ 0 };
            std::vector<SIZE_T> rw_to_rx_regions{ 0 };
            while (VirtualQueryEx(hProcess, (LPVOID)address, &memory_info, sizeof(memory_info))) {
                address = (SIZE_T)memory_info.BaseAddress + memory_info.RegionSize;
                if (address == 0) {
                    throw std::runtime_error("Memory region can't be empty");
                }
                if (memory_info.State != MEM_COMMIT) {
                    continue;
                }

                if (memory_info.Protect == PAGE_EXECUTE_READWRITE) {
                    rwx_regions.back() += memory_info.RegionSize;
                }
                else if (rwx_regions.back()) {
                    rwx_regions.push_back(0);
                }

                if (memory_info.AllocationProtect == PAGE_EXECUTE_READ
                    && memory_info.Protect == PAGE_READWRITE) {
                    rx_to_rw_regions.back() += memory_info.RegionSize;
                }
                else if (rx_to_rw_regions.back()) {
                    rx_to_rw_regions.push_back(0);
                }

                if (memory_info.AllocationProtect == PAGE_READWRITE
                    && memory_info.Protect == PAGE_EXECUTE_READ) {
                    rw_to_rx_regions.back() += memory_info.RegionSize;
                }
                else if (rw_to_rx_regions.back()) {
                    rw_to_rx_regions.push_back(0);
                }

            }
            rwx_regions.pop_back();
            rx_to_rw_regions.pop_back();
            rw_to_rx_regions.pop_back();
            if (!rwx_regions.empty()) {
                for (int i : rwx_regions) {
                    comments += std::to_string(i / 1024)
                        + "KB region with RWX rights detected!\n";
                }
            }
            if (!rx_to_rw_regions.empty()) {
                for (int i : rx_to_rw_regions) {
                    comments += std::to_string(i / 1024)
                        + "KB region with switched from RX to RW rights detected!\n";
                }
            }
            if (!rw_to_rx_regions.empty()) {
                for (int i : rw_to_rx_regions) {
                    comments += std::to_string(i / 1024)
                        + "KB region with switched from RW to RX rights detected!\n";
                }
            }
            return comments;
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

        std::string RWXAnalyzer::CheckRegions(std::vector<SIZE_T> regions, std::string_view comment) {
            std::string result;
            for (SIZE_T region : regions) {
                auto [count, mesure] = Convert(region);
                result += std::to_string(count) 
                    + ' ' + mesure + ' '
                    + std::string(comment) + '\n';
            }
            return result;
        }

        std::pair<SIZE_T, std::string> RWXAnalyzer::Convert(SIZE_T bytes) {
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

    }

}