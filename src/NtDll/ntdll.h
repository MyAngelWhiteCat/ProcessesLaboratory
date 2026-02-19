#pragma once

#include "ntdll_domain.h"

#include <Windows.h>


namespace maltech {

    namespace ntdll {

        using namespace std::literals;

        class NtDll {
        public:
            NtDll();
            NTSTATUS RtlAdjustPrivilege(ULONG privilege,
                BOOLEAN enable,
                BOOLEAN client,
                PBOOLEAN was_enabled);

            NTSTATUS NtQuerySystemInformation(
                SYSTEM_INFORMATION_CLASS SystemInformationClass,
                PVOID SystemInformation,
                ULONG SystemInformationLength,
                PULONG ReturnLength
                );

        private:
            HMODULE ntdll_{ 0 };
            pRtlAdjustPrivilege RtlAdjustPrivilege_{ 0 };
            pNtQuerySystemInformation NtQuerySystemInformation_{ 0 };

            void LoadRtlAdjustPrivelege();
            void LoadNtQuerySystemInformation();
        };

    }

}