#pragma once

#include <Windows.h>
#include <winternl.h>

#include <string_view>
#include <string>

namespace maltech {

    namespace ntdll {

        using namespace std::literals;

        struct Names {
            Names() = delete;
            static constexpr std::wstring_view NTDLL = L"ntdll.dll"sv;
            static constexpr std::string_view ADJUST_PRIVILEGE = "RtlAdjustPrivilege"sv;
            static constexpr std::string_view NTQSI = "NtQuerySystemInformation"sv;
        };

        typedef NTSTATUS(*pNtQuerySystemInformation)(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
            );

        typedef NTSTATUS(NTAPI* pRtlAdjustPrivilege)
            (ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);


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