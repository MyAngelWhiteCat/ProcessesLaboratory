#pragma once

#include <Windows.h>

#include <string_view>


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

    }

}