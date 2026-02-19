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
            static constexpr std::string_view OPEN_PROCESS = "OpenProcess"sv;
        };

        typedef NTSTATUS(*pNtQuerySystemInformation)(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
            );

        typedef NTSTATUS(*pRtlAdjustPrivilege)
            (ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

        typedef NTSTATUS(*pNtOpenProcess)(
            PHANDLE hProcess,
            ACCESS_MASK DesiredAccess,
            POBJECT_ATTRIBUTES ObjectAttributes,
            CLIENT_ID* Client
            );

    }

}