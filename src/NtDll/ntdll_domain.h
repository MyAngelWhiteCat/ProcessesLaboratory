#pragma once

#include <Windows.h>
#include <winternl.h>

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

        HMODULE LoadModule(std::wstring_view module_name);

        template<typename Fn>
        Fn LoadFunctionFromModule(HMODULE hModule, std::string_view function_name) {
            Fn func = reinterpret_cast<Fn>(GetProcAddress(hModule, function_name.data()));
            if (!func) {
                throw std::runtime_error("Incorrect load func: " + std::string(function_name));
            }
            LOG_DEBUG(std::string(function_name).append(" loaded"));
            return func;
        }

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