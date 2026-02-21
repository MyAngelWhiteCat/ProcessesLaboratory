#pragma once

#include <Windows.h>
#include <winternl.h>

#include <string_view>
#include <stdexcept>
#include <string>


namespace maltech {

    namespace ntdll {

        namespace domain {

            using namespace std::literals;

            struct Names {
                Names() = delete;
                static constexpr std::string_view NTDLL = "ntdll.dll"sv;
                static constexpr std::string_view ADJUST_PRIVILEGE = "NtAdjustPrivilegesToken"sv;
                static constexpr std::string_view NTQSI = "NtQuerySystemInformation"sv;
                static constexpr std::string_view OPEN_PROCESS = "NtOpenProcess"sv;
                static constexpr std::string_view OPEN_PROCESS_TOKEN = "NtOpenProcessToken"sv;
                static constexpr std::string_view NTQIT = "NtQueryInformationToken"sv;
            };

            HMODULE LoadModule(std::string_view module_name);

            std::string GetHexStatusCode(NTSTATUS status);


            template<typename Fn>
            Fn LoadFunctionFromModule(HMODULE hModule, std::string_view function_name) {
                Fn func = reinterpret_cast<Fn>(GetProcAddress(hModule, function_name.data()));
                if (!func) {
                    throw std::runtime_error("Incorrect load func: " + std::string(function_name));
                }
                return func;
            }

        }

        typedef NTSTATUS(*pNtQuerySystemInformation)(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
            );

        typedef NTSTATUS
        (NTAPI* pNtAdjustPrivilege)(
            HANDLE hTocken,
            BOOLEAN DisableAllPrivileges,
            PTOKEN_PRIVILEGES NewPrivilege,
            ULONG BufferLen,
            PTOKEN_PRIVILEGES PreviousPrivilege,
            ULONG ReturnLen
            );

        typedef NTSTATUS(*pNtOpenProcess)(
            PHANDLE hProcess,
            ACCESS_MASK DesiredAccess,
            POBJECT_ATTRIBUTES ObjectAttributes,
            CLIENT_ID* Client
            );

        typedef NTSTATUS(*pNtOpenProcessToken) (
            HANDLE ProcessHandle,
            ACCESS_MASK DesiredAccess,
            PHANDLE TokenHandle
            );

        typedef NTSTATUS(*pNtQueryInformationToken) (
            HANDLE TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            PVOID TokenInformation,
            ULONG TokenInformationLength,
            PULONG ReturnLength
            );

    }

}