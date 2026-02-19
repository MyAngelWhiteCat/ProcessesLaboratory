#pragma once

#include "ntdll_domain.h"

#include <Windows.h>
#include <winternl.h>


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

            NTSTATUS NtOpenProcess(
                PHANDLE hProcess,
                ACCESS_MASK desired_access,
                POBJECT_ATTRIBUTES object_attributes,
                CLIENT_ID* client_id
            );

            NTSTATUS NtOpenProcessToken(
                HANDLE hProcess,
                ACCESS_MASK desired_access,
                PHANDLE hToken
            );

        private:
            HMODULE ntdll_{ 0 };
            pRtlAdjustPrivilege RtlAdjustPrivilege_{ 0 };
            pNtQuerySystemInformation NtQuerySystemInformation_{ 0 };
            pNtOpenProcess NtOpenProcess_{ 0 };
            pNtOpenProcessToken NtOpenProcessToken_{ 0 };

            void LoadRtlAdjustPrivelege();
            void LoadNtQuerySystemInformation();
            void LoadNtOpenProcess();
            void LoadNtOpenProcessToken();
        };

    }

}