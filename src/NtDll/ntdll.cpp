#include "ntdll.h"
#include "ntdll_domain.h"

#include <Windows.h>

namespace maltech {

    namespace ntdll {

        NtDll::NtDll() {
            ntdll_ = domain::LoadModule(domain::Names::NTDLL);
        }

        NTSTATUS NtDll::NtAdjustPrivilege(
            HANDLE hToken,
            BOOLEAN disable_all_privileges,
            PTOKEN_PRIVILEGES new_privilege,
            ULONG buffer_len,
            PTOKEN_PRIVILEGES previous_privilege,
            ULONG return_len
        )
        {
            LoadNtAdjustPrivilege();
            return NtAdjustPrivilege_(hToken, disable_all_privileges, new_privilege,
                buffer_len, previous_privilege, return_len);
        }

        NTSTATUS NtDll::NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass,
            PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
        {
            LoadNtQuerySystemInformation();
            return NtQuerySystemInformation_(SystemInformationClass,
                SystemInformation, SystemInformationLength, ReturnLength);
        }

        NTSTATUS NtDll::NtOpenProcess(PHANDLE hProcess,
            ACCESS_MASK desired_access, POBJECT_ATTRIBUTES object_attributes, CLIENT_ID* client_id) {
            LoadNtOpenProcess();
            return NtOpenProcess_(hProcess, desired_access, object_attributes, client_id);
        }

        NTSTATUS NtDll::NtOpenProcessToken(HANDLE hProcess,
            ACCESS_MASK desired_access, PHANDLE hToken) {
            LoadNtOpenProcessToken();
            return NtOpenProcessToken_(hProcess, desired_access, hToken);
        }

        NTSTATUS NtDll::NtQueryInformationToken(
            HANDLE hToken, 
            TOKEN_INFORMATION_CLASS requested_info,
            PVOID token_info, ULONG token_size, PULONG returned_size)
        {
            LoadNtQueryInformationToken();
            return NtQueryInformationToken_
            (hToken, requested_info, token_info, token_size, returned_size);
        }

        void NtDll::LoadNtAdjustPrivilege() {
            if (NtAdjustPrivilege_) return;
            NtAdjustPrivilege_ = domain::LoadFunctionFromModule
                <pNtAdjustPrivilege>(ntdll_, domain::Names::ADJUST_PRIVILEGE);
        }

        void NtDll::LoadNtQuerySystemInformation() {
            if (NtQuerySystemInformation_) {
                return;
            }
            NtQuerySystemInformation_ = domain::LoadFunctionFromModule
                <pNtQuerySystemInformation>(ntdll_, domain::Names::NTQSI);
        }

        void NtDll::LoadNtOpenProcess() {
            if (NtOpenProcess_) {
                return;
            }
            NtOpenProcess_ = domain::LoadFunctionFromModule<pNtOpenProcess>(ntdll_, domain::Names::OPEN_PROCESS);
        }

        void NtDll::LoadNtOpenProcessToken() {
            if (NtOpenProcessToken_) {
                return;
            }
            NtOpenProcessToken_ = domain::LoadFunctionFromModule<pNtOpenProcessToken>
                (ntdll_, domain::Names::OPEN_PROCESS_TOKEN);
        }

        void NtDll::LoadNtQueryInformationToken() {
            if (NtQueryInformationToken_) {
                return;
            }
            NtQueryInformationToken_ = domain::LoadFunctionFromModule<pNtQueryInformationToken>
                (ntdll_, domain::Names::NTQIT);
        }

    }

}