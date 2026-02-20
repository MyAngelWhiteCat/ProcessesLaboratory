#include "ntdll.h"
#include "../domain.h"

#include <Windows.h>
#include "ntdll_domain.h"

namespace maltech {

    namespace ntdll {

        NtDll::NtDll() {
            ntdll_ = LoadModule(Names::NTDLL);
        }

        NTSTATUS NtDll::RtlAdjustPrivilege(ULONG privilege,
            BOOLEAN enable, BOOLEAN client, PBOOLEAN was_enabled)
        {
            LoadRtlAdjustPrivelege();
            return RtlAdjustPrivilege_(privilege, enable, client, was_enabled);
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
            return NtOpenProcess(hProcess, desired_access, object_attributes, client_id);
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

        void NtDll::LoadRtlAdjustPrivelege() {
            if (RtlAdjustPrivilege_) return;
            RtlAdjustPrivilege_ = LoadFunctionFromModule
                <pRtlAdjustPrivilege>(ntdll_, Names::ADJUST_PRIVILEGE);
        }

        void NtDll::LoadNtQuerySystemInformation() {
            if (NtQuerySystemInformation_) {
                return;
            }
            NtQuerySystemInformation_ = LoadFunctionFromModule
                <pNtQuerySystemInformation>(ntdll_, Names::NTQSI);
        }

        void NtDll::LoadNtOpenProcess() {
            if (NtOpenProcess_) {
                return;
            }
            NtOpenProcess_ = LoadFunctionFromModule<pNtOpenProcess>(ntdll_, Names::OPEN_PROCESS);
        }

        void NtDll::LoadNtOpenProcessToken() {
            if (NtOpenProcessToken_) {
                return;
            }
            NtOpenProcessToken_ = LoadFunctionFromModule<pNtOpenProcessToken>
                (ntdll_, Names::OPEN_PROCESS_TOKEN);
        }

        void NtDll::LoadNtQueryInformationToken() {
            if (NtQueryInformationToken_) {
                return;
            }
            NtQueryInformationToken_ = LoadFunctionFromModule<pNtQueryInformationToken>
                (ntdll_, Names::NTQIT);
        }

    }

}