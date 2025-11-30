#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <TlHelp32.h>
#include <string>

#define SeDebugPriv 20
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#define NtCurrentProcess ( (HANDLE)(LONG_PTR) -1 ) 
#define ProcessHandleType 0x7
#define SystemHandleInformation 16 

// Use Windows SDK / NT headers for these types (winternl.h, ntdef/ntifs), do not re-declare them

typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );

typedef NTSTATUS(NTAPI* _RtlAdjustPrivilege)(
    ULONG Privilege,
    BOOLEAN Enable,
    BOOLEAN CurrentThread,
    PBOOLEAN Enabled
    );

typedef NTSYSAPI NTSTATUS(NTAPI* _NtOpenProcess)(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    CLIENT_ID*         ClientId
    );

// SYSTEM_HANDLE / SYSTEM_HANDLE_INFORMATION are not in public headers in this form,
// define local versions used by NtQuerySystemInformation(SystemHandleInformation,...)
typedef struct _SYSTEM_HANDLE_ENTRY
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_ENTRY, * PSYSTEM_HANDLE_ENTRY;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE_ENTRY Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

SYSTEM_HANDLE_INFORMATION* hInfo;

namespace hj {
    HANDLE procHandle = NULL;

    OBJECT_ATTRIBUTES InitObjectAttributes(PUNICODE_STRING name, ULONG attributes, HANDLE hRoot, PSECURITY_DESCRIPTOR security)
    {
        OBJECT_ATTRIBUTES object;

        object.Length = sizeof(OBJECT_ATTRIBUTES);
        object.ObjectName = name;
        object.Attributes = attributes;
        object.RootDirectory = hRoot;
        object.SecurityDescriptor = security;

        return object;
    }

    bool IsHandleValid(HANDLE handle)
    {
        if (handle && handle != INVALID_HANDLE_VALUE)
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    HANDLE HijackExistingHandle(DWORD dwTargetProcessId)
    {

        HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!Ntdll) {
            MessageBoxA(NULL, "Failed to get handle to ntdll.dll.", "Athena Development", MB_OK | MB_ICONERROR);
            return NULL;
        }

        auto RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(Ntdll, "RtlAdjustPrivilege");
        auto NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(Ntdll, "NtQuerySystemInformation");
        auto NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(Ntdll, "NtDuplicateObject");
        auto NtOpenProcess = (_NtOpenProcess)GetProcAddress(Ntdll, "NtOpenProcess");

        if (!RtlAdjustPrivilege || !NtQuerySystemInformation || !NtDuplicateObject || !NtOpenProcess) {
            MessageBoxA(NULL, "One or more necessary functions not found in ntdll.dll.", "Athena Development", MB_OK | MB_ICONERROR);
            return NULL;
        }

        BOOLEAN OldPriv;
        if (!NT_SUCCESS(RtlAdjustPrivilege(SeDebugPriv, TRUE, FALSE, &OldPriv))) {
            MessageBoxA(NULL, "Failed to adjust SeDebugPrivilege. Please run game as admin", "Athena Development", MB_OK | MB_ICONERROR);
        }

        OBJECT_ATTRIBUTES Obj_Attribute = {};
        Obj_Attribute.Length = sizeof(OBJECT_ATTRIBUTES);

        CLIENT_ID clientID = {};
        DWORD size = sizeof(SYSTEM_HANDLE_INFORMATION);
        BYTE* buffer = nullptr;
        SYSTEM_HANDLE_INFORMATION* hInfo = nullptr;
        HANDLE procHandle = NULL;
        HANDLE hHijacked = NULL;

        NTSTATUS NtRet = 0;

        do {
            delete[] buffer;
            size = static_cast<DWORD>(size * 1.5);

            try {
                buffer = new BYTE[size];
                ZeroMemory(buffer, size);
                hInfo = reinterpret_cast<SYSTEM_HANDLE_INFORMATION*>(buffer);
            }
            catch (const std::bad_alloc&) {
                MessageBoxA(NULL, "Memory allocation failed for handle information.", "Athena Development", MB_OK | MB_ICONERROR);
                return NULL;
            }

            NtRet = NtQuerySystemInformation(SystemHandleInformation, hInfo, size, NULL);
            Sleep(1);

        } while (NtRet == STATUS_INFO_LENGTH_MISMATCH);

        if (!NT_SUCCESS(NtRet)) {
            MessageBoxA(NULL, "NtQuerySystemInformation failed to retrieve handle list.", "Athena Development", MB_OK | MB_ICONERROR);
            delete[] buffer;
            return NULL;
        }

        for (unsigned int i = 0; i < hInfo->HandleCount; ++i)
        {
            DWORD ownerPid = hInfo->Handles[i].ProcessId;

            if (ownerPid != dwTargetProcessId)
                continue;

            HANDLE rawHandle = (HANDLE)(ULONG_PTR)hInfo->Handles[i].Handle;

            if (!rawHandle || rawHandle == INVALID_HANDLE_VALUE)
                continue;

            if (hInfo->Handles[i].ObjectTypeNumber != ProcessHandleType)
                continue;

            clientID.UniqueProcess = reinterpret_cast<PVOID>((ULONG_PTR)ownerPid);
            clientID.UniqueThread = 0;

            if (procHandle)
            {
                CloseHandle(procHandle);
                procHandle = NULL;
            }

            NtRet = NtOpenProcess(&procHandle, PROCESS_DUP_HANDLE, &Obj_Attribute, &clientID);
            if (!procHandle || !NT_SUCCESS(NtRet)) {
                continue;
            }

            HANDLE tempHandle = NULL;
            NtRet = NtDuplicateObject(procHandle, rawHandle, NtCurrentProcess, &tempHandle,
                PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE,
                0, 0);

            if (!NT_SUCCESS(NtRet) || !IsHandleValid(tempHandle)) {
                if (tempHandle) {
                    CloseHandle(tempHandle);
                }
                continue;
            }

            DWORD hijackedPid = GetProcessId(tempHandle);

            if (hijackedPid == dwTargetProcessId) {
                hHijacked = tempHandle;
                break;
            }
            CloseHandle(tempHandle);
        }

        if (procHandle)
            CloseHandle(procHandle);

        delete[] buffer;

        return hHijacked;
    }
}
