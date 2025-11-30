#pragma once
#include <Windows.h>
#include <winternl.h>
#include <vector>
#include <algorithm>

// Provide a local LDR_MODULE structure that contains the fields used
// throughout the project. Different Windows SDKs sometimes give
// slightly different field names for internal loader types; using a
// local type here keeps the code stable across SDKs.
typedef struct _LDR_MODULE
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_MODULE, *PLDR_MODULE;


typedef struct _UNLINKED_MODULE
{
	HMODULE hModule;
	PLIST_ENTRY RealInLoadOrderLinks;
	PLIST_ENTRY RealInMemoryOrderLinks;
	PLIST_ENTRY RealInInitializationOrderLinks;
	PLDR_MODULE Entry; // PLDR_DATA_TABLE_ENTRY alias
} UNLINKED_MODULE;

#define UNLINK(x)					\
	(x).Flink->Blink = (x).Blink;	\
	(x).Blink->Flink = (x).Flink;

#define RELINK(x, real)			\
	(x).Flink->Blink = (real);	\
	(x).Blink->Flink = (real);	\
	(real)->Blink = (x).Blink;	\
	(real)->Flink = (x).Flink;

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
	OUT PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE StartRoutine,
	LPVOID Argument,
	ULONG CreateFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	LPVOID AttributeList
	);


struct FindModuleHandle
{
	HMODULE m_hModule;
	FindModuleHandle(HMODULE hModule) : m_hModule(hModule)
	{
	}
	bool operator() (UNLINKED_MODULE const& Module) const
	{
		return (Module.hModule == m_hModule);
	}
};

void UnlinkModuleFromPEB(HMODULE hModule);
void RelinkModuleToPEB(HMODULE hModule);
void WipePEHeader(HMODULE hModule);
void WipeImportTable(HMODULE hModule);
void WipeDebugDirectory(HMODULE hModule);
bool CreateHiddenThread(LPTHREAD_START_ROUTINE startRoutine, LPVOID arg);

// Advanced Anti-Detection Methods
void EraseModuleFromModuleList(HMODULE hModule);
void WipeExceptionHandlers(HMODULE hModule);
void ObfuscateStackTraces();
void DisableDebugPrivileges();
void HideFromProcessHollowing();
void CloakMemoryPatterns();
void DisableETW();
void DisableWindowsHook();
void AntiDumping();
void AntiAttach();
void EraseVAC_LiveSignatures(HMODULE hModule);
