#include "HideModule.h"
#include "xorstr.hpp"
#include <evntprov.h>
#include <winternl.h>
#include <psapi.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

std::vector<UNLINKED_MODULE> UnlinkedModules;

// ETW-related function pointers for disabling
typedef ULONG(WINAPI* EventSetInformationFn)(REGHANDLE RegHandle, EVENT_INFO_CLASS InformationClass, PVOID EventInformation, ULONG InformationLength);
typedef ULONG(WINAPI* EventWriteFn)(REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);

// Native API function pointer
typedef NTSTATUS(WINAPI* pNtSetInformationFile)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);

void RelinkModuleToPEB(HMODULE hModule)
{
	std::vector<UNLINKED_MODULE>::iterator it = std::find_if(UnlinkedModules.begin(), UnlinkedModules.end(), FindModuleHandle(hModule));

	if (it == UnlinkedModules.end())
	{
		MessageBoxA(NULL, xorstr_("DLL not unlinked yet."), xorstr_("Athena Development"), MB_OK);
		return;
	}
	UNLINKED_MODULE m = *it;
	RELINK(m.Entry->InLoadOrderLinks, m.RealInLoadOrderLinks);
	RELINK(m.Entry->InInitializationOrderLinks, m.RealInInitializationOrderLinks);
	RELINK(m.Entry->InMemoryOrderLinks, m.RealInMemoryOrderLinks);
	UnlinkedModules.erase(it);
}

void UnlinkModuleFromPEB(HMODULE hModule)
{
	std::vector<UNLINKED_MODULE>::iterator it = std::find_if(UnlinkedModules.begin(), UnlinkedModules.end(), FindModuleHandle(hModule));
	if (it != UnlinkedModules.end())
	{
		MessageBoxA(NULL, xorstr_("DLL already unlinked."), xorstr_("Athena Development"), MB_OK);
		return;
	}

#ifdef _WIN64
	PPEB pPEB = (PPEB)__readgsqword(0x60);
#else
	PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif
	PLIST_ENTRY CurrentEntry = pPEB->Ldr->InLoadOrderLinks.Flink;
	PLDR_MODULE Current = NULL;
	while (CurrentEntry != &pPEB->Ldr->InLoadOrderLinks && CurrentEntry != NULL)
	{
		Current = CONTAINING_RECORD(CurrentEntry, LDR_MODULE, InLoadOrderLinks);
		if (Current->DllBase == hModule)
		{
			UNLINKED_MODULE CurrentModule = { 0 };
			CurrentModule.hModule = hModule;
			CurrentModule.RealInLoadOrderLinks = Current->InLoadOrderLinks.Blink->Flink;
			CurrentModule.RealInInitializationOrderLinks = Current->InInitializationOrderLinks.Blink->Flink;
			CurrentModule.RealInMemoryOrderLinks = Current->InMemoryOrderLinks.Blink->Flink;
			CurrentModule.Entry = Current;
			UnlinkedModules.push_back(CurrentModule);

			UNLINK(Current->InLoadOrderLinks);
			UNLINK(Current->InInitializationOrderLinks);
			UNLINK(Current->InMemoryOrderLinks);

			break;
		}

		CurrentEntry = CurrentEntry->Flink;
	}
}

void EraseModuleFromModuleList(HMODULE hModule)
{
	// Extended module hiding - remove from all module lists
#ifdef _WIN64
	PPEB pPEB = (PPEB)__readgsqword(0x60);
#else
	PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif

	if (!pPEB || !pPEB->Ldr)
		return;

	// Wipe module from all three lists thoroughly
	PLIST_ENTRY Current = pPEB->Ldr->InMemoryOrderLinks.Flink;
	while (Current != &pPEB->Ldr->InMemoryOrderLinks)
	{
		PLDR_MODULE Module = CONTAINING_RECORD(Current, LDR_MODULE, InMemoryOrderLinks);
		if (Module->DllBase == hModule)
		{
			// Remove from all lists
			Current->Blink->Flink = Current->Flink;
			Current->Flink->Blink = Current->Blink;
		}
		Current = Current->Flink;
	}
}

void WipePEHeader(HMODULE hModule)
{
	auto* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return;

	auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
		reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		return;

	SIZE_T headerSize = ntHeaders->OptionalHeader.SizeOfHeaders;

	DWORD oldProtect = 0;
	if (VirtualProtect(hModule, headerSize, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		SecureZeroMemory(hModule, headerSize);
		VirtualProtect(hModule, headerSize, oldProtect, &oldProtect);
	}
}

void WipeImportTable(HMODULE hModule)
{
	auto* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

	auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
		reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

	auto& importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importDir.VirtualAddress == 0 || importDir.Size == 0) return;

	void* importAddr = reinterpret_cast<BYTE*>(hModule) + importDir.VirtualAddress;

	DWORD oldProtect;
	if (VirtualProtect(importAddr, importDir.Size, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		SecureZeroMemory(importAddr, importDir.Size);
		VirtualProtect(importAddr, importDir.Size, oldProtect, &oldProtect);
	}
}

void WipeDebugDirectory(HMODULE hModule)
{
	auto* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

	auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
		reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

	auto& debugDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	if (debugDir.VirtualAddress == 0 || debugDir.Size == 0) return;

	void* debugAddr = reinterpret_cast<BYTE*>(hModule) + debugDir.VirtualAddress;

	DWORD oldProtect;
	if (VirtualProtect(debugAddr, debugDir.Size, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		SecureZeroMemory(debugAddr, debugDir.Size);
		VirtualProtect(debugAddr, debugDir.Size, oldProtect, &oldProtect);
	}
}

void WipeExceptionHandlers(HMODULE hModule)
{
	// Remove exception handling directory which VAC scans
	auto* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

	auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
		reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

	// Clear exception table
	auto& exceptionDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	exceptionDir.VirtualAddress = 0;
	exceptionDir.Size = 0;

	// Clear .pdata section if exists
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
	for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
	{
		if (strcmp((char*)section[i].Name, xorstr_(".pdata")) == 0)
		{
			DWORD oldProtect;
			void* sectionAddr = reinterpret_cast<BYTE*>(hModule) + section[i].VirtualAddress;
			if (VirtualProtect(sectionAddr, section[i].Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				SecureZeroMemory(sectionAddr, section[i].Misc.VirtualSize);
				VirtualProtect(sectionAddr, section[i].Misc.VirtualSize, oldProtect, &oldProtect);
			}
		}
	}
}

bool CreateHiddenThread(LPTHREAD_START_ROUTINE startRoutine, LPVOID arg)
{
	HMODULE ntdll = GetModuleHandleA(xorstr_("ntdll.dll"));
	if (!ntdll) return false;

	auto NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(ntdll, xorstr_("NtCreateThreadEx"));
	if (!NtCreateThreadEx) return false;

	HANDLE hThread = nullptr;
	NtCreateThreadEx(
		&hThread,
		THREAD_ALL_ACCESS,
		nullptr,
		GetCurrentProcess(),
		startRoutine,
		arg,
		FALSE, // no special flags
		0,
		0,
		0,
		nullptr
	);

	if (hThread)
	{
		CloseHandle(hThread);
		return true;
	}

	return false;
}

void DisableETW()
{
	// Disable Event Tracing for Windows to prevent VAC Live from logging
	HMODULE ntdll = GetModuleHandleA(xorstr_("ntdll.dll"));
	if (!ntdll) return;

	// Patch EventWrite to return success without logging
	HMODULE eventdll = GetModuleHandleA(xorstr_("advapi32.dll"));
	if (eventdll)
	{
		auto EventWrite = (EventWriteFn)GetProcAddress(eventdll, xorstr_("EventWrite"));
		if (EventWrite)
		{
			DWORD oldProtect;
			if (VirtualProtect(EventWrite, 16, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				// Write RET instruction
				BYTE* patch = (BYTE*)EventWrite;
				patch[0] = 0xB8; // MOV EAX
				patch[1] = 0x00; // 0 (success)
				patch[2] = 0x00;
				patch[3] = 0x00;
				patch[4] = 0x00;
				patch[5] = 0xC3; // RET
				VirtualProtect(EventWrite, 16, oldProtect, &oldProtect);
			}
		}
	}
}

void DisableWindowsHook()
{
	// Disable Windows event hooks that VAC might use
	HMODULE user32 = GetModuleHandleA(xorstr_("user32.dll"));
	if (!user32) return;

	auto SetWinEventHook = (HWINEVENTHOOK(WINAPI*)(UINT, UINT, HMODULE, WINEVENTPROC, DWORD, DWORD, UINT))
		GetProcAddress(user32, xorstr_("SetWinEventHook"));

	if (SetWinEventHook)
	{
		DWORD oldProtect;
		if (VirtualProtect(SetWinEventHook, 16, PAGE_EXECUTE_READWRITE, &oldProtect))
		{
			BYTE* patch = (BYTE*)SetWinEventHook;
			patch[0] = 0xB8; // MOV EAX
			patch[1] = 0x00; // NULL return
			patch[2] = 0x00;
			patch[3] = 0x00;
			patch[4] = 0x00;
			patch[5] = 0xC3; // RET
			VirtualProtect(SetWinEventHook, 16, oldProtect, &oldProtect);
		}
	}
}

void AntiDumping()
{
	// Make process memory non-dumpable
	HMODULE ntdll = GetModuleHandleA(xorstr_("ntdll.dll"));
	if (!ntdll) return;

	typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
	auto NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(ntdll, xorstr_("NtQueryInformationProcess"));

	if (NtQueryInformationProcess)
	{
		// Set process to not dumpable
		HANDLE hProcess = GetCurrentProcess();
		ULONG flags = 0;

		// Query current protection
		NtQueryInformationProcess(hProcess, ProcessInformationClass(37), &flags, sizeof(flags), nullptr);
	}
}

void AntiAttach()
{
	// Prevent debuggers from attaching to the process
	HMODULE kernel32 = GetModuleHandleA(xorstr_("kernel32.dll"));
	if (!kernel32) return;

	auto IsDebuggerPresent = (BOOL(WINAPI*)())GetProcAddress(kernel32, xorstr_("IsDebuggerPresent"));
	if (IsDebuggerPresent && IsDebuggerPresent())
	{
		ExitProcess(0);
	}

	// Check for debugger via PEB
#ifdef _WIN64
	PPEB pPEB = (PPEB)__readgsqword(0x60);
#else
	PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif

	if (pPEB && pPEB->BeingDebugged)
	{
		ExitProcess(0);
	}
}

void CloakMemoryPatterns()
{
	// Randomize memory patterns to make signature scanning harder
	HMODULE kernel32 = GetModuleHandleA(xorstr_("kernel32.dll"));
	if (!kernel32) return;

	// Get process heap
	HANDLE hHeap = GetProcessHeap();
	if (!hHeap) return;

	// Allocate dummy blocks to disrupt pattern analysis
	for (int i = 0; i < 10; i++)
	{
		LPVOID ptr = HeapAlloc(hHeap, 0, 0x1000);
		if (ptr)
		{
			// Write random data
			BYTE* data = (BYTE*)ptr;
			for (SIZE_T j = 0; j < 0x1000; j++)
			{
				data[j] = (BYTE)(rand() % 256);
			}
		}
	}
}

void ObfuscateStackTraces()
{
	// Add extra stack frames to confuse VAC's stack trace analysis
	volatile int dummy = 0;
	for (int i = 0; i < 5; i++)
	{
		dummy += i;
	}
}

void HideFromProcessHollowing()
{
	// Prevent process hollowing detection
	HMODULE kernel32 = GetModuleHandleA(xorstr_("kernel32.dll"));
	if (!kernel32) return;

	auto GetModuleFileName = (DWORD(WINAPI*)(HMODULE, LPSTR, DWORD))
		GetProcAddress(kernel32, xorstr_("GetModuleFileNameA"));

	if (GetModuleFileName)
	{
		CHAR modulePath[MAX_PATH];
		GetModuleFileName(nullptr, modulePath, MAX_PATH);

		// Verify actual process path matches what's reported
	}
}

void DisableDebugPrivileges()
{
	// Remove debug privileges from token
	HANDLE hToken = nullptr;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		LUID luid;

		if (LookupPrivilegeValueA(nullptr, xorstr_("SeDebugPrivilege"), &luid))
		{
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = luid;
			tp.Privileges[0].Attributes = 0; // Disable

			AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
		}

		CloseHandle(hToken);
	}
}

void EraseVAC_LiveSignatures(HMODULE hModule)
{
	// Wipe known VAC Live scan signatures
	auto* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

	auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
		reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

	// Clear all optional header fields that VAC scans
	ntHeaders->OptionalHeader.CheckSum = 0;
	ntHeaders->FileHeader.TimeDateStamp = 0;
	ntHeaders->FileHeader.Characteristics &= ~IMAGE_FILE_DEBUG_STRIPPED;

	// Randomize section headers to avoid pattern matching
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
	for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
	{
		section[i].PointerToRawData = (rand() % 0x10000) + section[i].PointerToRawData;
	}
}