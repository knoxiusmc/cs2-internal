#include "HideModule.h"
#include <xorstr.hpp>

std::vector<UNLINKED_MODULE> UnlinkedModules;

void RelinkModuleToPEB(HMODULE hModule)
{
	std::vector<UNLINKED_MODULE>::iterator it = std::find_if(UnlinkedModules.begin(), UnlinkedModules.end(), FindModuleHandle(hModule));

	if (it == UnlinkedModules.end())
	{
		MessageBoxA(NULL, "DLL not unlinked yet.", "Athena Development", MB_OK);
		return;
	}
	UNLINKED_MODULE m = *it;
	RELINK(m.Entry->InLoadOrderModuleList, m.RealInLoadOrderLinks);
	RELINK(m.Entry->InInitializationOrderModuleList, m.RealInInitializationOrderLinks);
	RELINK(m.Entry->InMemoryOrderModuleList, m.RealInMemoryOrderLinks);
	UnlinkedModules.erase(it);
}

void UnlinkModuleFromPEB(HMODULE hModule)
{
	std::vector<UNLINKED_MODULE>::iterator it = std::find_if(UnlinkedModules.begin(), UnlinkedModules.end(), FindModuleHandle(hModule));
	if (it != UnlinkedModules.end())
	{
		MessageBoxA(NULL, "DLL already unlinked.", "Athena Development", MB_OK);
		return;
	}

#ifdef _WIN64
	PPEB pPEB = (PPEB)__readgsqword(0x60);
#else
	PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif
	PLIST_ENTRY CurrentEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;
	PLDR_MODULE Current = NULL;
	while (CurrentEntry != &pPEB->Ldr->InLoadOrderModuleList && CurrentEntry != NULL)
	{
		Current = CONTAINING_RECORD(CurrentEntry, LDR_MODULE, InLoadOrderModuleList);
		if (Current->BaseAddress == hModule)
		{
			UNLINKED_MODULE CurrentModule = { 0 };
			CurrentModule.hModule = hModule;
			CurrentModule.RealInLoadOrderLinks = Current->InLoadOrderModuleList.Blink->Flink;
			CurrentModule.RealInInitializationOrderLinks = Current->InInitializationOrderModuleList.Blink->Flink;
			CurrentModule.RealInMemoryOrderLinks = Current->InMemoryOrderModuleList.Blink->Flink;
			CurrentModule.Entry = Current;
			UnlinkedModules.push_back(CurrentModule);

			UNLINK(Current->InLoadOrderModuleList);
			UNLINK(Current->InInitializationOrderModuleList);
			UNLINK(Current->InMemoryOrderModuleList);

			break;
		}

		CurrentEntry = CurrentEntry->Flink;
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