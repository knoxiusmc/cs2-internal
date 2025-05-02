#ifndef _PPROCESS_HPP_
#define _PPROCESS_HPP_

#include <vector>
#include <math.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <iostream>
#include <Psapi.h> 

typedef NTSTATUS(WINAPI* pNtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesRead);
typedef NTSTATUS(WINAPI* pNtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);

class pMemory {

public:
	pMemory() {
		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (!ntdll)
			FreeLibraryAndExitThread(GetModuleHandleA(NULL), -1);
		pfnNtReadVirtualMemory = (pNtReadVirtualMemory)GetProcAddress(ntdll, "NtReadVirtualMemory");
		pfnNtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
	}

	pNtReadVirtualMemory pfnNtReadVirtualMemory;
	pNtWriteVirtualMemory pfnNtWriteVirtualMemory;
};

struct ProcessModule
{
	uintptr_t base, size;
};

class pProcess
{
public:
	DWORD		  pid_;
	HANDLE		  handle_;
	HWND		  hwnd_;
	ProcessModule base_client_;

public:
	bool AttachProcess(const char* process_name);
	bool AttachProcessHj(const char* process_name, bool fallback_to_normal_attach);
	bool AttachWindow(const char* window_name);
	bool UpdateHWND();
	void Close();

public:
	ProcessModule GetModule(const char* module_name);
	LPVOID		  Allocate(size_t size_in_bytes);
	uintptr_t	  FindCodeCave(uint32_t length_in_bytes);
	uintptr_t     FindSignature(std::vector<uint8_t> signature);
	uintptr_t     FindSignature(ProcessModule target_module, std::vector<uint8_t> signature);

	bool read_raw(uintptr_t address, void* buffer, size_t size)
	{
		SIZE_T bytesRead;
		pMemory cMemory;

		if (cMemory.pfnNtReadVirtualMemory(this->handle_, (PVOID)(address), buffer, static_cast<ULONG>(size), (PULONG)&bytesRead))
		{
			return bytesRead == size;
		}
		return false;
	}

	template<class T>
	void write(uintptr_t address, T value)
	{
		pMemory cMemory;
		cMemory.pfnNtWriteVirtualMemory(handle_, (void*)address, &value, sizeof(T), 0);
	}

	template<class T>
	T read(uintptr_t address)
	{
		T buffer{};
		pMemory cMemory;
#pragma warning(disable: 4267)
		cMemory.pfnNtReadVirtualMemory(handle_, (void*)address, &buffer, sizeof(T), 0);
		return buffer;
	}

	void write_bytes(uintptr_t addr, std::vector<uint8_t> patch)
	{
		pMemory cMemory;
		cMemory.pfnNtWriteVirtualMemory(handle_, (void*)addr, &patch[0], patch.size(), 0);
	}

private:
	uint32_t FindProcessIdByProcessName(const char* process_name);
	uint32_t FindProcessIdByWindowName(const char* window_name);
	HWND GetWindowHandleFromProcessId(DWORD ProcessId);
};
#endif