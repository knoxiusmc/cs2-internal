#include "memory.hpp"
#include <tlhelp32.h>
#include "handle_hijack.hpp"

uint32_t pProcess::FindProcessIdByProcessName(const char* ProcessName)
{
	std::wstring wideProcessName;
	int wideCharLength = MultiByteToWideChar(CP_UTF8, 0, ProcessName, -1, nullptr, 0);
	if (wideCharLength > 0)
	{
		wideProcessName.resize(wideCharLength);
		MultiByteToWideChar(CP_UTF8, 0, ProcessName, -1, &wideProcessName[0], wideCharLength);
	}

	HANDLE hPID = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32W process_entry_{ };
	process_entry_.dwSize = sizeof(PROCESSENTRY32W);

	DWORD pid = 0;
	if (Process32FirstW(hPID, &process_entry_))
	{
		do
		{
			if (!wcscmp(process_entry_.szExeFile, wideProcessName.c_str()))
			{
				pid = process_entry_.th32ProcessID;
				break;
			}
		} while (Process32NextW(hPID, &process_entry_));
	}
	CloseHandle(hPID);
	return pid;
}

uint32_t pProcess::FindProcessIdByWindowName(const char* WindowName)
{
	DWORD process_id = 0;
	HWND windowHandle = FindWindowA(nullptr, WindowName);
	if (windowHandle)
		GetWindowThreadProcessId(windowHandle, &process_id);
	return process_id;
}

HWND pProcess::GetWindowHandleFromProcessId(DWORD ProcessId) {
	HWND hwnd = NULL;
	do {
		hwnd = FindWindowEx(NULL, hwnd, NULL, NULL);
		DWORD pid = 0;
		GetWindowThreadProcessId(hwnd, &pid);
		if (pid == ProcessId) {
			TCHAR windowTitle[MAX_PATH];
			GetWindowText(hwnd, windowTitle, MAX_PATH);
			if (IsWindowVisible(hwnd) && windowTitle[0] != '\0') {
				return hwnd;
			}
		}
	} while (hwnd != NULL);
	return NULL;
}

bool pProcess::AttachProcess(const char* ProcessName)
{
	this->pid_ = this->FindProcessIdByProcessName(ProcessName);

	if (pid_)
	{
		HMODULE modules[0xFF];
		MODULEINFO module_info;
		DWORD _;

		handle_ = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid_);

		EnumProcessModulesEx(this->handle_, modules, sizeof(modules), &_, LIST_MODULES_64BIT);
		base_client_.base = (uintptr_t)modules[0];

		GetModuleInformation(this->handle_, modules[0], &module_info, sizeof(module_info));
		base_client_.size = module_info.SizeOfImage;

		hwnd_ = this->GetWindowHandleFromProcessId(pid_);

		return true;
	}

	return false;
}

bool pProcess::AttachProcessHj(const char* ProcessName, bool fallback_to_normal_attach)
{
	this->pid_ = this->FindProcessIdByProcessName(ProcessName);

	if (pid_)
	{
		HMODULE modules[0xFF];
		MODULEINFO module_info;
		DWORD _;

		handle_ = hj::HijackExistingHandle(pid_);

		if (!hj::IsHandleValid(handle_))
		{
			if (fallback_to_normal_attach)
			{
				MessageBoxA(NULL, "Hijack failed, using fallback method. Risk is higher", "Athena Development", MB_OK | MB_ICONERROR);
				return pProcess::AttachProcess(ProcessName);
			}
			else
			{
				MessageBoxA(NULL, "Handle Hijack Failed", "Athena Development", MB_OK | MB_ICONERROR);
				return false;
			}
		}

		EnumProcessModulesEx(this->handle_, modules, sizeof(modules), &_, LIST_MODULES_64BIT);
		base_client_.base = (uintptr_t)modules[0];

		GetModuleInformation(this->handle_, modules[0], &module_info, sizeof(module_info));
		base_client_.size = module_info.SizeOfImage;

		hwnd_ = this->GetWindowHandleFromProcessId(pid_);

		return true;
	}

	return false;
}


bool pProcess::AttachWindow(const char* WindowName)
{
	this->pid_ = this->FindProcessIdByWindowName(WindowName);

	if (pid_)
	{
		HMODULE modules[0xFF];
		MODULEINFO module_info;
		DWORD _;

		handle_ = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid_);

		EnumProcessModulesEx(this->handle_, modules, sizeof(modules), &_, LIST_MODULES_64BIT);
		base_client_.base = (uintptr_t)modules[0];

		GetModuleInformation(this->handle_, modules[0], &module_info, sizeof(module_info));
		base_client_.size = module_info.SizeOfImage;

		hwnd_ = this->GetWindowHandleFromProcessId(pid_);

		return true;
	}
	return false;
}

bool pProcess::UpdateHWND()
{
	hwnd_ = this->GetWindowHandleFromProcessId(pid_);
	return hwnd_ == nullptr;
}

ProcessModule pProcess::GetModule(const char* lModule)
{
	std::wstring wideModule;
	int wideCharLength = MultiByteToWideChar(CP_UTF8, 0, lModule, -1, nullptr, 0);
	if (wideCharLength > 0)
	{
		wideModule.resize(wideCharLength);
		MultiByteToWideChar(CP_UTF8, 0, lModule, -1, &wideModule[0], wideCharLength);
	}

	HANDLE handle_module = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid_);
	MODULEENTRY32W module_entry_{};
	module_entry_.dwSize = sizeof(MODULEENTRY32W);

	do
	{
		if (!wcscmp(module_entry_.szModule, wideModule.c_str()))
		{
			CloseHandle(handle_module);
			return { (DWORD_PTR)module_entry_.modBaseAddr, module_entry_.dwSize };
		}
	} while (Module32NextW(handle_module, &module_entry_));

	CloseHandle(handle_module);
	return { 0, 0 };
}

LPVOID pProcess::Allocate(size_t size_in_bytes)
{
	return VirtualAllocEx(this->handle_, NULL, size_in_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

uintptr_t pProcess::FindSignature(std::vector<uint8_t> signature)
{
	std::unique_ptr<uint8_t[]> data;
	data = std::make_unique<uint8_t[]>(this->base_client_.size);

	if (!ReadProcessMemory(this->handle_, (void*)(this->base_client_.base), data.get(), this->base_client_.size, NULL)) {
		return 0x0;
	}

	for (uintptr_t i = 0; i < this->base_client_.size; i++)
	{
		for (uintptr_t j = 0; j < signature.size(); j++)
		{
			if (signature.at(j) == 0x00)
				continue;

			if (*reinterpret_cast<uint8_t*>(reinterpret_cast<uintptr_t>(&data[i + j])) == signature.at(j))
			{
				if (j == signature.size() - 1)
					return this->base_client_.base + i;
				continue;
			}
			break;
		}
	}
	return 0x0;
}

uintptr_t pProcess::FindSignature(ProcessModule target_module, std::vector<uint8_t> signature)
{
	std::unique_ptr<uint8_t[]> data;
	data = std::make_unique<uint8_t[]>(0xFFFFFFF);

	if (!ReadProcessMemory(this->handle_, (void*)(target_module.base), data.get(), 0xFFFFFFF, NULL)) {
		return NULL;
	}

	for (uintptr_t i = 0; i < 0xFFFFFFF; i++)
	{
		for (uintptr_t j = 0; j < signature.size(); j++)
		{
			if (signature.at(j) == 0x00)
				continue;

			if (*reinterpret_cast<uint8_t*>(reinterpret_cast<uintptr_t>(&data[i + j])) == signature.at(j))
			{
				if (j == signature.size() - 1)
					return this->base_client_.base + i;
				continue;
			}
			break;
		}
	}
	return 0x0;
}

uintptr_t pProcess::FindCodeCave(uint32_t length_in_bytes)
{
	std::vector<uint8_t> cave_pattern = {};

	for (uint32_t i = 0; i < length_in_bytes; i++) {
		cave_pattern.push_back(0x00);
	}

	return FindSignature(cave_pattern);
}

void pProcess::Close()
{
	CloseHandle(handle_);
}

// ============ ANTI-DETECTION IMPLEMENTATIONS ============

bool pProcess::AntiScan_RemoveModuleSignatures()
{
	// Remove identifiable signatures from target process memory
	HMODULE modules[256];
	MODULEINFO moduleInfo;
	DWORD moduleCount = 0;

	if (!EnumProcessModulesEx(this->handle_, modules, sizeof(modules), &moduleCount, LIST_MODULES_64BIT))
		return false;

	moduleCount = moduleCount / sizeof(HMODULE);

	for (DWORD i = 0; i < moduleCount; i++)
	{
		// Get module information
		if (!GetModuleInformation(this->handle_, modules[i], &moduleInfo, sizeof(moduleInfo)))
			continue;

		// Read module header
		BYTE dosHeader[64];
		if (!read_raw((uintptr_t)moduleInfo.lpBaseOfDll, dosHeader, sizeof(dosHeader)))
			continue;

		// Check for DOS signature
		if (*(WORD*)dosHeader != 0x5A4D) // 'MZ'
			continue;

		// Wipe PE header signature to prevent identification
		BYTE patch[2] = { 0xFF, 0xFF };
		write_bytes((uintptr_t)moduleInfo.lpBaseOfDll, { patch[0], patch[1] });
	}

	return true;
}

bool pProcess::AntiScan_PatchMemoryGuards()
{
	// Patch known VAC memory guard patterns
	std::vector<uint8_t> guard_pattern = {
		0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x20, 0x8B, 0x45, 0x08
	};

	// Search for guard patterns and neutralize them
	for (uintptr_t addr = base_client_.base; addr < base_client_.base + base_client_.size; addr += 0x1000)
	{
		BYTE buffer[256];
		if (read_raw(addr, buffer, sizeof(buffer)))
		{
			// Replace suspicious patterns with NOPs
			for (size_t i = 0; i < sizeof(buffer) - guard_pattern.size(); i++)
			{
				bool match = true;
				for (size_t j = 0; j < guard_pattern.size(); j++)
				{
					if (buffer[i + j] != guard_pattern[j])
					{
						match = false;
						break;
					}
				}

				if (match)
				{
					// Found pattern - replace with NOPs
					std::vector<uint8_t> nops(guard_pattern.size(), 0x90);
					write_bytes(addr + i, nops);
				}
			}
		}
	}

	return true;
}

bool pProcess::AntiScan_ObfuscateModuleBase()
{
	// Make module base appear randomized to prevent scanning
	DWORD_PTR fakeBase = (DWORD_PTR)(rand() % 0xFFFFFFFF);
	
	// Allocate fake module at random address
	LPVOID fakeModule = Allocate(0x1000);
	if (fakeModule)
	{
		// Write misleading data
		BYTE fakeData[256];
		for (int i = 0; i < sizeof(fakeData); i++)
		{
			fakeData[i] = rand() % 256;
		}
		write_bytes((uintptr_t)fakeModule, std::vector<uint8_t>(fakeData, fakeData + sizeof(fakeData)));
	}

	return true;
}

bool pProcess::AntiScan_RandomizeMemory()
{
	// Randomize memory layout to disrupt pattern analysis
	for (uintptr_t addr = base_client_.base; addr < base_client_.base + base_client_.size; addr += 0x10000)
	{
		BYTE randomData[256];
		for (int i = 0; i < sizeof(randomData); i++)
		{
			randomData[i] = rand() % 256;
		}

		// Write random patterns to unused memory
		write_bytes(addr, std::vector<uint8_t>(randomData, randomData + sizeof(randomData)));
	}

	return true;
}

bool pProcess::AntiScan_HideMemoryPages()
{
	// Mark memory pages as inaccessible to prevent scanning
	MEMORY_BASIC_INFORMATION mbi;
	uintptr_t address = base_client_.base;

	while (address < base_client_.base + base_client_.size)
	{
		if (VirtualQueryEx(this->handle_, (LPVOID)address, &mbi, sizeof(mbi)) == 0)
			break;

		// Change protection on suspicious pages
		if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_READWRITE)
		{
			DWORD oldProtect;
			VirtualProtectEx(this->handle_, mbi.BaseAddress, mbi.RegionSize, PAGE_NOACCESS, &oldProtect);
		}

		address += mbi.RegionSize;
	}

	return true;
}

bool pProcess::AntiScan_InvalidateImportTables()
{
	// Corrupt import address tables to prevent scanning
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, this->pid_);
	if (snapshot == INVALID_HANDLE_VALUE)
		return false;

	MODULEENTRY32 modEntry;
	modEntry.dwSize = sizeof(MODULEENTRY32);

	if (Module32First(snapshot, &modEntry))
	{
		do {
			// Read module base
			BYTE dosHeader[64];
			if (!read_raw((uintptr_t)modEntry.modBaseAddr, dosHeader, sizeof(dosHeader)))
				continue;

			// Verify DOS signature
			if (*(WORD*)dosHeader != 0x5A4D)
				continue;

			// Wipe IAT
			BYTE iatWipe[512];
			ZeroMemory(iatWipe, sizeof(iatWipe));
			write_bytes((uintptr_t)modEntry.modBaseAddr + 0x3000, std::vector<uint8_t>(iatWipe, iatWipe + sizeof(iatWipe)));

		} while (Module32Next(snapshot, &modEntry));
	}

	CloseHandle(snapshot);
	return true;
}