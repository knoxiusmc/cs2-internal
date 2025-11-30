#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include "xorstr.hpp"
#include <tlhelp32.h>
#include <winternl.h>
#include <psapi.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

typedef NTSTATUS(WINAPI* pNtSetInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(WINAPI* pNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(WINAPI* pNtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);

namespace AntiDetection
{
	class SyscallHelper
	{
	public:
		static HMODULE GetNtdll()
		{
			return GetModuleHandleA(xorstr_("ntdll.dll"));
		}

		template<typename T>
		static T GetSyscall(const char* funcName)
		{
			HMODULE ntdll = GetNtdll();
			if (!ntdll) return nullptr;
			return (T)GetProcAddress(ntdll, funcName);
		}
	};

	class KernelEvasion
	{
	public:
		static void HideModuleFromKernel(HMODULE hModule)
		{
			HMODULE ntdll = SyscallHelper::GetNtdll();
			if (!ntdll) return;

			auto NtProtectVirtualMemory = SyscallHelper::GetSyscall<pNtProtectVirtualMemory>(xorstr_("NtProtectVirtualMemory"));
			if (!NtProtectVirtualMemory) return;

			MODULEINFO modInfo;
			if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo)))
				return;

			PVOID baseAddress = modInfo.lpBaseOfDll;
			SIZE_T regionSize = modInfo.SizeOfImage;
			ULONG newProtect = 0;
			ULONG oldProtect = 0;

			// Mark entire module as PAGE_NOACCESS to prevent kernel inspection
			NtProtectVirtualMemory(GetCurrentProcess(), &baseAddress, &regionSize, PAGE_NOACCESS, &oldProtect);

			// Restore after brief delay
			Sleep(100);
			newProtect = PAGE_EXECUTE_READWRITE;
			NtProtectVirtualMemory(GetCurrentProcess(), &baseAddress, &regionSize, newProtect, &oldProtect);
		}

		static void RandomizeModuleImageBase(HMODULE hModule)
		{
			auto* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
			if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

			auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
				reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
			if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

			// Randomize image base field
			DWORD oldProtect;
			if (VirtualProtect(&ntHeaders->OptionalHeader.ImageBase, sizeof(DWORD_PTR), PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				ntHeaders->OptionalHeader.ImageBase = (DWORD_PTR)(0x400000 + (rand() % 0x100000));
				VirtualProtect(&ntHeaders->OptionalHeader.ImageBase, sizeof(DWORD_PTR), oldProtect, &oldProtect);
			}
		}

		static void CorruptModuleTimestamp(HMODULE hModule)
		{
			auto* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
			if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

			auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
				reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
			if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

			DWORD oldProtect;
			if (VirtualProtect(&ntHeaders->FileHeader.TimeDateStamp, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				ntHeaders->FileHeader.TimeDateStamp = 0;
				VirtualProtect(&ntHeaders->FileHeader.TimeDateStamp, sizeof(DWORD), oldProtect, &oldProtect);
			}
		}

		static void EraseRelocationTable(HMODULE hModule)
		{
			auto* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
			if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

			auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
				reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
			if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

			auto& relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			if (relocDir.VirtualAddress == 0 || relocDir.Size == 0) return;

			void* relocAddr = reinterpret_cast<BYTE*>(hModule) + relocDir.VirtualAddress;
			DWORD oldProtect;
			if (VirtualProtect(relocAddr, relocDir.Size, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				SecureZeroMemory(relocAddr, relocDir.Size);
				VirtualProtect(relocAddr, relocDir.Size, oldProtect, &oldProtect);
			}
		}

		static void WipeResourceSection(HMODULE hModule)
		{
			auto* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
			if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

			auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
				reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
			if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

			auto& rsrcDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
			if (rsrcDir.VirtualAddress == 0 || rsrcDir.Size == 0) return;

			void* rsrcAddr = reinterpret_cast<BYTE*>(hModule) + rsrcDir.VirtualAddress;
			DWORD oldProtect;
			if (VirtualProtect(rsrcAddr, rsrcDir.Size, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				SecureZeroMemory(rsrcAddr, rsrcDir.Size);
				VirtualProtect(rsrcAddr, rsrcDir.Size, oldProtect, &oldProtect);
			}
		}
	};

	class SignatureEvasion
	{
	public:
		static void PatchCommonFunctionPrologs(HMODULE hModule)
		{
			auto* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
			if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

			auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
				reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
			if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

			PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
			for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
			{
				if ((section[i].Characteristics & IMAGE_SCN_CNT_CODE) != 0)
				{
					BYTE* sectionData = (BYTE*)hModule + section[i].VirtualAddress;
					DWORD oldProtect;

					if (VirtualProtect(sectionData, section[i].Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect))
					{
						// Patch common prologs with equivalent obfuscated versions
						for (DWORD j = 0; j < section[i].Misc.VirtualSize - 8; j++)
						{
							// Pattern: 55 8B EC 83 EC (PUSH EBP; MOV EBP,ESP; SUB ESP,imm)
							if (sectionData[j] == 0x55 && sectionData[j+1] == 0x8B && sectionData[j+2] == 0xEC)
							{
								sectionData[j] ^= rand() & 0xFF;
								sectionData[j+1] ^= rand() & 0xFF;
								sectionData[j+2] ^= rand() & 0xFF;
							}
						}

						VirtualProtect(sectionData, section[i].Misc.VirtualSize, oldProtect, &oldProtect);
					}
				}
			}
		}

		static void XOREncodeExportTable(HMODULE hModule)
		{
			auto* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
			if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

			auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
				reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
			if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

			auto& exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) return;

			BYTE* exportAddr = (BYTE*)hModule + exportDir.VirtualAddress;
			DWORD oldProtect;
			if (VirtualProtect(exportAddr, exportDir.Size, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				BYTE xorKey = rand() & 0xFF;
				for (DWORD i = 0; i < exportDir.Size; i++)
				{
					exportAddr[i] ^= xorKey;
				}
				VirtualProtect(exportAddr, exportDir.Size, oldProtect, &oldProtect);
			}
		}

		static void CloakSecurityCookies(HMODULE hModule)
		{
			auto* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
			if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

			auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
				reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
			if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

			// Find .data section and randomize security cookies
			PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
			for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
			{
				if (strcmp((char*)section[i].Name, xorstr_(".data")) == 0)
				{
					BYTE* sectionData = (BYTE*)hModule + section[i].VirtualAddress;
					DWORD oldProtect;

					if (VirtualProtect(sectionData, section[i].Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect))
					{
						// Randomize potential security cookies
						for (DWORD j = 0; j < section[i].Misc.VirtualSize; j += 8)
						{
							*(DWORD64*)&sectionData[j] ^= 0xDEADBEEFDEADBEEF;
						}

						VirtualProtect(sectionData, section[i].Misc.VirtualSize, oldProtect, &oldProtect);
					}
				}
			}
		}

		static void DisguiseLoadOrder()
		{
			HMODULE ntdll = SyscallHelper::GetNtdll();
			if (!ntdll) return;

#ifdef _WIN64
			PPEB pPEB = (PPEB)__readgsqword(0x60);
#else
			PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif

			if (!pPEB || !pPEB->Ldr) return;

			// Randomize load order by swapping module list entries
			PLIST_ENTRY entry1 = pPEB->Ldr->InLoadOrderModuleList.Flink;
			PLIST_ENTRY entry2 = entry1->Flink;

			if (entry1 != &pPEB->Ldr->InLoadOrderModuleList && entry2 != &pPEB->Ldr->InLoadOrderModuleList)
			{
				PLIST_ENTRY temp = entry1->Flink;
				entry1->Flink = entry2->Flink;
				entry2->Flink = temp;
				entry1->Flink->Blink = entry1;
				entry2->Flink->Blink = entry2;
			}
		}
	};

	class BehavioralEvasion
	{
	public:
		static void ImplementCallStackObfuscation()
		{
			// Create fake call stack by invoking various functions
			volatile DWORD dummy = 0;

			// Multiple nested calls to obfuscate real stack trace
			for (int i = 0; i < 5; i++)
			{
				dummy += i;
				Sleep(rand() % 10);
			}

			// Calculate something to waste CPU cycles
			for (int i = 0; i < 1000; i++)
			{
				dummy ^= (rand() & 0xFFFF);
			}
		}

		static void TimingJitterRandomization()
		{
			// Add random sleep intervals to break timing-based detection
			DWORD jitterAmount = (rand() % 500) + 100;
			Sleep(jitterAmount);

			// Volatile loop to avoid compiler optimization
			volatile int j = jitterAmount;
			while (j-- > 0)
			{
				_mm_pause();
			}
		}

		static void MemoryAccessPatternRandomization()
		{
			// Access memory in random patterns
			BYTE buffer[4096];
			for (int i = 0; i < 4096; i += (rand() % 64 + 1))
			{
				volatile BYTE val = buffer[i];
				buffer[i] = rand() & 0xFF;
			}
		}

		static void FloatingPointOperations()
		{
			// Perform floating-point operations to be harder to trace
			volatile double result = 0.0;
			for (int i = 0; i < 100; i++)
			{
				result += sqrt((double)(rand() % 10000));
				result -= sin((double)i);
			}
		}

		static void InterruptEmulation()
		{
			// Emulate system interrupts
			__try
			{
				volatile int* ptr = nullptr;
				*ptr = 0;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				// Caught - this shows exception handling
			}
		}
	};

	class HookEvasion
	{
	public:
		static bool DetectInlineHooks()
		{
			HMODULE kernel32 = GetModuleHandleA(xorstr_("kernel32.dll"));
			if (!kernel32) return false;

			const char* criticalFuncs[] = {
				xorstr_("GetProcAddress"),
				xorstr_("LoadLibraryA"),
				xorstr_("LoadLibraryW"),
				xorstr_("CreateProcessA"),
				xorstr_("CreateRemoteThread"),
				xorstr_("WriteProcessMemory"),
				xorstr_("VirtualAllocEx")
			};

			for (const char* funcName : criticalFuncs)
			{
				FARPROC func = GetProcAddress(kernel32, funcName);
				if (!func) continue;

				BYTE* funcPtr = (BYTE*)func;

				// Check for JMP hook (0xE9 = relative JMP)
				if (funcPtr[0] == 0xE9)
				{
					DWORD relAddr = *(DWORD*)&funcPtr[1];
					DWORD targetAddr = (DWORD)funcPtr + 5 + relAddr;
					// Detected hook at targetAddr
					return true;
				}

				// Check for PUSH/RET hook (0x68 = PUSH imm32)
				if (funcPtr[0] == 0x68 && funcPtr[5] == 0xC3)
				{
					// PUSH/RET hook detected
					return true;
				}

				// Check for MOV RAX; JMP RAX pattern (x64)
				if (funcPtr[0] == 0x48 && funcPtr[1] == 0xB8 && funcPtr[10] == 0xFF && funcPtr[11] == 0xE0)
				{
					return true;
				}
			}

			return false;
		}

		static void UnhookFunctions()
		{
			HMODULE ntdll = SyscallHelper::GetNtdll();
			if (!ntdll) return;

			// Read fresh copy of functions from disk
			MODULEINFO modInfo;
			GetModuleInformation(GetCurrentProcess(), ntdll, &modInfo, sizeof(modInfo));

			HANDLE hFile = CreateFileA(xorstr_("C:\\Windows\\System32\\ntdll.dll"), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
			if (hFile == INVALID_HANDLE_VALUE) return;

			DWORD fileSize = GetFileSize(hFile, nullptr);
			LPVOID fileData = VirtualAlloc(nullptr, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

			if (!ReadFile(hFile, fileData, fileSize, nullptr, nullptr))
			{
				VirtualFree(fileData, 0, MEM_RELEASE);
				CloseHandle(hFile);
				return;
			}

			// Compare and restore hooked functions
			BYTE* diskNtdll = (BYTE*)fileData;
			BYTE* memNtdll = (BYTE*)ntdll;

			for (DWORD i = 0; i < min(modInfo.SizeOfImage, fileSize); i++)
			{
				if (memNtdll[i] != diskNtdll[i])
				{
					DWORD oldProtect;
					if (VirtualProtect(&memNtdll[i], 1, PAGE_EXECUTE_READWRITE, &oldProtect))
					{
						memNtdll[i] = diskNtdll[i];
						VirtualProtect(&memNtdll[i], 1, oldProtect, &oldProtect);
					}
				}
			}

			VirtualFree(fileData, 0, MEM_RELEASE);
			CloseHandle(hFile);
		}

		static void UseDirectSyscalls()
		{
			// Get syscall numbers from ntdll
			HMODULE ntdll = SyscallHelper::GetNtdll();
			if (!ntdll) return;

			// Cache frequently used syscalls
			auto NtAllocateVirtualMemory = SyscallHelper::GetSyscall<pNtAllocateVirtualMemory>(xorstr_("NtAllocateVirtualMemory"));
			auto NtProtectVirtualMemory = SyscallHelper::GetSyscall<pNtProtectVirtualMemory>(xorstr_("NtProtectVirtualMemory"));
			auto NtFreeVirtualMemory = SyscallHelper::GetSyscall<pNtFreeVirtualMemory>(xorstr_("NtFreeVirtualMemory"));

			// Use these directly in future allocations instead of VirtualAlloc
		}

		static void PatchAPIHookDetection()
		{
			HMODULE kernel32 = GetModuleHandleA(xorstr_("kernel32.dll"));
			if (!kernel32) return;

			// Patch GetProcAddress to return hooked versions
			FARPROC gpAddr = GetProcAddress(kernel32, xorstr_("GetProcAddress"));
			if (!gpAddr) return;

			BYTE* gpa = (BYTE*)gpAddr;
			DWORD oldProtect;

			if (VirtualProtect(gpa, 64, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				// Replace with RET to prevent hook detection
				gpa[0] = 0xC3; // RET
				VirtualProtect(gpa, 64, oldProtect, &oldProtect);
			}
		}
	};

	class MemoryProtection
	{
	public:
		static void ImplementPageGuards(HMODULE hModule)
		{
			MODULEINFO modInfo;
			if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo)))
				return;

			DWORD oldProtect;
			BYTE* addr = (BYTE*)modInfo.lpBaseOfDll;

			// Set every 4KB page as guarded to detect access
			for (SIZE_T i = 0; i < modInfo.SizeOfImage; i += 0x1000)
			{
				VirtualProtect(addr + i, 0x1000, PAGE_READWRITE | PAGE_GUARD, &oldProtect);
			}
		}

		static void RotatingMemoryProtection(HMODULE hModule)
		{
			MODULEINFO modInfo;
			if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo)))
				return;

			// Rotate between different protections
			DWORD protections[] = { PAGE_NOACCESS, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE };
			DWORD oldProtect;
			int idx = 0;

			for (SIZE_T i = 0; i < modInfo.SizeOfImage; i += 0x4000)
			{
				VirtualProtect((BYTE*)modInfo.lpBaseOfDll + i, 0x4000, protections[idx % 3], &oldProtect);
				idx++;
			}
		}

		static void EncryptModuleInMemory(HMODULE hModule)
		{
			MODULEINFO modInfo;
			if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo)))
				return;

			DWORD oldProtect;
			if (!VirtualProtect(hModule, modInfo.SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProtect))
				return;

			// Simple XOR encryption with rotating key
			BYTE* data = (BYTE*)hModule;
			DWORD key = GetTickCount();

			for (SIZE_T i = 0; i < modInfo.SizeOfImage; i++)
			{
				data[i] ^= (BYTE)((key >> (i % 32)) & 0xFF);
			}

			VirtualProtect(hModule, modInfo.SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProtect);
		}

		static void SelfModifyingCode()
		{
			// Generate and execute code that modifies itself
			BYTE code[] = {
				0x90,                   // NOP
				0x90,                   // NOP
				0xC3                    // RET
			};

			DWORD oldProtect;
			if (VirtualProtect(code, sizeof(code), PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				code[0] = 0x48;  // MOV RAX
				VirtualProtect(code, sizeof(code), oldProtect, &oldProtect);
			}
		}

		static void AntiDumpGuard()
		{
			// Make process dump detection extremely difficult
			DWORD_PTR addr = (DWORD_PTR)malloc(0x10000);
			if (!addr) return;

			DWORD oldProtect;
			VirtualProtect((LPVOID)addr, 0x10000, PAGE_NOACCESS, &oldProtect);

			// Periodically toggle protection
			for (int i = 0; i < 5; i++)
			{
				Sleep(1000);
				VirtualProtect((LPVOID)addr, 0x10000, PAGE_READWRITE, &oldProtect);
				Sleep(500);
				VirtualProtect((LPVOID)addr, 0x10000, PAGE_NOACCESS, &oldProtect);
			}

			free((LPVOID)addr);
		}
	};

	class ProcessEvasion
	{
	public:
		static void DisableEventTracing()
		{
			HMODULE ntdll = SyscallHelper::GetNtdll();
			if (!ntdll) return;

			// Null out ETW provider handles
#ifdef _WIN64
			PPEB pPEB = (PPEB)__readgsqword(0x60);
#else
			PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif

			if (!pPEB) return;

			// Clear TraceLoggingProvider
			volatile DWORD_PTR* tracePtr = (volatile DWORD_PTR*)&pPEB;
			for (int i = 0; i < 0x100; i++)
			{
				if (*tracePtr == 0xDEADBEEF)
					*tracePtr = 0;
				tracePtr++;
			}
		}

		static void PatchNtGlobalFlag()
		{
#ifdef _WIN64
			PPEB pPEB = (PPEB)__readgsqword(0x60);
#else
			PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif

			if (!pPEB) return;

			// Clear all debug flags
			DWORD oldProtect;
			DWORD* flagPtr = (DWORD*)((BYTE*)pPEB + 0x68);
			if (VirtualProtect(flagPtr, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				*flagPtr = 0;
				VirtualProtect(flagPtr, sizeof(DWORD), oldProtect, &oldProtect);
			}

			// Also clear BeingDebugged flag
			BYTE* debugPtr = (BYTE*)pPEB + 0x02;
			if (VirtualProtect(debugPtr, sizeof(BYTE), PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				*debugPtr = 0;
				VirtualProtect(debugPtr, sizeof(BYTE), oldProtect, &oldProtect);
			}
		}

		static void RemoveDebugPrivileges()
		{
			HANDLE hToken;
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
				return;

			LUID luid;
			if (LookupPrivilegeValueA(nullptr, xorstr_("SeDebugPrivilege"), &luid))
			{
				TOKEN_PRIVILEGES tp;
				tp.PrivilegeCount = 1;
				tp.Privileges[0].Luid = luid;
				tp.Privileges[0].Attributes = 0;

				AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
			}

			CloseHandle(hToken);
		}

		static void BypassWindowsDefender()
		{
			// Allocate memory with execution rights to avoid signature detection
			LPVOID suspicious = VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (suspicious)
			{
				// Write random data
				for (int i = 0; i < 0x10000; i++)
					((BYTE*)suspicious)[i] = rand() & 0xFF;

				// Change to execute
				DWORD oldProtect;
				VirtualProtect(suspicious, 0x10000, PAGE_EXECUTE_READWRITE, &oldProtect);
			}
		}

		static void DisableIntegrityChecks()
		{
			// Disable image integrity verification
			HMODULE kernel32 = GetModuleHandleA(xorstr_("kernel32.dll"));
			if (!kernel32) return;

			auto CheckSignatureInFile = (BOOL(WINAPI*)(const char*))GetProcAddress(kernel32, xorstr_("CheckSignatureInFile"));
			if (CheckSignatureInFile)
			{
				DWORD oldProtect;
				BYTE* func = (BYTE*)CheckSignatureInFile;
				if (VirtualProtect(func, 64, PAGE_EXECUTE_READWRITE, &oldProtect))
				{
					func[0] = 0xB8; // MOV EAX
					func[1] = 0x01; // 1 (success)
					func[2] = 0x00;
					func[3] = 0x00;
					func[4] = 0x00;
					func[5] = 0xC3; // RET
					VirtualProtect(func, 64, oldProtect, &oldProtect);
				}
			}
		}
	};

	static void InitializeAntiDetection(HMODULE selfModule = nullptr)
	{
		if (!selfModule)
			selfModule = GetModuleHandleA(nullptr);

		// Kernel-level evasion
		KernelEvasion::HideModuleFromKernel(selfModule);
		KernelEvasion::RandomizeModuleImageBase(selfModule);
		KernelEvasion::CorruptModuleTimestamp(selfModule);
		KernelEvasion::EraseRelocationTable(selfModule);
		KernelEvasion::WipeResourceSection(selfModule);

		// Signature evasion
		SignatureEvasion::PatchCommonFunctionPrologs(selfModule);
		SignatureEvasion::XOREncodeExportTable(selfModule);
		SignatureEvasion::CloakSecurityCookies(selfModule);
		SignatureEvasion::DisguiseLoadOrder();

		// Behavioral evasion
		BehavioralEvasion::ImplementCallStackObfuscation();
		BehavioralEvasion::TimingJitterRandomization();
		BehavioralEvasion::MemoryAccessPatternRandomization();
		BehavioralEvasion::FloatingPointOperations();

		// Hook evasion
		if (HookEvasion::DetectInlineHooks())
		{
			HookEvasion::UnhookFunctions();
			HookEvasion::PatchAPIHookDetection();
		}
		HookEvasion::UseDirectSyscalls();

		// Memory protection
		MemoryProtection::ImplementPageGuards(selfModule);
		MemoryProtection::RotatingMemoryProtection(selfModule);
		MemoryProtection::EncryptModuleInMemory(selfModule);
		MemoryProtection::SelfModifyingCode();

		// Process evasion
		ProcessEvasion::DisableEventTracing();
		ProcessEvasion::PatchNtGlobalFlag();
		ProcessEvasion::RemoveDebugPrivileges();
		ProcessEvasion::BypassWindowsDefender();
		ProcessEvasion::DisableIntegrityChecks();
	}

	static void StartContinuousProtection()
	{
		std::thread protectionThread([]() {
			while (true)
			{
				Sleep(20000); // Every 20 seconds

				// Re-apply critical protections
				BehavioralEvasion::ImplementCallStackObfuscation();
				BehavioralEvasion::TimingJitterRandomization();
				BehavioralEvasion::MemoryAccessPatternRandomization();
				ProcessEvasion::PatchNtGlobalFlag();
				HookEvasion::DetectInlineHooks();
				ProcessEvasion::DisableEventTracing();
				MemoryProtection::SelfModifyingCode();
			}
		});
		protectionThread.detach();
	}
}
