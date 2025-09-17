#pragma once
#include <windows.h>
#include <string>
#include <filesystem>
#include <tlhelp32.h>
#include <psapi.h>
#include <ntstatus.h>
#include <winternl.h>
#include <map>

#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI ZwUnmapViewOfSection(HANDLE proc, PVOID base);

template <typename T>
bool read(HANDLE proc, uintptr_t addr, T* out, size_t size = sizeof(T)) {
	size_t bytes_read;
	auto res = ReadProcessMemory(proc, reinterpret_cast<PVOID>(addr), out, size, &bytes_read);
	return res && size == bytes_read;
}

template <typename T>
bool write(HANDLE proc, uintptr_t addr, T val, size_t size = sizeof(T)) {
	size_t bytes_written;
	auto res = WriteProcessMemory(proc, reinterpret_cast<LPVOID>(addr), (LPCVOID)val, size, &bytes_written);
	return res && size == bytes_written;
}

bool suspend_all(DWORD pid) {
	THREADENTRY32 te;
	te.dwSize = sizeof(THREADENTRY32);
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (!snap || snap == INVALID_HANDLE_VALUE) {
		return false;
	}
	if (Thread32First(snap, &te)) {
		do {
			if (te.th32OwnerProcessID == pid) {
				auto thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
				if (!thread) continue;
				SuspendThread(thread);
				CloseHandle(thread);
			}
		} while (Thread32Next(snap, &te));
	}
	CloseHandle(snap);
	return true;
}

bool resume_all(DWORD pid) {
	THREADENTRY32 te;
	te.dwSize = sizeof(THREADENTRY32);
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (!snap || snap == INVALID_HANDLE_VALUE) {
		return false;
	}
	if (Thread32First(snap, &te)) {
		do {
			if (te.th32OwnerProcessID == pid) {
				auto thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
				if (!thread) continue;
				ResumeThread(thread);
				CloseHandle(thread);
			}
		} while (Thread32Next(snap, &te));
	}
	CloseHandle(snap);
	return true;
}

uintptr_t byfron_section;
size_t byfron_size;

bool remap_section(HANDLE proc, HMODULE mod, std::string section_name) {
	BYTE* base = reinterpret_cast<BYTE*>(mod);

	IMAGE_DOS_HEADER dos{};
	if (!read(proc, reinterpret_cast<uintptr_t>(base), &dos)) {
		return false;
	}
	if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}

	IMAGE_NT_HEADERS nt{};
	if (!read(proc, reinterpret_cast<uintptr_t>(base + dos.e_lfanew), &nt)) {
		return false;
	}

	IMAGE_SECTION_HEADER section;
	bool a = false;
	BYTE* table = base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS);
	for (auto i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
		if (!read(
			proc,
			reinterpret_cast<uintptr_t>(table + i * sizeof(IMAGE_SECTION_HEADER)),
			&section)
			) {
			return false;
		}
		char name[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
		memcpy(name, section.Name, IMAGE_SIZEOF_SHORT_NAME);
		if (_strcmpi(name, section_name.c_str()) == 0) {
			a = true;
			break;
		}
	}

	if (!a) {
		return false;
	}

	uintptr_t addr = reinterpret_cast<uintptr_t>(base + section.VirtualAddress);
	SIZE_T size = section.Misc.VirtualSize;

	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	DWORD pagesz = sysInfo.dwPageSize;

	byfron_section = addr;
	byfron_size = size;

	std::vector<uint8_t> original_bytes(size);
	if (!read(proc, addr, original_bytes.data(), size)) {
		return false;
	}

	NTSTATUS status = ZwUnmapViewOfSection(proc, (PVOID)addr);
	if (status != STATUS_SUCCESS) {
		return false;
	}

	if (!VirtualAllocEx(proc, (PVOID)addr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) {
		return false;
	}

	if (!write(proc, addr, original_bytes.data(), size)) {
		return false;
	}

	return true;
}

HMODULE get_byfron_handle(HANDLE proc) {
	HMODULE modules[1024];
	DWORD needed;
	if (K32EnumProcessModules(proc, modules, sizeof(modules), &needed)) {
		for (unsigned int i = 0; i < (needed / sizeof(HMODULE)); i++) {
			char szModuleName[MAX_PATH];
			if (GetModuleBaseName(proc, modules[i], szModuleName, sizeof(szModuleName) / sizeof(char))) {
				if (_strcmpi(szModuleName, "RobloxPlayerBeta.dll") == 0) {
					return modules[i];
				}
			}
		}
	}
	return nullptr;
}

 namespace offsets {
	 namespace subs {
		constexpr uint32_t sub_checks[12] = {
		0x4d51fc, 0x4e0744, 0x4ec5f4,
		0x4ed1c4, 0x4edc24, 0x4ee3c4,
		0x4f6614, 0x4f7ea4, 0x4fb740,
		0x4fbd74, 0x4fc1c0, 0x512c24
		};
	}

	constexpr uint32_t general_integrity = 0x4FBD74;

	 namespace integrity {
		constexpr uint32_t whitelist_check = 0x4FD7D3;
		constexpr uint32_t console_check = 0x7428CC;
		constexpr uint32_t control_flow_guard_check = 0x27F860;
		constexpr uint32_t icebp_check = 0xCF08FF;
	}
}

bool patch_checks(HANDLE proc, HMODULE base) {
	using patch = const std::vector<uint8_t>;
	using patches = const std::map<uint32_t, patch>;

	patch sub_patch = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

	patches main_patches = {
		//{ offsets::integrity::whitelist_check, { 0xB8, 0x03, 0x00, 0x00, 0x00 } },
		{ offsets::integrity::console_check, { 0x38, 0xC0, 0x90, 0x90, 0x90 } },
		{ offsets::integrity::control_flow_guard_check, { 0xFF, 0xE0, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } },
		/*{ offsets::integrity::icebp_check, { 0xC7, 0x41, 0x68, 0xF4, 0x0F, 0xFF, 0xFF, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } },*/
	};

	for (auto& addr : offsets::subs::sub_checks) {
		auto t = reinterpret_cast<uintptr_t>(base) + addr;
		write(proc, t, sub_patch.data(), sub_patch.size());
	}

	for (auto& [addr, hex] : main_patches) {
		auto t = reinterpret_cast<uintptr_t>(base) + addr;
		write(proc, t, hex.data(), hex.size());
	}

	return true;
}

bool restore_protection(HANDLE proc, HMODULE base) {
	if (byfron_section == 0 || byfron_size == 0) {
		return false;
	}

	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	SIZE_T pageSize = sysInfo.dwPageSize;

	uintptr_t start = byfron_section & ~(static_cast<uintptr_t>(pageSize) - 1);
	uintptr_t end = (byfron_section + byfron_size + pageSize - 1) & ~(static_cast<uintptr_t>(pageSize) - 1);
	SIZE_T size = end - start;

	DWORD oldProtect = 0;
	BOOL ok = VirtualProtectEx(proc, reinterpret_cast<LPVOID>(start), size, PAGE_EXECUTE_READ, &oldProtect);
	if (!ok) {
		return false;
	}

	if (!FlushInstructionCache(proc, reinterpret_cast<LPCVOID>(start), size)) {
		return false;
	}

	return true;
}