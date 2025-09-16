#include "Injection.h"
#include "iostream"
#include "thread"
#include "string"

void InjectionICHook(ICStack* regs) {
	char printbuf[500] = {};
	static HANDLE iclogfile = NULL;
	static DWORD iclogfilecur = 0;
	if (iclogfile == NULL) {
		iclogfile = CreateFileW(L"ICLog.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
		SetFilePointer(iclogfile, 0, NULL, FILE_BEGIN);
	}

	//unhooking cool functions
	static void* KiUserCallbackDispatcher = NULL;
	static void* KiUserApcDispatcher = NULL;
	if (KiUserCallbackDispatcher == NULL) { KiUserCallbackDispatcher = GetProcAddress(NTDLL, "KiUserCallbackDispatcher"); }
	if (KiUserApcDispatcher == NULL) { KiUserApcDispatcher = GetProcAddress(NTDLL, "KiUserApcDispatcher"); }
	if (regs->r10 == (DWORD64)KiUserCallbackDispatcher) {
		regs->rcx = *(DWORD64*)(regs->rsp + 0x20);
		regs->returnaddr = regs->r10 + 5;
	}
	if (regs->r10 == (DWORD64)KiUserApcDispatcher) {
		regs->rcx = *(DWORD64*)(regs->rsp + 0x18);
		regs->returnaddr = regs->r10 + 5;
	}

	//hooking exceptions
	static void* KiUserExceptionDispatcher = NULL;
	static void (*RtlRestoreContext)(PCONTEXT ContextRecord, _EXCEPTION_RECORD * ExceptionRecord) = NULL;
	if (KiUserExceptionDispatcher == NULL) { KiUserExceptionDispatcher = GetProcAddress(NTDLL, "KiUserExceptionDispatcher"); }
	if (RtlRestoreContext == NULL) { RtlRestoreContext = (void (*)(PCONTEXT ContextRecord, _EXCEPTION_RECORD * ExceptionRecord))GetProcAddress(NTDLL, "RtlRestoreContext"); }
	if (regs->r10 == (DWORD64)KiUserExceptionDispatcher) {
		PEXCEPTION_RECORD ExceptionRecord = (PEXCEPTION_RECORD)(regs->rsp + 0x4f0);
		PCONTEXT Context = (PCONTEXT)regs->rsp;


		if ((ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE)) {
			MEMORY_BASIC_INFORMATION binfo = {};
			NtQueryVirtualMemoryInline((HANDLE)0xffffffffffffffff, (void*)Context->Rip, MemoryBasicInformation, &binfo, sizeof(MEMORY_BASIC_INFORMATION), NULL);
			NtProtectVirtualMemoryInline((HANDLE)0xffffffffffffffff, &binfo.BaseAddress, &binfo.RegionSize, PAGE_EXECUTE_READ, NULL);
			RtlRestoreContext(Context, ExceptionRecord);
		}

	}


	//memory hider
	if (((regs->r10 > (ULONG_PTR)injection_vars.byfron.lpBaseOfDll) && (regs->r10 < (ULONG_PTR)injection_vars.byfron.lpBaseOfDll + injection_vars.byfron.SizeOfImage))) {
		MEMORY_BASIC_INFORMATION checkinfo = {};
		DWORD stat = NtQueryVirtualMemoryInline((HANDLE)0xffffffffffffffff, (void*)regs->rsp, MemoryBasicInformation, &checkinfo, sizeof(MEMORY_BASIC_INFORMATION), NULL);
		if ((checkinfo.Type != 0) && (stat == 0)) {
			ULONG_PTR cur = regs->rsp;
			ULONG_PTR end = (ULONG_PTR)checkinfo.BaseAddress + checkinfo.RegionSize - 0x100;
			while (cur < end) {
				PMEMORY_BASIC_INFORMATION checkbi = (PMEMORY_BASIC_INFORMATION)cur;
				DWORD checkcur = 0;
				while (checkcur < injection_vars.InjectionHiddenMemoryC) {
					PMEMORY_BASIC_INFORMATION compare = &injection_vars.InjectionHiddenMemory[checkcur];
					if ((checkbi->BaseAddress == compare->BaseAddress) && (checkbi->Protect == compare->Protect) && (checkbi->AllocationProtect == compare->AllocationProtect)) {
						checkbi->Protect = 1;
						checkbi->AllocationProtect = 1;
						checkbi->BaseAddress = (PVOID)0; //who wrote this byfron's rwx scanner ?
					}
					checkcur++;
				}
				cur++;
			}
		}
	}

	regs->returnaddr = (DWORD64)injection_vars.ICAddr;
	return;
}

int InjectionDllCaller() {
	DeleteFileA("msvcp140.dll");
	DeleteFileA("msvcp140_1.dll");
	DeleteFileA("msvcp140_2.dll");
	DeleteFileA("vcruntime140.dll");
	DeleteFileA("vcruntime140_1.dll");

	LoadLibraryA("msvcp140.dll");
	LoadLibraryA("vcruntime140.dll");
	LoadLibraryA("vcruntime140_1.dll");

	uintptr_t sectionBase = (uintptr_t)GetModuleHandleA("winsta.dll") + 0x328;
	uintptr_t allocatedMemory = *(uintptr_t*)sectionBase;
	uint64_t totalSize = *(uint64_t*)(sectionBase + 0x8);

	*(int*)(sectionBase + 0x10) = 1; // ready for mapping

	do {
		Sleep(1);
	} while (*(int*)(sectionBase + 0x18) != 1);

	uintptr_t entryPoint = *(uintptr_t*)(sectionBase + 0x20);

	// SEH support
	uintptr_t dllBase = *(uintptr_t*)(sectionBase + 0x28);
	uintptr_t exceptionAddress = *(uintptr_t*)(sectionBase + 0x30);
	uintptr_t exceptionSize = *(uintptr_t*)(sectionBase + 0x38);

	if (exceptionAddress != 0 && exceptionSize != 0) {
		RtlAddFunctionTable((IMAGE_RUNTIME_FUNCTION_ENTRY*)(dllBase + exceptionAddress), exceptionSize / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), dllBase);
	}

	BOOL(*dllMain)(HMODULE, DWORD, LPVOID) = (BOOL(*__stdcall)(HMODULE, DWORD, LPVOID))(entryPoint);

	dllMain((HMODULE)dllBase, 1, 0);
	return 0;
}


bool InjectionFindByfron(HANDLE process, PInternalVars s) {
	MODULEINFO byfron = FindModuleByNameInProcess(process, L"RobloxPlayerBeta.dll");
	if (byfron.lpBaseOfDll != 0) {
		s->byfron = byfron;
		return 1;
	}
	return 0;
}

bool InjectionBeforeAllocSelf(HANDLE process, PVOID mem, PInternalVars s) {
	ICHookerLowLevelPartSetHooker(ConvertAddrByBase(&InjectionICHook, thismoduleinfo.lpBaseOfDll, mem));
	PVOID ic = (PVOID)PFindData(ByfronICPattern, 8, (ULONG_PTR)s->byfron.lpBaseOfDll, s->byfron.SizeOfImage, process, 100000);
	if (ic == (PVOID)-1) { return 0; }
	s->ICAddr = ic;
	return 1;
}
bool InjectionAllocSelf(HANDLE process, PInternalVars s, MODULEINFO thismodinfo) {

	PVOID selfmem = VirtualAllocEx(process, NULL, thismodinfo.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (InjectionBeforeAllocSelf(process, selfmem, s) == 0) { goto err; }
	if (selfmem == NULL) { return 0; }
	if (VirtualQueryEx(process, selfmem, &s->InjectionHiddenMemory[s->InjectionHiddenMemoryC], sizeof(MEMORY_BASIC_INFORMATION)) == 0) { goto err; };
	s->InjectionHiddenMemoryC++;
	if (WriteProcessMemory(process, selfmem, thismodinfo.lpBaseOfDll, thismodinfo.SizeOfImage, NULL) == 0) { goto err; };
	s->Injector = selfmem;
	return 1;

err:
	if (selfmem != 0)
		VirtualFreeEx(process, selfmem, 0, MEM_RELEASE);
	return 0;


}

typedef void(*InitializeFunc)();
bool InjectionSetupInternalPart(HANDLE process, PInternalVars s) {
	void* addy = ConvertAddrByBase(&InjectionDllCaller, thismoduleinfo.lpBaseOfDll, s->Injector);
	return CreateTPDirectThread(process, addy);
}

bool GetThisModuleInfo() {
	HMODULE thismod = GetModuleHandleA(NULL);
	if (thismod == NULL) { return 0; }
	return GetModuleInformation(GetCurrentProcess(), thismod, &thismoduleinfo, sizeof(MODULEINFO));
}

ULONG_PTR ConvertAddrByBase(ULONG_PTR Addr, ULONG_PTR OldBase, ULONG_PTR NewBase) {
	return Addr - OldBase + NewBase;
}
void* ConvertAddrByBase(const void* Addr, const void* OldBase, const void* NewBase) {
	return (void*)((ULONG_PTR)Addr - (ULONG_PTR)OldBase + (ULONG_PTR)NewBase);
}

InternalVars injection_vars = {};
MODULEINFO thismoduleinfo = {};
