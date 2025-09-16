#include "bypass.h"
#include <windows.h>
#include <cstdio>

#include "mem.h"

int Bypass(void) {

    DWORD pid = 0;
    HWND game = FindWindowA(nullptr, "Roblox");
    if (!game) {
        return 1;
    }

    if (!GetWindowThreadProcessId(game, &pid) || pid == 0) {
        return 1;
    }

    HANDLE rbx = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!rbx) {
        return 1;
    }

    HMODULE byfron = get_byfron_handle(rbx);
    if (!byfron) {
        CloseHandle(rbx);
        return 1;
    }

    if (!suspend_all(pid)) {
        CloseHandle(rbx);
        return 1;
    }

    if (!remap_section(rbx, byfron, ".byfron")) {
        resume_all(pid);
        CloseHandle(rbx);
        return 1;
    }

    if (!patch_checks(rbx, byfron)) {
        resume_all(pid);
        CloseHandle(rbx);
        return 1;
    }

    if (!restore_protection(rbx, byfron)) {
        printf("[-] failed to restore protection\n");
        resume_all(pid);
        CloseHandle(rbx);
        return 1;
    }

    if (!resume_all(pid)) {
        CloseHandle(rbx);
        return 1;
    }

    CloseHandle(rbx);
    return 0;
}