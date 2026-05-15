






#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include "injector_logger.h"

DWORD FindProcessId(const wchar_t* procName) {
    PROCESSENTRY32W entry = { sizeof(entry) };
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, procName) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return 0;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 3) {
        Log(L"Usage: injector.exe <process_name.exe> <full_path_to_overlay.dll>");
        return 1;
    }
    const wchar_t* procName = argv[1];
    const wchar_t* dllPath  = argv[2];

    DWORD pid = FindProcessId(procName);
    if (!pid) {
        Log(L"[-] Process not found: %s", procName);
        return 1;
    }

    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                               FALSE, pid);
    if (!hProc) {
        Log(L"[-] OpenProcess failed (%lu)", GetLastError());
        return 1;
    }

    size_t pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(hProc, nullptr, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        Log(L"[-] VirtualAllocEx failed (%lu)", GetLastError());
        CloseHandle(hProc);
        return 1;
    }
    WriteProcessMemory(hProc, remoteMem, dllPath, pathSize, nullptr);

    

    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    FARPROC loadLib = GetProcAddress(hKernel, "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLib), remoteMem, 0, nullptr);
    if (!hThread) {
        Log(L"[-] CreateRemoteThread failed (%lu)", GetLastError());
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    Log(L"[+] Injection successful.");
    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
