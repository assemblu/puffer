






#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include "injector_logger.h"



#define IDC_PROCEDIT   101
#define IDC_BROWSE     102
#define IDC_INJECT     103
#define IDC_DLLPATH    104
#define IDC_STATUS     105



static wchar_t g_processName[256] = L"cs2.exe"; 

static wchar_t g_dllPath[MAX_PATH] = L"";
static wchar_t g_status[512] = L"";



static DWORD FindProcessId(const wchar_t* procName) {
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



static bool InjectDLL(const wchar_t* procName, const wchar_t* dllPath) {
    DWORD pid = FindProcessId(procName);
    if (!pid) {
        wsprintfW(g_status, L"[-] Process not found: %s", procName);
        Log(L"[-] Process not found: %s", procName);
        return false;
    }

    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                               FALSE, pid);
    if (!hProc) {
        wsprintfW(g_status, L"[-] OpenProcess failed (error %lu)", GetLastError());
        Log(L"[-] OpenProcess failed (%lu)", GetLastError());
        return false;
    }

    size_t pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(hProc, nullptr, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        wsprintfW(g_status, L"[-] VirtualAllocEx failed (error %lu)", GetLastError());
        CloseHandle(hProc);
        return false;
    }
    if (!WriteProcessMemory(hProc, remoteMem, dllPath, pathSize, nullptr)) {
        wsprintfW(g_status, L"[-] WriteProcessMemory failed (error %lu)", GetLastError());
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    FARPROC loadLib = GetProcAddress(hKernel, "LoadLibraryW");
    if (!loadLib) {
        wsprintfW(g_status, L"[-] GetProcAddress failed (error %lu)", GetLastError());
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLib), remoteMem, 0, nullptr);
    if (!hThread) {
        wsprintfW(g_status, L"[-] CreateRemoteThread failed (error %lu)", GetLastError());
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    

    WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);

    if (exitCode == 0) {
        wsprintfW(g_status, L"[-] LoadLibrary failed inside target process.");
        Log(L"[-] LoadLibrary failed inside target process.");
        return false;
    }
    wsprintfW(g_status, L"[+] Injection successful. DLL loaded at 0x%p", (void*)(uintptr_t)exitCode);
    Log(L"[+] Injection successful. DLL loaded at 0x%p", (void*)exitCode);
    return true;
}



static void BrowseForDll(HWND hWnd) {
    OPENFILENAMEW ofn = { 0 };
    wchar_t fileName[MAX_PATH] = L"";
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFilter = L"DLL Files\0*.dll\0All Files\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameW(&ofn)) {
        wcsncpy_s(g_dllPath, fileName, _TRUNCATE);
        

        SetWindowTextW(GetDlgItem(hWnd, IDC_DLLPATH), g_dllPath);
    }
}



static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        

        CreateWindowW(L"EDIT", g_processName,
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            20, 20, 200, 24, hWnd, (HMENU)IDC_PROCEDIT, nullptr, nullptr);
        

        CreateWindowW(L"BUTTON", L"Browse DLL...",
            WS_CHILD | WS_VISIBLE,
            230, 20, 100, 24, hWnd, (HMENU)IDC_BROWSE, nullptr, nullptr);
        

        CreateWindowW(L"STATIC", L"<no DLL selected>",
            WS_CHILD | WS_VISIBLE,
            20, 60, 440, 24, hWnd, (HMENU)IDC_DLLPATH, nullptr, nullptr);
        

        CreateWindowW(L"BUTTON", L"Inject",
            WS_CHILD | WS_VISIBLE,
            350, 20, 100, 24, hWnd, (HMENU)IDC_INJECT, nullptr, nullptr);
        

        CreateWindowW(L"STATIC", L"Ready",
            WS_CHILD | WS_VISIBLE,
            20, 100, 440, 24, hWnd, (HMENU)IDC_STATUS, nullptr, nullptr);
        break;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BROWSE:
            BrowseForDll(hWnd);
            break;
        case IDC_INJECT:
            

            GetWindowTextW(GetDlgItem(hWnd, IDC_PROCEDIT), g_processName, _countof(g_processName));
            if (g_dllPath[0] == L'\0') {
                SetWindowTextW(GetDlgItem(hWnd, IDC_STATUS), L"[-] No DLL selected.");
                break;
            }
            if (InjectDLL(g_processName, g_dllPath)) {
                SetWindowTextW(GetDlgItem(hWnd, IDC_STATUS), g_status);
            } else {
                SetWindowTextW(GetDlgItem(hWnd, IDC_STATUS), g_status);
            }
            break;
        }
        break;
    case WM_CLOSE:
        DestroyWindow(hWnd);
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int) {
    const wchar_t CLASS_NAME[] = L"InjectorGUI";
    WNDCLASSW wc = { };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = CLASS_NAME;
    RegisterClassW(&wc);

    HWND hWnd = CreateWindowExW(0, CLASS_NAME, L"CS2 Overlay Injector",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 500, 180,
        nullptr, nullptr, hInst, nullptr);
    if (!hWnd) return 0;

    ShowWindow(hWnd, SW_SHOW);
    UpdateWindow(hWnd);

    MSG msg = { };
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
