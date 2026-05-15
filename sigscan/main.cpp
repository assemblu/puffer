#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <wchar.h>
#include <string.h>
#include <cmath>
#pragma comment(lib, "psapi.lib")







static const uintptr_t OFF_PAWN_IS_ALIVE = 0x914;
static const uintptr_t OFF_PAWN_HEALTH   = 0x918;
static const uintptr_t OFF_PAWN_ARMOR    = 0x91C;
static const uintptr_t OFF_TEAM_NUM      = 0x3BF;

















DWORD find_cs2_pid() {
    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    DWORD pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "cs2.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

uintptr_t find_module_base(HANDLE hProcess, PCWSTR name) {
    HMODULE modules[1024];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(hProcess, modules, sizeof(modules), &needed, LIST_MODULES_ALL))
        return 0;

    for (DWORD i = 0; i < needed / sizeof(HMODULE); i++) {
        WCHAR path[MAX_PATH];
        if (GetModuleFileNameExW(hProcess, modules[i], path, ARRAYSIZE(path))) {
            PWSTR basename = wcsrchr(path, L'\\');
            if (basename) basename++;
            else basename = path;
            if (_wcsicmp(basename, name) == 0)
                return (uintptr_t)modules[i];
        }
    }
    return 0;
}

SIZE_T get_module_size(HANDLE hProcess, uintptr_t base) {
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    SIZE_T read = 0;

    if (!ReadProcessMemory(hProcess, (LPCVOID)base, &dos, sizeof(dos), &read))
        return 0;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    if (!ReadProcessMemory(hProcess, (LPCVOID)(base + dos.e_lfanew), &nt, sizeof(nt), &read))
        return 0;
    if (nt.Signature != IMAGE_NT_SIGNATURE)
        return 0;

    return nt.OptionalHeader.SizeOfImage;
}








struct SigMatch {
    uintptr_t instr_addr;   

    uintptr_t global_addr;  

};











std::vector<SigMatch> scan_signature(HANDLE hProcess, uintptr_t base, SIZE_T size,
                                      const std::vector<uint8_t>& pattern_bytes,
                                      const std::vector<size_t>& wildcards,
                                      size_t instr_len, size_t disp_offset) {
    std::vector<SigMatch> results;
    std::vector<BYTE> page(0x1000);

    

    std::vector<bool> is_wild(256, false);
    for (size_t w : wildcards) if (w < 256) is_wild[w] = true;

    for (uintptr_t addr = base; addr < base + size; addr += 0x1000) {
        SIZE_T read = 0;
        if (!ReadProcessMemory(hProcess, (LPCVOID)addr, page.data(), 0x1000, &read))
            continue;
        if (read < instr_len) continue;

        for (size_t i = 0; i <= read - instr_len; i++) {
            bool match = true;
            for (size_t p = 0; p < pattern_bytes.size(); p++) {
                if (is_wild[p]) continue;
                if (page[i + p] != pattern_bytes[p]) {
                    match = false;
                    break;
                }
            }
            if (!match) continue;

            

            int32_t disp = *(int32_t*)(page.data() + i + disp_offset);
            uintptr_t rip = addr + i + instr_len; 

            

            

            

            

            uintptr_t rip_correct = addr + i + 3 + 4; 

            uintptr_t global = rip_correct + disp;
            results.push_back({ addr + i, global });
        }
    }
    return results;
}










std::vector<SigMatch> scan_local_player_controller(HANDLE hProcess, uintptr_t base, SIZE_T size) {
    return scan_signature(hProcess, base, size,
        { 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x41, 0x89, 0xBE },
        { 3, 4, 5, 6 },  

        7, 3);            

}



std::vector<SigMatch> scan_viewmatrix(HANDLE hProcess, uintptr_t base, SIZE_T size) {
    return scan_signature(hProcess, base, size,
        { 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x48, 0xC1, 0xE0, 0x06 },
        { 3, 4, 5, 6 },  

        7, 3);            

}





std::vector<SigMatch> scan_entity_list(HANDLE hProcess, uintptr_t base, SIZE_T size) {
    

    

    auto results = scan_signature(hProcess, base, size,
        { 0x48, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x63, 0xB3 },
        { 3, 4, 5, 6, 11, 12, 13, 14 },
        7, 3);
    if (!results.empty()) return results;

    

    results = scan_signature(hProcess, base, size,
        { 0x48, 0x89, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00, 0xCC },
        { 3, 4, 5, 6, 9, 10, 11, 12 },
        7, 3);
    if (!results.empty()) return results;

    

    results = scan_signature(hProcess, base, size,
        { 0x48, 0x89, 0x35, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xF6 },
        { 3, 4, 5, 6 },
        7, 3);
    if (!results.empty()) return results;

    

    results = scan_signature(hProcess, base, size,
        { 0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x7C, 0x24, 0x00, 0x8B, 0xFA, 0xC1 },
        { 3, 4, 5, 6, 12 },
        7, 3);
    if (!results.empty()) return results;

    return results; 

}








template<typename T>
bool read(HANDLE hProcess, uintptr_t addr, T& out) {
    SIZE_T r = 0;
    return ReadProcessMemory(hProcess, (LPCVOID)addr, &out, sizeof(T), &r) && r == sizeof(T);
}








struct Vec3 {
    float x, y, z;
};

struct ViewMatrix {
    float m[4][4]; 

};

bool world_to_screen(const ViewMatrix& vm, const Vec3& origin, int screen_w, int screen_h, float& out_x, float& out_y) {
    float w = vm.m[3][0] * origin.x + vm.m[3][1] * origin.y + vm.m[3][2] * origin.z + vm.m[3][3];
    
    if (w < 0.1f) return false; 


    float x = vm.m[0][0] * origin.x + vm.m[0][1] * origin.y + vm.m[0][2] * origin.z + vm.m[0][3];
    float y = vm.m[1][0] * origin.x + vm.m[1][1] * origin.y + vm.m[1][2] * origin.z + vm.m[1][3];

    out_x = (screen_w / 2.0f) * (1.0f + x / w);
    out_y = (screen_h / 2.0f) * (1.0f - y / w);
    return true;
}








uint32_t handle_to_index(uint32_t handle) {
    return handle & 0x7FFF;
}








int main() {
    std::cout << "[*] Finding cs2.exe..." << std::endl;
    DWORD pid = find_cs2_pid();
    if (!pid) {
        std::cerr << "[-] cs2.exe not found!" << std::endl;
        return 1;
    }
    std::cout << "[+] cs2.exe PID: " << std::dec << pid << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] OpenProcess failed: " << GetLastError() << std::endl;
        return 1;
    }

    uintptr_t client_base = find_module_base(hProcess, L"client.dll");
    if (!client_base) {
        std::cerr << "[-] client.dll not found!" << std::endl;
        return 1;
    }
    std::cout << "[+] client.dll: " << std::hex << client_base << std::endl;

    SIZE_T client_size = get_module_size(hProcess, client_base);
    if (!client_size) {
        std::cerr << "[-] Failed to read client.dll size" << std::endl;
        return 1;
    }
    std::cout << "[+] client.dll size: " << std::hex << client_size << std::endl;

    

    

    

    std::cout << "\n[*] Scanning for dwLocalPlayerController..." << std::endl;
    auto ctrl_matches = scan_local_player_controller(hProcess, client_base, client_size);
    std::cout << "[+] Found " << std::dec << ctrl_matches.size() << " match(es)" << std::endl;

    uintptr_t controller = 0;
    uintptr_t global_addr_ctrl = 0;

    for (size_t g = 0; g < ctrl_matches.size(); g++) {
        uintptr_t cand = 0;
        if (read(hProcess, ctrl_matches[g].global_addr, cand) && cand && cand > 0x10000) {
            uint8_t test = 0;
            if (read(hProcess, cand, test)) {
                global_addr_ctrl = ctrl_matches[g].global_addr;
                controller = cand;
                std::cout << "[+] Using candidate [" << g << "] Global: " << std::hex << global_addr_ctrl 
                          << " Instr: " << ctrl_matches[g].instr_addr << std::endl;
                break;
            }
        }
    }

    if (!controller) {
        std::cerr << "[-] No valid controller found!" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }
    std::cout << "[+] Controller: " << std::hex << controller << std::endl;

    

    uint8_t alive = 0, team = 0;
    uint32_t health = 0;
    int32_t armor = 0;

    read(hProcess, controller + OFF_PAWN_IS_ALIVE, alive);
    read(hProcess, controller + OFF_PAWN_HEALTH, health);
    read(hProcess, controller + OFF_PAWN_ARMOR, armor);
    read(hProcess, controller + OFF_TEAM_NUM, team);

    std::cout << "\n=== Local Player Data ===" << std::endl;
    std::cout << "[+] m_bPawnIsAlive (0x" << std::hex << OFF_PAWN_IS_ALIVE << "): " << std::dec << (int)alive << std::endl;
    std::cout << "[+] m_iPawnHealth  (0x" << std::hex << OFF_PAWN_HEALTH << "): " << std::dec << health << std::endl;
    std::cout << "[+] m_iPawnArmor   (0x" << std::hex << OFF_PAWN_ARMOR << "): " << std::dec << armor << std::endl;
    std::cout << "[+] m_iTeamNum     (0x" << std::hex << OFF_TEAM_NUM << "): " << std::dec << (int)team << " ";
    if (team == 2) std::cout << "(CT)";
    else if (team == 3) std::cout << "(T)";
    std::cout << std::endl;

    

    

    

    std::cout << "\n[*] Scanning for dwViewMatrix..." << std::endl;
    auto vm_matches = scan_viewmatrix(hProcess, client_base, client_size);
    std::cout << "[+] Found " << std::dec << vm_matches.size() << " match(es)" << std::endl;

    uintptr_t viewmatrix_addr = 0;
    for (size_t g = 0; g < vm_matches.size(); g++) {
        std::cout << "  Match [" << g << "] Global: " << std::hex << vm_matches[g].global_addr 
                  << " Instr: " << vm_matches[g].instr_addr << std::endl;
        
        

        ViewMatrix vm;
        if (read(hProcess, vm_matches[g].global_addr, vm)) {
            

            

            bool valid = true;
            for (int r = 0; r < 4; r++) for (int c = 0; c < 4; c++) {
                if (vm.m[c][r] != vm.m[c][r]) { valid = false; break; } 

            }
            if (valid) {
                viewmatrix_addr = vm_matches[g].global_addr;
                std::cout << "[+] Using ViewMatrix candidate [" << g << "]" << std::endl;
                
                

                std::cout << "\n=== ViewMatrix (column-major 4x4) ===" << std::endl;
                for (int r = 0; r < 4; r++) {
                    std::cout << "  Row " << r << ": " << std::fixed;
                    for (int c = 0; c < 4; c++) {
                        std::cout << vm.m[c][r] << "  ";
                    }
                    std::cout << std::endl;
                }
                break;
            }
        }
    }

    if (!viewmatrix_addr) {
        std::cout << "\n[WARN] Could not validate ViewMatrix — may need manual selection" << std::endl;
    }

    

    

    

    std::cout << "\n[*] Scanning for dwEntityList..." << std::endl;
    auto el_matches = scan_entity_list(hProcess, client_base, client_size);
    std::cout << "[+] Found " << std::dec << el_matches.size() << " match(es)" << std::endl;

    uintptr_t entity_list_addr = 0;
    for (size_t g = 0; g < el_matches.size(); g++) {
        std::cout << "  Match [" << g << "] Global: " << std::hex << el_matches[g].global_addr 
                  << " Instr: " << el_matches[g].instr_addr << std::endl;
        
        uintptr_t el_candidate = 0;
        if (read(hProcess, el_matches[g].global_addr, el_candidate) && el_candidate && el_candidate > 0x10000) {
            entity_list_addr = el_matches[g].global_addr;
            std::cout << "[+] Using EntityList candidate [" << g << "] Value: " << std::hex << el_candidate << std::endl;
            break;
        }
    }

    if (!entity_list_addr) {
        std::cout << "\n[WARN] Could not find valid EntityList" << std::endl;
    }

    

    

    

    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << "[+] dwLocalPlayerController: " << std::hex << global_addr_ctrl 
              << " (RVA: " << (global_addr_ctrl - client_base) << ")" << std::endl;
    if (viewmatrix_addr) {
        std::cout << "[+] dwViewMatrix: " << std::hex << viewmatrix_addr 
                  << " (RVA: " << (viewmatrix_addr - client_base) << ")" << std::endl;
    }
    if (entity_list_addr) {
        std::cout << "[+] dwEntityList: " << std::hex << entity_list_addr 
                  << " (RVA: " << (entity_list_addr - client_base) << ")" << std::endl;
    }

    

    

    

    std::cout << "\n[*] Press Enter to start live monitoring (HP + ViewMatrix every 500ms)..." << std::endl;
    std::cin.get();

    int screen_w = 1920, screen_h = 1080; 

    std::cout << "\nMonitoring (screen: " << screen_w << "x" << screen_h << ")..." << std::endl;

    for (int ticks = 0; ticks < 200; ticks++) { 

        uintptr_t ctrl = 0;
        read(hProcess, global_addr_ctrl, ctrl);
        if (!ctrl) { std::cout << "\nController NULL" << std::endl; break; }

        uint32_t h = 0;
        uint8_t a = 0;
        read(hProcess, ctrl + OFF_PAWN_HEALTH, h);
        read(hProcess, ctrl + OFF_PAWN_IS_ALIVE, a);

        

        std::string w2s_str = "N/A";
        if (viewmatrix_addr) {
            ViewMatrix vm;
            if (read(hProcess, viewmatrix_addr, vm)) {
                Vec3 test_pos{ 0.0f, 0.0f, 0.0f }; 

                float sx = 0, sy = 0;
                if (world_to_screen(vm, test_pos, screen_w, screen_h, sx, sy)) {
                    char buf[64];
                    snprintf(buf, sizeof(buf), "(%.0f, %.0f)", sx, sy);
                    w2s_str = buf;
                }
            }
        }

        std::cout << "\r  HP: " << std::dec << h << " | Alive: " << (int)a 
                  << " | W2S(0,0,0): " << w2s_str << "   " << std::flush;
        Sleep(500);
    }

    std::cout << "\n\n[DONE]" << std::endl;
    CloseHandle(hProcess);
    return 0;
}
