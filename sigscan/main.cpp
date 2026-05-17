#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <string>
#include <wchar.h>
#include <string.h>
#include <cmath>
#pragma comment(lib, "psapi.lib")

static const uintptr_t OFF_PAWN_IS_ALIVE = 0x914;
static const uintptr_t OFF_PAWN_HEALTH   = 0x918;
static const uintptr_t OFF_PAWN_ARMOR    = 0x91C;
static const uintptr_t OFF_TEAM_NUM      = 0x3BF;
static const uintptr_t OFF_PAWN_HANDLE   = 0x90C;
static const uintptr_t OFF_SCENE_NODE    = 0x330;
static const uintptr_t OFF_ABS_ORIGIN    = 0xC8; 
static const uintptr_t OFF_VEC_ORIGIN    = 0x80;

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

            uintptr_t rip_correct = addr + i + disp_offset + 4;

            uintptr_t global = rip_correct + disp;
            results.push_back({ addr + i, global });
        }
    }
    return results;
}
std::vector<SigMatch> scan_local_player_controller_self(HANDLE hProcess, uintptr_t base, SIZE_T size) {
    return scan_signature(hProcess, base, size,
        { 0x4C, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,
          0x33, 0xD2, 0x4D, 0x8B, 0x04, 0xC0, 0x4D, 0x85, 0xC0, 0x74,
          0x00, 0x45, 0x8B, 0x80, 0x00, 0x00, 0x00, 0x00, 0x41, 0x83, 0xF8 },
        { 3, 4, 5, 6, 17, 21, 22, 23, 24 },

        7, 3);
}

std::vector<SigMatch> scan_local_player_controller(HANDLE hProcess, uintptr_t base, SIZE_T size) {
    return scan_signature(hProcess, base, size,
        { 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x41, 0x89, 0xBE },
        { 3, 4, 5, 6 },

        7, 3);

}

std::vector<SigMatch> scan_viewmatrix_self(HANDLE hProcess, uintptr_t base, SIZE_T size) {
    return scan_signature(hProcess, base, size,
        { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
          0x48, 0x63, 0xC1, 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
          0x48, 0xC1, 0xE0, 0x06, 0x48, 0x03, 0xC1, 0xC3 },
        { 0, 1, 2, 3, 4, 5, 6, 7, 14, 15, 16, 17 },

        18, 14);
}

std::vector<SigMatch> scan_viewmatrix(HANDLE hProcess, uintptr_t base, SIZE_T size) {
    return scan_signature(hProcess, base, size,
        { 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x48, 0xC1, 0xE0, 0x06 },
        { 3, 4, 5, 6 },

        7, 3);

}

std::vector<SigMatch> scan_entity_list_self(HANDLE hProcess, uintptr_t base, SIZE_T size) {
  
    auto results = scan_signature(hProcess, base, size,
        { 0x48, 0x83, 0xEC, 0x00, 0x8B, 0x51, 0x00, 0x45, 0x33, 0xD2, 0x83, 0xFA, 0x00, 0x74, 0x00,
          0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC9, 0x74, 0x00,
          0x83, 0xFA, 0x00, 0x74, 0x00, 0x8B, 0xC2, 0x25, 0x00, 0x00, 0x00, 0x00,
          0x44, 0x8B, 0xC0, 0x48, 0xC1, 0xE8, 0x00, 0x4C, 0x8B, 0x0C, 0xC1,
          0x4D, 0x85, 0xC9, 0x74, 0x00, 0x41, 0x81, 0xE0, 0x00, 0x00, 0x00, 0x00,
          0x49, 0x6B, 0xC0, 0x00, 0x49, 0x03, 0xC1, 0x74, 0x00, 0x39, 0x50, 0x00,
          0x49, 0x0F, 0x45, 0xC2, 0xEB, 0x00, 0x49, 0x8B, 0xC2, 0x48, 0x85, 0xC0,
          0x74, 0x00, 0x48, 0x8B, 0x08, 0xEB, 0x00, 0x49, 0x8B, 0xCA },
        { 3, 6, 12, 14, 19, 20, 21, 22, 25, 28, 30, 37, 38, 39, 40, 45, 48, 51, 54, 57, 59, 65, 67, 70 },
        23, 19);
    if (!results.empty()) return results;

  
    results = scan_signature(hProcess, base, size,
        { 0x0F, 0x8E, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00,
          0x4C, 0x89, 0x74, 0x24, 0x00, 0x4C, 0x8B, 0xF7, 0x0F, 0x1F, 0x00,
          0x48, 0x8B, 0x86, 0x00, 0x00, 0x00, 0x00, 0x41, 0x8B, 0x0C, 0x06,
          0x83, 0xF9, 0x00, 0x74, 0x00, 0x4D, 0x85, 0xC9, 0x74, 0x00 },
        { 2, 3, 4, 5, 9, 10, 11, 12, 17, 27, 28, 29, 30, 35, 37, 41 },

        12, 9);
    if (!results.empty()) return results;

  
    return scan_signature(hProcess, base, size,
        { 0x4C, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00,
          0x4D, 0x85, 0xC9, 0x74, 0x00, 0x41, 0x83, 0xF8, 0x00, 0x74, 0x00,
          0x41, 0x8B, 0xC8, 0x81, 0xE1, 0x00, 0x00, 0x00, 0x00,
          0x8B, 0xC1, 0xC1, 0xE8, 0x00, 0x4D, 0x8B, 0x14, 0xC1 },
        { 3, 4, 5, 6, 11, 14, 16, 23, 24, 25, 26, 31 },

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
std::vector<SigMatch> scan_entity_list_anchor(HANDLE hProcess, uintptr_t client_base, SIZE_T client_size, uintptr_t controller_instr_addr) {
    std::vector<SigMatch> results;
    if (!controller_instr_addr) return results;

    std::vector<BYTE> bytes(7);
  
  
    for (int delta = 1; delta <= 100; delta++) {
        uintptr_t try_addr = controller_instr_addr + delta;
        if (!ReadProcessMemory(hProcess, (LPCVOID)try_addr, bytes.data(), 7, nullptr))
            break;

      
        if ((bytes[0] == 0x4C || bytes[0] == 0x48) && bytes[1] == 0x8B && bytes[2] == 0x0D) {
            int32_t disp = *(int32_t*)(bytes.data() + 3);
            uintptr_t global = try_addr + 7 + disp;

          
            if (global < client_base + 0x1900000 || global > client_base + 0x2700000)
                continue;

          
            uintptr_t global_value = 0;
            if (!read(hProcess, global, global_value) || global_value < 0x10000)
                continue;

          
            uintptr_t chunk_base = 0;
            read(hProcess, global_value + 0x10, chunk_base);

            std::cout << "  Candidate delta=" << std::dec << delta
                      << " Global: " << std::hex << global << " (RVA: " << (global - client_base) << ")"
                      << " Value: " << global_value;
            if (chunk_base > 0x10000) {
                std::cout << " Chunk[0]: " << chunk_base << " ✅" << std::endl;
                results.push_back({ try_addr, global });
            } else {
                std::cout << " Chunk[0]: " << chunk_base << " ❌" << std::endl;
            }
        }
    }
    return results;
}

void validate_position_chain(HANDLE hProcess, uintptr_t ent38, uintptr_t client_base, SIZE_T client_size, uintptr_t ent88) {
    std::cout << "\n=== Position Chain Validation ===" << std::endl;
    
  
    struct EntityCandidate { uintptr_t addr; const char* name; };
    EntityCandidate candidates[] = { {ent88, "ent88"}, {ent38, "ent38"} };
    
    uintptr_t scene_node = 0;
    std::string sn_source;
    int sn_offset_found = -1;
    
  
    for (auto& cand : candidates) {
        if (!cand.addr) continue;
        std::cout << "[+] " << cand.name << ": " << std::hex << cand.addr << std::endl;
        
        for (int off = 0x200; off <= 0x400; off += 8) {
            uintptr_t ptr = 0;
            if (read(hProcess, cand.addr + off, ptr) && ptr > 0x100000000ULL && ptr < 0x7fff00000000ULL) {
              
                if (ptr >= client_base && ptr < client_base + client_size) continue;
                std::cout << "  [?] " << cand.name << "+0x" << std::hex << off << " = 0x" << ptr << " ✅ HEAP" << std::endl;
                scene_node = ptr;
                sn_source = cand.name;
                sn_offset_found = off;
                goto found_scene;
            }
        }
    }

found_scene:
    if (!scene_node) {
        std::cout << "[-] No valid scene node pointer found" << std::endl;
        return;
    }
    
    if (!scene_node) {
        std::cout << "[-] No valid scene node pointer found near ent38+0x330" << std::endl;
        return;
    }
    
    std::cout << "[+] Scene node candidate: 0x" << std::hex << scene_node << " (offset 0x" << sn_offset_found << ")" << std::endl;
    
  
    std::cout << "  [scanning sceneNode for position Vec3...]" << std::endl;
    for (int off = 0x80; off <= 0x120; off += 4) {
        float pos[3] = {0};
        if (read(hProcess, scene_node + off, pos)) {
            bool nan = (pos[0] != pos[0] || pos[1] != pos[1] || pos[2] != pos[2]);
            if (nan) continue;
            bool huge = (pos[0] < -100000 || pos[0] > 100000 ||
                        pos[1] < -100000 || pos[1] > 100000 ||
                        pos[2] < -100000 || pos[2] > 100000);
            if (huge) continue;
            bool all_zero = (pos[0] == 0 && pos[1] == 0 && pos[2] == 0);
            
            std::cout << "  sceneNode+0x" << std::hex << off << " = (" 
                      << std::fixed << std::setprecision(1)
                      << pos[0] << ", " << pos[1] << ", " << pos[2] << ")";
            if (!all_zero && pos[2] > -1000 && pos[2] < 1000) {
                std::cout << " ✅ NON-ZERO, MAP RANGE";
            } else if (all_zero) {
                std::cout << " (zero)";
            }
            std::cout << std::endl;
        }
    }
    
  
    std::cout << "  [scanning ent38 for position Vec3...]" << std::endl;
    for (int off = 0x100; off <= 0x800; off += 4) {
        float pos[3] = {0};
        if (read(hProcess, ent38 + off, pos)) {
            bool nan = (pos[0] != pos[0] || pos[1] != pos[1] || pos[2] != pos[2]);
            if (nan) continue;
            bool huge = (pos[0] < -100000 || pos[0] > 100000 ||
                        pos[1] < -100000 || pos[1] > 100000 ||
                        pos[2] < -100000 || pos[2] > 100000);
            if (huge) continue;
            bool all_zero = (pos[0] == 0 && pos[1] == 0 && pos[2] == 0);
            if (!all_zero && pos[2] > -1000 && pos[2] < 1000) {
                std::cout << "  ent38+0x" << std::hex << off << " = (" 
                          << std::fixed << std::setprecision(1)
                          << pos[0] << ", " << pos[1] << ", " << pos[2] << ") ✅ NON-ZERO" << std::endl;
            }
        }
    }
}

void resolve_pawn_position(HANDLE hProcess, uintptr_t controller, uintptr_t entity_list_value,
                           uintptr_t client_base, SIZE_T client_size) {
    // cs2-dumper entity list needs +0x10 to reach chunk array
    uintptr_t chunkArrayBase = entity_list_value + 0x10;
    std::cout << "\n=== Position Chain — Brute Force Entity Scan ===" << std::endl;
    std::cout << "[+] Entity list base: " << std::hex << entity_list_value << " chunk array: " << chunkArrayBase << std::endl;
    
  
    int max_chunk = 0;
    for (int c = 0; c < 64; c++) {
        uintptr_t cb = 0;
        read(hProcess, chunkArrayBase + (c * 8), cb);
        if (cb) max_chunk = c;
    }
    std::cout << "[+] Allocated chunks: 0-" << std::dec << max_chunk << std::endl;
    
    int entities_scanned = 0;
    int scene_nodes_found = 0;
    
    for (int c = 0; c <= max_chunk && c < 64; c++) {
        uintptr_t chunk_base = 0;
        if (!read(hProcess, chunkArrayBase + (c * 8), chunk_base)) continue;
        if (!chunk_base) continue;
        
        for (int e = 0; e < 512; e++) {
            uintptr_t slot = chunk_base + (e * 0x70);
            uintptr_t entity_ptr = 0;
            read(hProcess, slot + 8, entity_ptr);
            if (!entity_ptr) continue;
            
          
            if (entity_ptr < 0x100000000ULL || entity_ptr >= 0x7fff00000000ULL) continue;
            
            entities_scanned++;
            
          
            uintptr_t scene_node = 0;
            read(hProcess, entity_ptr + 0x330, scene_node);
            if (scene_node < 0x100000000ULL || scene_node >= 0x7fff00000000ULL) continue;
            
          
            float pos[3] = {0};
            if (!read(hProcess, scene_node + 0xC8, pos)) continue;
            bool nan = (pos[0] != pos[0] || pos[1] != pos[1] || pos[2] != pos[2]);
            if (nan) continue;
            
            scene_nodes_found++;
            if (scene_nodes_found <= 20) {
                std::cout << "  [" << std::dec << c << "," << e << "] entity=" << std::hex << entity_ptr
                          << " sceneNode=" << scene_node
                          << " pos=(" << std::fixed << std::setprecision(1)
                          << pos[0] << "," << pos[1] << "," << pos[2] << ")" << std::endl;
            }
            
            if (scene_nodes_found >= 20) break;
        }
        if (scene_nodes_found >= 20) break;
    }
    
    std::cout << "[+] Scanned " << std::dec << entities_scanned << " entities, found " << scene_nodes_found << " with scene nodes" << std::endl;

  
    std::cout << "\n=== m_hPlayerPawn Validation ===" << std::endl;
    std::cout << "[+] Controller: " << std::hex << controller << std::endl;
    int hpn_offset_found = -1;
    for (int off = 0x8F0; off <= 0x920; off += 4) {
        uint32_t h = 0;
        if (!read(hProcess, controller + off, h)) continue;
        uint32_t idx = h & 0x7FFF;
        if (idx > 0 && idx < (max_chunk + 1) * 512 && idx != 0x7FFF) {
          
            int ci = idx >> 9, ei = idx & 0x1FF;
            uintptr_t cb = 0;
            read(hProcess, chunkArrayBase + (ci * 8), cb);
            if (!cb) continue;
            uintptr_t ep = 0;
            read(hProcess, cb + (ei * 0x70) + 8, ep);
            if (ep > 0x100000000ULL && ep < 0x7fff00000000ULL) {
                std::cout << "  [found] controller+0x" << std::hex << off << " = handle 0x" << h
                          << " idx=" << std::dec << idx << " -> entity " << std::hex << ep << " ✅ RESOLVED" << std::endl;
                hpn_offset_found = off;
                break;
            }
        }
    }
    if (hpn_offset_found < 0) {
        std::cout << "[-] m_hPlayerPawn not found in scan range 0x8F0-0x920" << std::endl;
    } else {
        std::cout << "[+] m_hPlayerPawn offset: 0x" << std::hex << hpn_offset_found << std::endl;
    }

  
    std::cout << "\n=== m_vecOrigin Validation ===" << std::endl;
    for (int c = 0; c <= max_chunk && c < 64; c++) {
        uintptr_t chunk_base = 0;
        if (!read(hProcess, chunkArrayBase + (c * 8), chunk_base)) continue;
        if (!chunk_base) continue;
        for (int e = 0; e < 512; e++) {
            uintptr_t slot = chunk_base + (e * 0x70);
            uintptr_t entity_ptr = 0;
            read(hProcess, slot + 8, entity_ptr);
            if (!entity_ptr || entity_ptr < 0x100000000ULL) continue;
            uintptr_t scene_node = 0;
            read(hProcess, entity_ptr + 0x330, scene_node);
            if (scene_node < 0x100000000ULL) continue;
          
            float origin[3] = {0}, absOrigin[3] = {0};
            if (!read(hProcess, scene_node + 0x80, origin)) continue;
            if (!read(hProcess, scene_node + 0xC8, absOrigin)) continue;
            bool nan = (origin[0] != origin[0] || absOrigin[0] != absOrigin[0]);
            if (nan) continue;
            std::cout << "  [" << std::dec << c << "," << e << "] m_vecOrigin(0x80)=(" << std::fixed << std::setprecision(1)
                      << origin[0] << "," << origin[1] << "," << origin[2] << ")"
                      << " | m_vecAbsOrigin(0xC8)=(" << absOrigin[0] << "," << absOrigin[1] << "," << absOrigin[2] << ")" << std::endl;
            if (e >= 5) break;
        }
        if (c >= 2) break;
    }
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
    std::cout << "\n[*] Scanning for dwLocalPlayerController (self-discovered sig)..." << std::endl;
    auto ctrl_matches_self = scan_local_player_controller_self(hProcess, client_base, client_size);
    std::cout << "[+] Self-discovered sig: " << std::dec << ctrl_matches_self.size() << " match(es)" << std::endl;
    for (size_t g = 0; g < ctrl_matches_self.size(); g++) {
        std::cout << "  Match [" << g << "] Global: " << std::hex << ctrl_matches_self[g].global_addr
                  << " Instr: " << ctrl_matches_self[g].instr_addr
                  << " RVA: " << (ctrl_matches_self[g].instr_addr - client_base) << std::endl;
    }

    std::cout << "\n[*] Scanning for dwLocalPlayerController (cs2-dumper sig)..." << std::endl;
    auto ctrl_matches = scan_local_player_controller(hProcess, client_base, client_size);
    std::cout << "[+] cs2-dumper sig: " << std::dec << ctrl_matches.size() << " match(es)" << std::endl;
    for (size_t g = 0; g < ctrl_matches.size(); g++) {
        std::cout << "  Match [" << g << "] Global: " << std::hex << ctrl_matches[g].global_addr
                  << " Instr: " << ctrl_matches[g].instr_addr
                  << " RVA: " << (ctrl_matches[g].instr_addr - client_base) << std::endl;
    }

    uintptr_t controller = 0;
    uintptr_t global_addr_ctrl = 0;
    std::string sig_source = "";

  
    for (size_t g = 0; g < ctrl_matches_self.size(); g++) {
        uintptr_t cand = 0;
        if (read(hProcess, ctrl_matches_self[g].global_addr, cand) && cand && cand > 0x10000) {
            uint8_t test = 0;
            if (read(hProcess, cand, test)) {
                global_addr_ctrl = ctrl_matches_self[g].global_addr;
                controller = cand;
                sig_source = "self-discovered";
                std::cout << "[+] Using self-discovered sig [" << g << "] Global: " << std::hex << global_addr_ctrl
                          << " Instr: " << ctrl_matches_self[g].instr_addr << std::endl;
                break;
            }
        }
    }

  
    if (!controller) {
        for (size_t g = 0; g < ctrl_matches.size(); g++) {
            uintptr_t cand = 0;
            if (read(hProcess, ctrl_matches[g].global_addr, cand) && cand && cand > 0x10000) {
                uint8_t test = 0;
                if (read(hProcess, cand, test)) {
                    global_addr_ctrl = ctrl_matches[g].global_addr;
                    controller = cand;
                    sig_source = "cs2-dumper";
                    std::cout << "[+] Using cs2-dumper sig [" << g << "] Global: " << std::hex << global_addr_ctrl
                              << " Instr: " << ctrl_matches[g].instr_addr << std::endl;
                    break;
                }
            }
        }
    }

    if (!controller) {
        std::cerr << "[-] No valid controller found!" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }
    std::cout << "[+] Controller (from " << sig_source << "): " << std::hex << controller << std::endl;

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

  
    uintptr_t ent88 = 0, ent38 = 0;
    read(hProcess, controller + 0x88, ent88);
    if (ent88) read(hProcess, ent88 + 0x20, ent38);
    if (!ent38) { read(hProcess, controller + 0x38, ent38); }
    
    if (ent38) {
        std::cout << "[+] ent88: " << std::hex << ent88 << " | ent38: " << ent38 << std::endl;
        validate_position_chain(hProcess, ent38, client_base, client_size, ent88);
    } else {
        std::cout << "[-] Could not resolve ent38" << std::endl;
    }

    std::cout << "\n[*] Scanning for dwViewMatrix (self-discovered sig)..." << std::endl;
    auto vm_matches_self = scan_viewmatrix_self(hProcess, client_base, client_size);
    std::cout << "[+] Self-discovered sig: " << std::dec << vm_matches_self.size() << " match(es)" << std::endl;
    for (size_t g = 0; g < vm_matches_self.size(); g++) {
        std::cout << "  Match [" << g << "] Global: " << std::hex << vm_matches_self[g].global_addr
                  << " Instr: " << vm_matches_self[g].instr_addr
                  << " RVA: " << (vm_matches_self[g].instr_addr - client_base) << std::endl;
    }

    std::cout << "\n[*] Scanning for dwViewMatrix (cs2-dumper sig)..." << std::endl;
    auto vm_matches = scan_viewmatrix(hProcess, client_base, client_size);
    std::cout << "[+] cs2-dumper sig: " << std::dec << vm_matches.size() << " match(es)" << std::endl;
    for (size_t g = 0; g < vm_matches.size(); g++) {
        std::cout << "  Match [" << g << "] Global: " << std::hex << vm_matches[g].global_addr
                  << " Instr: " << vm_matches[g].instr_addr
                  << " RVA: " << (vm_matches[g].instr_addr - client_base) << std::endl;
    }

    uintptr_t viewmatrix_addr = 0;
    std::string vm_source = "";
  
    for (size_t g = 0; g < vm_matches_self.size(); g++) {
        ViewMatrix vm;
        if (read(hProcess, vm_matches_self[g].global_addr, vm)) {
            bool valid = true;
            for (int r = 0; r < 4; r++) for (int c = 0; c < 4; c++) {
                if (vm.m[c][r] != vm.m[c][r]) { valid = false; break; }
            }
            if (valid) {
                viewmatrix_addr = vm_matches_self[g].global_addr;
                vm_source = "self-discovered";
                std::cout << "[+] Using self-discovered ViewMatrix [" << g << "]" << std::endl;
                break;
            }
        }
    }
  
    if (!viewmatrix_addr) {
        for (size_t g = 0; g < vm_matches.size(); g++) {
            ViewMatrix vm;
            if (read(hProcess, vm_matches[g].global_addr, vm)) {
                bool valid = true;
                for (int r = 0; r < 4; r++) for (int c = 0; c < 4; c++) {
                    if (vm.m[c][r] != vm.m[c][r]) { valid = false; break; }
                }
                if (valid) {
                    viewmatrix_addr = vm_matches[g].global_addr;
                    vm_source = "cs2-dumper";
                    std::cout << "[+] Using cs2-dumper ViewMatrix [" << g << "]" << std::endl;
                    break;
                }
            }
        }
    }

    if (viewmatrix_addr) {
        ViewMatrix vm;
        read(hProcess, viewmatrix_addr, vm);
        std::cout << "\n=== ViewMatrix (column-major 4x4, from " << vm_source << ") ===" << std::endl;
        for (int r = 0; r < 4; r++) {
            std::cout << "  Row " << r << ": " << std::fixed;
            for (int c = 0; c < 4; c++) {
                std::cout << vm.m[c][r] << "  ";
            }
            std::cout << std::endl;
        }
    } else {
        std::cout << "\n[WARN] Could not validate ViewMatrix" << std::endl;
    }

    std::cout << "\n[*] Scanning for dwEntityList (anchor from controller match)..." << std::endl;
    auto el_matches_anchor = scan_entity_list_anchor(hProcess, client_base, client_size, ctrl_matches_self[0].instr_addr);
    std::cout << "[+] Anchor sig: " << std::dec << el_matches_anchor.size() << " match(es)" << std::endl;
    for (size_t g = 0; g < el_matches_anchor.size(); g++) {
        std::cout << "  Match [" << g << "] Global: " << std::hex << el_matches_anchor[g].global_addr
                  << " Instr: " << el_matches_anchor[g].instr_addr
                  << " RVA: " << (el_matches_anchor[g].instr_addr - client_base) << std::endl;
    }

    std::cout << "\n[*] Scanning for dwEntityList (self-discovered sig)..." << std::endl;
    auto el_matches_self = scan_entity_list_self(hProcess, client_base, client_size);
    std::cout << "[+] Self-discovered sig: " << std::dec << el_matches_self.size() << " match(es)" << std::endl;
    for (size_t g = 0; g < el_matches_self.size(); g++) {
        std::cout << "  Match [" << g << "] Global: " << std::hex << el_matches_self[g].global_addr
                  << " Instr: " << el_matches_self[g].instr_addr
                  << " RVA: " << (el_matches_self[g].instr_addr - client_base) << std::endl;
    }

    std::cout << "\n[*] Scanning for dwEntityList (cs2-dumper sig)..." << std::endl;
    auto el_matches = scan_entity_list(hProcess, client_base, client_size);
    std::cout << "[+] cs2-dumper sig: " << std::dec << el_matches.size() << " match(es)" << std::endl;
    for (size_t g = 0; g < el_matches.size(); g++) {
        std::cout << "  Match [" << g << "] Global: " << std::hex << el_matches[g].global_addr
                  << " Instr: " << el_matches[g].instr_addr
                  << " RVA: " << (el_matches[g].instr_addr - client_base) << std::endl;
    }

    uintptr_t entity_list_addr = 0;
    uintptr_t entity_list_value = 0;
    std::string el_source = "";
  
    for (size_t g = 0; g < el_matches_anchor.size(); g++) {
        uintptr_t el_candidate = 0;
        if (read(hProcess, el_matches_anchor[g].global_addr, el_candidate) && el_candidate && el_candidate > 0x10000) {
          
            uintptr_t chunk0_via_offset = 0;
            uintptr_t chunk0_direct = 0;     
            read(hProcess, el_candidate + 0x10, chunk0_via_offset);
            read(hProcess, el_candidate, chunk0_direct);
            std::cout << "  [INFO] Anchor value: " << std::hex << el_candidate << std::endl;
            std::cout << "  [INFO] [val+0x10]=" << chunk0_via_offset << " [val+0x00]=" << chunk0_direct << std::endl;

          
          
          
            entity_list_addr = el_matches_anchor[g].global_addr;
            entity_list_value = el_candidate;
            el_source = "anchor-from-controller";
            std::cout << "[+] Using anchor EntityList [" << g << "] Value: " << std::hex << el_candidate << std::endl;
            break;
        }
    }
  
    if (!entity_list_addr) {
        for (size_t g = 0; g < el_matches_self.size(); g++) {
            uintptr_t el_candidate = 0;
            if (read(hProcess, el_matches_self[g].global_addr, el_candidate) && el_candidate && el_candidate > 0x10000) {
                entity_list_addr = el_matches_self[g].global_addr;
                entity_list_value = el_candidate;
                el_source = "self-discovered";
                std::cout << "[+] Using self-discovered EntityList [" << g << "] Value: " << std::hex << el_candidate << std::endl;
                break;
            }
        }
    }
  
    if (!entity_list_addr) {
        for (size_t g = 0; g < el_matches.size(); g++) {
            uintptr_t el_candidate = 0;
            if (read(hProcess, el_matches[g].global_addr, el_candidate) && el_candidate && el_candidate > 0x10000) {
                entity_list_addr = el_matches[g].global_addr;
                entity_list_value = el_candidate;
                el_source = "cs2-dumper";
                std::cout << "[+] Using cs2-dumper EntityList [" << g << "] Value: " << std::hex << el_candidate << std::endl;
                break;
            }
        }
    }

    if (!entity_list_addr) {
        std::cout << "\n[WARN] Could not find valid EntityList" << std::endl;
    } else {
        resolve_pawn_position(hProcess, controller, entity_list_value, client_base, client_size);
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

    // DEBUG: scan all 64 controller slots
    std::cout << "\n=== Controller Array Scan ===" << std::endl;
    uintptr_t ctrlArrayPtr = 0;
    read(hProcess, global_addr_ctrl, ctrlArrayPtr);
    std::cout << "[+] Global: " << std::hex << global_addr_ctrl << " (RVA " << (global_addr_ctrl - client_base) << ")" << std::endl;
    std::cout << "[+] Dereferenced: " << ctrlArrayPtr << std::endl;
    std::cout << "[+] Scanning 64 slots at stride 0x8..." << std::endl;

    int validCtrl = 0;
    for (int s = 0; s < 64; s++) {
        uintptr_t ctrl = 0;
        if (!read(hProcess, ctrlArrayPtr + s * 8, ctrl)) continue;
        if (!ctrl || ctrl < 0x100000000ULL || ctrl >= 0x7fff00000000ULL) continue;
        validCtrl++;

        uint32_t hp = 0;
        uint8_t alive = 0;
        uint32_t handle = 0;
        read(hProcess, ctrl + OFF_PAWN_HEALTH, hp);
        read(hProcess, ctrl + OFF_PAWN_IS_ALIVE, alive);
        read(hProcess, ctrl + 0x90C, handle);
        uint32_t idx = handle & 0x7FFF;

        std::cout << "  Slot " << std::dec << s << ": ctrl=" << std::hex << ctrl
                  << " HP=" << std::dec << hp << " alive=" << (int)alive
                  << " handle=0x" << std::hex << handle << " idx=" << std::dec << idx;

        if (idx > 0 && idx != 0x7FFF && entity_list_addr) {
            int chunk = idx >> 9;
            int entry = idx & 0x1FF;
            uintptr_t elBase = 0;
            read(hProcess, entity_list_addr, elBase);
            if (elBase) {
                uintptr_t chunkBase = 0;
                read(hProcess, elBase + 0x10 + chunk * 8, chunkBase);
                if (chunkBase) {
                    uintptr_t entity = 0;
                    read(hProcess, chunkBase + entry * 0x70 + 8, entity);
                    if (entity > 0x100000000ULL && entity < 0x7fff00000000ULL) {
                        uintptr_t sn = 0;
                        read(hProcess, entity + 0x330, sn);
                        if (sn > 0x100000000ULL && sn < 0x7fff00000000ULL) {
                            float pos[3] = {0};
                            read(hProcess, sn + 0xC8, pos);
                            bool nan = (pos[0] != pos[0] || pos[1] != pos[1] || pos[2] != pos[2]);
                            bool huge = (pos[0] < -100000 || pos[0] > 100000 || pos[1] < -100000 || pos[1] > 100000);
                            if (!nan && !huge) {
                                std::cout << " -> ent=" << std::hex << entity
                                          << " pos=(" << std::fixed << pos[0] << "," << pos[1] << "," << pos[2] << ")";
                            }
                        }
                    }
                }
            }
        }
        std::cout << std::endl;
    }
    std::cout << "[+] Valid controllers: " << std::dec << validCtrl << "/64" << std::endl;

    // DEBUG: try entity system controller list
    std::cout << "\n=== Entity System Controller List ===" << std::endl;
    if (entity_list_addr) {
        uintptr_t elBase = 0;
        read(hProcess, entity_list_addr, elBase);
        std::cout << "[+] entity_list global: " << std::hex << entity_list_addr << " (RVA " << (entity_list_addr - client_base) << ")" << std::endl;
        std::cout << "[+] elBase (deref): " << elBase << std::endl;
        if (elBase > 0x100000000ULL) {
            uintptr_t ctrlList = 0;
            read(hProcess, elBase + 0x10, ctrlList);
            std::cout << "[+] ctrlList (base+0x10): " << ctrlList << std::endl;
            if (ctrlList > 0x100000000ULL) {
                int found = 0;
                for (int i = 0; i < 64; i++) {
                    uintptr_t ctrl = 0;
                    read(hProcess, ctrlList + i * 0x78, ctrl);
                    if (ctrl > 0x100000000ULL && ctrl < 0x7fff00000000ULL) {
                        found++;
                        uint32_t hp = 0;
                        read(hProcess, ctrl + OFF_PAWN_HEALTH, hp);
                        std::cout << "  i=" << std::dec << i << ": ctrl=" << std::hex << ctrl << " HP=" << std::dec << hp << std::endl;
                    }
                }
                std::cout << "[+] Found " << std::dec << found << "/64 controllers via entity system" << std::endl;
            }
        }
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
