#include "esp_config.h"
#include "logger.h"
#include <string>
#include <vector>
#include <utility>

// Minimal JSON parser for offsets.json — zero external dependencies.
// Supports only the subset of JSON needed: strings, numbers, nested objects.

// Read file as UTF-8 string directly (offsets.json is UTF-8)
static std::string ReadFile(const wchar_t* path) {
    // Convert wchar path to UTF-8 for fopen
    int len = WideCharToMultiByte(CP_UTF8, 0, path, (int)wcslen(path), nullptr, 0, nullptr, nullptr);
    if (len <= 0) {
        OverlayLog(L"[esp_config] WideCharToMultiByte failed for path");
        return "";
    }
    std::string utf8Path(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, path, (int)wcslen(path), &utf8Path[0], len, nullptr, nullptr);

    FILE* f = nullptr;
    fopen_s(&f, utf8Path.c_str(), "rb");
    if (!f) {
        OverlayLog(L"[esp_config] fopen_s failed for path");
        return "";
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    OverlayLog(L"[esp_config] File size: %ld bytes", size);

    std::string content(size, '\0');
    size_t read = fread(&content[0], 1, size, f);
    OverlayLog(L"[esp_config] fread returned %llu bytes", (unsigned long long)read);
    fclose(f);

    // Log first 8 bytes as hex
    if (read >= 4) {
        unsigned char* p = (unsigned char*)content.c_str();
        OverlayLog(L"[esp_config] First bytes: %02X %02X %02X %02X", p[0], p[1], p[2], p[3]);
    }
    return content;
}

static std::wstring _ToWide(const std::string& s) {
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (len <= 0) return L"";
    std::wstring result(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &result[0], len);
    return result;
}

class JsonValue {
public:
    enum Type { Null, String, Number, Object };
    Type type = Null;
    std::string strVal;
    int64_t numVal = 0;
    std::vector<std::pair<std::string, JsonValue>> members; // object key-value pairs

    const JsonValue* get(const std::string& key) const {
        if (type != Object) return nullptr;
        OverlayLog(L"[esp_config] GET looking for: '%S' in object with %u members", key.c_str(), (unsigned)members.size());
        for (auto& [k, v] : members) {
            OverlayLog(L"[esp_config] GET comparing: '%S' (len=%u) vs '%S' (len=%u) match=%d", k.c_str(), (unsigned)k.size(), key.c_str(), (unsigned)key.size(), k == key);
            if (k == key) return &v;
        }
        return nullptr;
    }

    void DebugDump(const std::string& label) const {
        if (type == Object) {
            OverlayLog(L"[esp_config] DEBUG %S: Object with %u members", label.c_str(), (unsigned)members.size());
            for (auto& [k, v] : members) {
                switch (v.type) {
                    case String: OverlayLog(L"[esp_config]   %S = \"%S\"", k.c_str(), v.strVal.c_str()); break;
                    case Number: OverlayLog(L"[esp_config]   %S = %lld", k.c_str(), v.numVal); break;
                    case Object: OverlayLog(L"[esp_config]   %S = Object(%u members)", k.c_str(), (unsigned)v.members.size()); break;
                    default: OverlayLog(L"[esp_config]   %S = Null", k.c_str()); break;
                }
            }
        } else {
            OverlayLog(L"[esp_config] DEBUG %S: type=%d (not Object)", label.c_str(), (int)type);
        }
    }

    std::string getString(const std::string& key, const std::string& def = "") const {
        auto* v = get(key);
        return v && v->type == String ? v->strVal : def;
    }

    int64_t getNumber(const std::string& key, int64_t def = 0) const {
        auto* v = get(key);
        if (v && v->type == Number) return v->numVal;
        // Try parsing hex string
        auto* sv = get(key);
        if (sv && sv->type == String) {
            std::string s = sv->strVal;
            if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
                return (int64_t)strtoull(s.c_str() + 2, nullptr, 16);
            }
            return strtoll(s.c_str(), nullptr, 10);
        }
        return def;
    }

    uintptr_t getHex(const std::string& key, uintptr_t def = 0) const {
        auto* v = get(key);
        if (!v) return def;
        // Direct number or hex string
        if (v->type == JsonValue::Number) return (uintptr_t)v->numVal;
        if (v->type == JsonValue::String) {
            std::string s = v->strVal;
            if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
                return (uintptr_t)strtoull(s.c_str() + 2, nullptr, 16);
            }
            return (uintptr_t)strtoull(s.c_str(), nullptr, 10);
        }
        // If the value is an object, look for common fields like "rva" or "offset"
        if (v->type == JsonValue::Object) {
            // Search for a child named "rva" or "offset"
            for (const auto& [childKey, childVal] : v->members) {
                if ((childKey == "rva" || childKey == "offset") && childVal.type == JsonValue::String) {
                    std::string s = childVal.strVal;
                    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
                        return (uintptr_t)strtoull(s.c_str() + 2, nullptr, 16);
                    }
                    return (uintptr_t)strtoull(s.c_str(), nullptr, 10);
                }
                // Also accept numeric child
                if ((childKey == "rva" || childKey == "offset") && childVal.type == JsonValue::Number) {
                    return (uintptr_t)childVal.numVal;
                }
            }
        }
        return def;
    }

    // Parse a JSON value from position pos in input. Advances pos past the value.
    static JsonValue Parse(const std::string& input, size_t& pos) {
        JsonValue result;
        // Skip whitespace
        while (pos < input.size() && (input[pos] == ' ' || input[pos] == '\t' || input[pos] == '\n' || input[pos] == '\r'))
            pos++;
        if (pos >= input.size()) return result;

        char c = input[pos];
        if (c == '"') {
            // String
            result.type = String;
            pos++; // skip opening quote
            while (pos < input.size() && input[pos] != '"') {
                if (input[pos] == '\\' && pos + 1 < input.size()) {
                    pos++;
                }
                result.strVal += input[pos++];
            }
            if (pos < input.size()) pos++; // skip closing quote
        }
        else if (c == '{') {
            // Object
            result.type = Object;
            pos++; // skip {
            while (pos < input.size() && input[pos] != '}') {
                if (input[pos] == ',') { pos++; continue; }
                // Skip whitespace
                while (pos < input.size() && (input[pos] == ' ' || input[pos] == '\t' || input[pos] == '\n' || input[pos] == '\r'))
                    pos++;
                if (pos >= input.size() || input[pos] == '}') break;

                // Parse key
                JsonValue keyVal = Parse(input, pos);
                std::string key = keyVal.strVal;

                // Skip colon
                while (pos < input.size() && input[pos] != ':') pos++;
                if (pos < input.size()) pos++;

                // Parse value
                JsonValue val = Parse(input, pos);
                result.members.push_back({ key, std::move(val) });
            }
            if (pos < input.size()) pos++; // skip }
        }
        else if (c == '-' || (c >= '0' && c <= '9')) {
            // Number
            result.type = Number;
            size_t start = pos;
            if (c == '-') pos++;
            while (pos < input.size() && ((input[pos] >= '0' && input[pos] <= '9') || input[pos] == '.'))
                pos++;
            result.numVal = strtoll(input.c_str() + start, nullptr, 10);
        }
        return result;
    }
};

bool EspConfig::Load(const wchar_t* path) {
    std::string content = ReadFile(path);
    if (content.empty()) {
        OverlayLog(L"[esp_config] Failed to open %s", path);
        return false;
    }

    // Log first char that parser will see
    size_t p = 0;
    while (p < content.size() && (content[p] == ' ' || content[p] == '\t' || content[p] == '\n' || content[p] == '\r'))
        p++;
    if (p < content.size()) {
        OverlayLog(L"[esp_config] First non-whitespace char: 0x%02X ('%c')", (unsigned char)content[p], content[p]);
    } else {
        OverlayLog(L"[esp_config] Content is all whitespace");
    }

    size_t pos = 0;
    JsonValue root = JsonValue::Parse(content, pos);

    if (root.type != JsonValue::Object) {
        OverlayLog(L"[esp_config] Parse failed — root is not an object");
        return false;
    }

    root.DebugDump("ROOT");

    // Parse globals
    const JsonValue* globals = root.get("globals");
    if (globals) {
        dwLocalPlayerController = globals->getHex("dwLocalPlayerController");
        dwViewMatrix = globals->getHex("dwViewMatrix");
        dwEntityList = globals->getHex("dwEntityList");
    }

    // Parse controller offsets
    const JsonValue* ctrl = root.get("controller_offsets");
    if (ctrl) {
        m_hPlayerPawn = ctrl->getHex("m_hPlayerPawn");
        m_iPawnHealth = ctrl->getHex("m_iPawnHealth");
        m_bPawnIsAlive = ctrl->getHex("m_bPawnIsAlive");
        m_iPawnArmor = ctrl->getHex("m_iPawnArmor");
    }

    // Parse entity offsets
    const JsonValue* ent = root.get("entity_offsets");
    if (ent) {
        m_pGameSceneNode = ent->getHex("m_pGameSceneNode");
    }

    // Parse scene node offsets
    const JsonValue* sn = root.get("scenenode_offsets");
    if (sn) {
        m_vecAbsOrigin = sn->getHex("m_vecAbsOrigin");
        m_vecOrigin = sn->getHex("m_vecOrigin");
    }

    // Parse entity list structure
    const JsonValue* el = root.get("entity_list");
    if (el) {
        chunkCount = (uint32_t)el->getNumber("chunk_count", 64);
        entitiesPerChunk = (uint32_t)el->getNumber("entities_per_chunk", 512);
        entryStride = (uintptr_t)el->getHex("entry_stride", 0x70);
        entityPtrOffset = (uintptr_t)el->getHex("entity_ptr_offset", 0x08);
        entityHandleOffset = (uintptr_t)el->getHex("entity_handle_offset", 0x10);
    }

    OverlayLog(L"[esp_config] Loaded offsets from %s", path);
    OverlayLog(L"[esp_config] dwLocalPlayerController=0x%llX", dwLocalPlayerController);
    OverlayLog(L"[esp_config] dwViewMatrix=0x%llX", dwViewMatrix);
    OverlayLog(L"[esp_config] dwEntityList=0x%llX", dwEntityList);
    OverlayLog(L"[esp_config] m_hPlayerPawn=0x%llX", m_hPlayerPawn);
    OverlayLog(L"[esp_config] m_pGameSceneNode=0x%llX", m_pGameSceneNode);
    OverlayLog(L"[esp_config] m_vecAbsOrigin=0x%llX", m_vecAbsOrigin);

    return IsValid();
}

bool EspConfig::IsValid() const {
    if (!dwLocalPlayerController) { OverlayLog(L"[esp_config] INVALID: dwLocalPlayerController is zero"); return false; }
    if (!dwViewMatrix) { OverlayLog(L"[esp_config] INVALID: dwViewMatrix is zero"); return false; }
    if (!dwEntityList) { OverlayLog(L"[esp_config] INVALID: dwEntityList is zero"); return false; }
    if (!m_hPlayerPawn) { OverlayLog(L"[esp_config] INVALID: m_hPlayerPawn is zero"); return false; }
    if (!m_pGameSceneNode) { OverlayLog(L"[esp_config] INVALID: m_pGameSceneNode is zero"); return false; }
    if (!m_vecAbsOrigin) { OverlayLog(L"[esp_config] INVALID: m_vecAbsOrigin is zero"); return false; }
    return true;
}
