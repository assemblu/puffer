






#include "logger.h"
#include <windows.h>
#include <cstdio>

static const wchar_t* LOG_PATH = L"C:\\Users\\emirg\\dev\\puffer\\overlay_debug.log";

void OverlayLog(const wchar_t* fmt, ...) {
    wchar_t buffer[1024];
    va_list args;
    va_start(args, fmt);
    _vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, fmt, args);
    va_end(args);

    

    FILE* f = nullptr;
    _wfopen_s(&f, LOG_PATH, L"a+, ccs=UTF-8");
    if (f) {
        fwprintf(f, L"%s\n", buffer);
        fclose(f);
    }
}
