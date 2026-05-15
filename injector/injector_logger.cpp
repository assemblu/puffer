




#include "injector_logger.h"
#include <cstdio>
#include <cwchar>
#include <windows.h>

static const wchar_t* LOG_FILE_PATH = L"C:\\Users\\emirg\\dev\\puffer\\injector_debug.log";

void Log(const wchar_t* fmt, ...) {
    

    wchar_t buffer[1024];
    va_list args;
    va_start(args, fmt);
    _vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, fmt, args);
    va_end(args);

    

    fwprintf(stderr, L"[injector] %s\n", buffer);

    

    FILE* f = nullptr;
    _wfopen_s(&f, LOG_FILE_PATH, L"a+, ccs=UTF-8");
    if (f) {
        fwprintf(f, L"[injector] %s\n", buffer);
        fclose(f);
    }
}
