/*
#include "global.h"
#include "log.h"

void Log(const char* format, ...)
{
    char msg[1024] = "";
    va_list vl;
    va_start(vl, format);
    const int n = _vsnprintf(msg, sizeof(msg) / sizeof(char), format, vl);
    msg[n] = '\0';
    va_end(vl);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, msg);
}
*/