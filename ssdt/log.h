#pragma once 

// void Log(const char* format, ...);

#define Log(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)