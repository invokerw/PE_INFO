#pragma once

#include <Windows.h>

#ifdef _WIN64
typedef  DWORD64 DWORDX;
#else
typedef  DWORD32 DWORDX;
#endif

bool PE_INFO(LPCVOID base, DWORDX length);

void DumpResourceDirectory(PIMAGE_RESOURCE_DIRECTORY root, PIMAGE_RESOURCE_DIRECTORY base, int depth, DWORDX offset);