#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <intrin.h>
#include <windef.h>

#define E(a) a
#define EPtr(a) a
#define ImpCall(a,...) (a(__VA_ARGS__))

#include "Define.h"


#define ConstStrLen(Str) ((sizeof(Str) - sizeof(Str[0])) / sizeof(Str[0]))
#define ToLower(Char) ((Char >= 'A' && Char <= 'Z') ? (Char + 32) : Char)
#define ToUpper(Char) ((Char >= 'a' && Char <= 'z') ? (Char - 'a') : Char)
#define GET_NT_HEADERS(BaseAddress) ((PIMAGE_NT_HEADERS)((ULONG_PTR)BaseAddress + (PIMAGE_DOS_HEADER(BaseAddress))->e_lfanew))
#define GET_IMAGE_SIZE(BaseAddress) (((PIMAGE_NT_HEADERS)((ULONG_PTR)BaseAddress + (PIMAGE_DOS_HEADER(BaseAddress))->e_lfanew))->OptionalHeader.SizeOfImage)

// if same, return TRUE
template <typename StrType, typename StrType2>
__forceinline bool StrICmp(StrType Str, StrType2 InStr, bool CompareFull) {
	if (!Str || !InStr) return false;
	wchar_t c1, c2; do {
		c1 = *Str++; c2 = *InStr++;
		c1 = ToLower(c1); c2 = ToLower(c2);
		if (!c1 && (CompareFull ? !c2 : 1))
			return true;
	} while (c1 == c2);

	return false;
}

#define MY_POOL_TAG ('LACK')
extern PVOID NtBase;
extern ULONG NtSize;

#include "log.h"
#include "util.h"
