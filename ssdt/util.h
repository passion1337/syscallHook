#pragma once 

namespace pe

{
    ULONG RvaToOffset(PVOID base, ULONG Rva);

    PIMAGE_SECTION_HEADER RvaToSection(PVOID base, ULONG Rva);

    ULONG GetExportOffset(PVOID base, LPCSTR name, bool IsFile = true);

    PVOID GetPageBase(PVOID base, ULONG* size, PVOID ptr);

    PVOID FindSection(PVOID base, LPCSTR name, ULONG* size);
}

#define LOCK(Lock) while (_InterlockedCompareExchange64(&Lock, 1, 0) == 1){;}

#define UNLOCK(Lock) (InterlockedExchange64(&Lock, 0))

#define SizeAlign(Size) ((Size + 0xFFF) & 0xFFFFFFFFFFFFF000)

namespace util
{
    inl void MemZero(PVOID Ptr, SIZE_T Size, UCHAR Filling = 0)
    {
        __stosb((PUCHAR)Ptr, Filling, Size);
    }

    inl void MemCpy(PVOID Destination, PVOID Source, SIZE_T Count)
    {
        __movsb((PUCHAR)Destination, (PUCHAR)Source, Count);
    }

    inl PVOID KAlloc(u64 Size, bool exec = false, bool PagedPool = false)
    {
        PVOID Buff = ImpCall(ExAllocatePoolWithTag,
            PagedPool ? POOL_TYPE::PagedPool : (exec ? NonPagedPool : NonPagedPoolNx),
            Size, MY_POOL_TAG);
        if (Buff) memset(Buff, 0, Size);
        return Buff;
    }

    inl void KFree(PVOID mem)
    {
        if (mem) ImpCall(ExFreePoolWithTag, mem, MY_POOL_TAG);
    }
#define ObDeref ObfDeref
    inl void ObfDeref(PVOID Obj)
    {
        if (Obj)
            ImpCall(ObfDereferenceObject, Obj);
    }

    inl void KSleep(LONG milliseconds)
    {
        LARGE_INTEGER interval;
        interval.QuadPart = -(10000 * milliseconds); // convert milliseconds to 100 nanosecond intervals
        ImpCall(KeDelayExecutionThread, KernelMode, FALSE, &interval);
    }

    template <class T>
    inl bool IsCanonicalAddress(T address)
    {
        u64 addr = *(u64*)&address;

        if (addr <= 0x1000)
            return false;

        if (
            ((addr >= 0xFFFF800000000000) && (addr <= 0xFFFFFFFFFFFFFFFF)) ||
            ((addr >= 0) && (addr <= 0x7FFFFFFFFFFF))
            )
        {
            return true;
        }

        return false;
    }

    inl BOOLEAN IsValid(pv addr)
    {
        if ((u64)addr <= 0x1000)
            return false;

        if (!IsCanonicalAddress(addr))
            return false;

        return ImpCall(MmIsAddressValid, addr);
    }

    inl BOOLEAN IsValid(u64 addr)
    {
        if (addr < 0x1000)
            return false;
        return ImpCall(MmIsAddressValid, (pv)addr);
    }

    inl DECLSPEC_NORETURN VOID BugCheck(u32 Line)
    {
        ImpCall(KeBugCheck, Line);
    }

    inl bool readByte(PVOID addr, UCHAR* ret)
    {
        *ret = *(volatile char*)addr;
        return true;
    }

    void* GetNtBase(ULONG* Size);

    ULONG GetWinVer();

    PVOID NQSI(SYSTEM_INFORMATION_CLASS Class);

    NTSTATUS getKernelModuleByName(const char* moduleName, PVOID* moduleStart, size_t* moduleSize);

    NTSTATUS GetProcessIdByProcessName(const wchar_t* ImageName, OUT HANDLE* OutPid);

    PUCHAR FindPatternSect(PVOID ModBase, const char* SectName, const char* Pattern);

    PUCHAR FindPatternRange(PVOID Start, u32 size, const char* Pattern);

    NTSTATUS ReadFile(IN const wchar_t* FileName, OUT char** DataFreeByCaller, OUT SIZE_T* DataSize);

    bool DeleteFile(PUNICODE_STRING Path);

    NTSTATUS WriteFile(PUNICODE_STRING filePath, PVOID data, ULONG length);

    bool IsValidFileObject(PFILE_OBJECT FileObject);

    POBJECT_NAME_INFORMATION GetFileNameInfo(PFILE_OBJECT FileObject);
}