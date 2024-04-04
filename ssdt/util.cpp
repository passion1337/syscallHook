#include "global.h"
#include "util.h"
#include "log.h"
namespace pe
{
    inl bool IsValidImage(PVOID base)
    {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
        PIMAGE_NT_HEADERS ntHeader = GET_NT_HEADERS(base);
        return ntHeader->Signature == IMAGE_NT_SIGNATURE;
    }

    ULONG RvaToOffset(PVOID base, ULONG Rva)
    {
        PIMAGE_NT_HEADERS ntHeader = GET_NT_HEADERS(base);
        PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(ntHeader);
        for (UINT i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, sect++)
        {
            DWORD start = sect->VirtualAddress;
            DWORD end = start + sect->Misc.VirtualSize;
            if (start <= Rva && Rva < end)
                return (Rva - start) + sect->PointerToRawData;
        }
        return 0;
    }

    PIMAGE_SECTION_HEADER RvaToSection(PVOID base, ULONG Rva)
    {
        PIMAGE_NT_HEADERS ntHeader = GET_NT_HEADERS(base);
        PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(ntHeader);
        for (UINT i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, sect++)
        {
            DWORD start = sect->VirtualAddress;
            DWORD end = start + sect->Misc.VirtualSize;
            if (start <= Rva && Rva < end)
                return sect;
        }
        return nullptr;
    }

    ULONG GetExportOffset(PVOID base, LPCSTR name, bool IsFile)
    {
        PIMAGE_NT_HEADERS ntheader = GET_NT_HEADERS(base);
        IMAGE_DATA_DIRECTORY ExportDirData = ntheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!ExportDirData.Size) return 0;

        ULONG Rva = ExportDirData.VirtualAddress;

        ULONG   ExportDirOffset = IsFile ? RvaToOffset(base, Rva) : Rva;
        if (!ExportDirOffset) return 0;

        PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)base + ExportDirOffset);
        ULONG AddressOfFunctionsOffset = IsFile ? RvaToOffset(base, ExportDir->AddressOfFunctions) : ExportDir->AddressOfFunctions;
        ULONG AddressOfNameOrdinalsOffset = IsFile ? RvaToOffset(base, ExportDir->AddressOfNameOrdinals) : ExportDir->AddressOfNameOrdinals;
        ULONG AddressOfNamesOffset = IsFile ? RvaToOffset(base, ExportDir->AddressOfNames) : ExportDir->AddressOfNames;
        ULONG* AddressOfFunctions = (ULONG*)((PBYTE)base + AddressOfFunctionsOffset);
        USHORT* AddressOfNameOrdinals = (USHORT*)((PBYTE)base + AddressOfNameOrdinalsOffset);
        ULONG* AddressOfNames = (ULONG*)((PBYTE)base + AddressOfNamesOffset);

        ULONG ret = 0;
        for (UINT i = 0; i < ExportDir->NumberOfNames; i++)
        {
            ULONG NameOffset = IsFile ? RvaToOffset(base, AddressOfNames[i]) : AddressOfNames[i];
            Rva = AddressOfFunctions[AddressOfNameOrdinals[i]];
            if (ExportDirData.VirtualAddress <= Rva && ExportDirData.VirtualAddress + ExportDirData.Size)
                continue;
            LPCSTR functionName = (LPCSTR)((PBYTE)base + NameOffset);
            if (functionName && !_stricmp(functionName, name))
            {
                Rva = IsFile ? RvaToOffset(base, Rva) : Rva;
                return Rva;
            }
        }
        return 0;
    }

    PVOID GetPageBase(PVOID base, ULONG* size, PVOID ptr)
    {
        if (ptr < base) return nullptr;
        if (!IsValidImage(base)) return nullptr;

        ULONG Rva = (ULONG)((PBYTE)ptr - (PBYTE)base);
        PIMAGE_SECTION_HEADER sect = RvaToSection(base, Rva);
        if (!sect) return nullptr;
        if (size) *size = sect->Misc.VirtualSize;
        return (PBYTE)base + sect->VirtualAddress;
    }

    PVOID FindSection(PVOID base, LPCSTR name, ULONG* size)
    {
        PIMAGE_NT_HEADERS ntheader = GET_NT_HEADERS(base);
        PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(ntheader);
        for (UINT i = 0; i < ntheader->FileHeader.NumberOfSections; i++, sect++)
        {
            char SectName[9]; 
            SectName[8] = 0;
            *(u64*)&SectName[0] = *(u64*)&sect->Name[0];
            if (StrICmp(name, SectName, true))
            {
                if (size) *size = sect->Misc.VirtualSize;
                return (PVOID)((u64)base + sect->VirtualAddress);
            }
        }
        return nullptr;
    }
}

namespace util
{
    ULONG GetWinVer()
    {
        DWORD dwBuildNumber;
        ImpCall(PsGetVersion, 0, 0, &dwBuildNumber, 0);
        return dwBuildNumber;
    }

    void* GetNtBase(ULONG* Size)
    {
        typedef unsigned char uint8_t;
        auto Idt_base = reinterpret_cast<uintptr_t>(KeGetPcr()->IdtBase);
        auto align_page = *reinterpret_cast<uintptr_t*>(Idt_base + 4) >> 0xc << 0xc;

        for (; align_page; align_page -= PAGE_SIZE)
        {
            for (int index = 0; index < PAGE_SIZE - 0x7; index++)
            {
                auto current_address = static_cast<intptr_t>(align_page) + index;

                if (*reinterpret_cast<uint8_t*>(current_address) == 0x48
                    && *reinterpret_cast<uint8_t*>(current_address + 1) == 0x8D
                    && *reinterpret_cast<uint8_t*>(current_address + 2) == 0x1D
                    && *reinterpret_cast<uint8_t*>(current_address + 6) == 0xFF) //48 8d 1D ?? ?? ?? ?? FF
                {
                    auto nto_base_offset = *reinterpret_cast<int*>(current_address + 3);
                    auto nto_base_ = (current_address + nto_base_offset + 7);
                    if (!(nto_base_ & 0xfff)) {
                        *Size = reinterpret_cast<IMAGE_NT_HEADERS64*>(nto_base_ + reinterpret_cast<IMAGE_DOS_HEADER*>(nto_base_)->e_lfanew)->OptionalHeader.SizeOfImage;
                        return (void*)nto_base_;
                    }
                }
            }
        }

        return NULL;
    }

    PVOID NQSI(SYSTEM_INFORMATION_CLASS Class)
    {
        ULONG ret_size = 0;
        ImpCall(ZwQuerySystemInformation, Class, 0, 0, &ret_size);

        NTSTATUS status = 0;
        PVOID pInfo = 0;
        do
        {
            if (pInfo) KFree(pInfo);

            pInfo = KAlloc(ret_size);
            status = ImpCall(ZwQuerySystemInformation, Class, pInfo, ret_size, &ret_size);
        } while (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH);

        return pInfo;
    }

    NTSTATUS getKernelModuleByName(const char* moduleName, PVOID* moduleStart, size_t* moduleSize)
    {
        if (!moduleStart)
            return STATUS_INVALID_PARAMETER;

        const auto listHeader = NQSI(SystemModuleInformation);
        if (!listHeader)
            return STATUS_MEMORY_NOT_ALLOCATED;

        auto currentModule = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Module;
        for (size_t i = 0; i < reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Count; ++i, ++currentModule)
        {
            // \SystemRoot\system32\ntoskrnl.exe -> ntoskrnl.exe 
            const auto currentModuleName = reinterpret_cast<const char*>(currentModule->FullPathName + currentModule->OffsetToFileName);
            if (!strcmp(moduleName, currentModuleName))
            {
                *moduleStart = currentModule->ImageBase;
                if (moduleSize)
                    *moduleSize = currentModule->ImageSize;
                KFree(listHeader);
                return STATUS_SUCCESS;
            }
        }
        KFree(listHeader);
        return STATUS_NOT_FOUND;
    }

    NTSTATUS GetProcessIdByProcessName(const wchar_t* ImageName, OUT HANDLE* OutPid)
    {
        PSYSTEM_PROCESS_INFO pInfo = 0;
        PSYSTEM_PROCESS_INFO Buffer = 0;
        NTSTATUS Status = STATUS_UNSUCCESSFUL;

        Buffer = (PSYSTEM_PROCESS_INFO)NQSI(SystemProcessInformation);
        if (!Buffer)
            return STATUS_UNSUCCESSFUL;

        pInfo = Buffer;

        Status = STATUS_UNSUCCESSFUL;
        for (;;)
        {
            if (pInfo->ImageName.Buffer && StrICmp(ImageName, pInfo->ImageName.Buffer, TRUE))
            {
                //__db();
                *OutPid = pInfo->UniqueProcessId;
                Status = 0;
                break;
            }
            else if (pInfo->NextEntryOffset)
                pInfo = (PSYSTEM_PROCESS_INFO)((PUCHAR)pInfo + pInfo->NextEntryOffset);
            else
                break;
        }

        KFree(Buffer);

        return Status;
    }

    //find pattern utils
#define InRange(x, a, b) (x >= a && x <= b) 
#define GetBits(x) (InRange(x, '0', '9') ? (x - '0') : (InRange(x, 'a', 'z') ? ((x - 'a') + 0xA) : ((x - 'A') + 0xA)) )
#define GetByte(x) ((UCHAR)(GetBits(x[0]) << 4 | GetBits(x[1])))
    PUCHAR FindPatternSect(PVOID ModBase, const char* SectName, const char* Pattern)
    {
        if (!ModBase || !Pattern || !SectName) return nullptr;

        //get sect range
        ULONG SectSize;
        PUCHAR ModuleStart = (PUCHAR)pe::FindSection(ModBase, SectName, &SectSize);
        PUCHAR ModuleEnd = ModuleStart + SectSize;

        if (!ModuleStart) return nullptr;

        //scan pattern main
        PUCHAR FirstMatch = nullptr;
        const char* CurPatt = Pattern;
        if (*Pattern == '\0')
            CurPatt++;

        for (; ModuleStart < ModuleEnd; ++ModuleStart)
        {
            bool SkipByte = (*CurPatt == '\?');

            //hp(ModuleStart);
            UCHAR byte1;
            if (!readByte(ModuleStart, &byte1)) {
                auto addr2 = (u64)ModuleStart;
                addr2 &= 0xFFFFFFFFFFFFF000;
                addr2 += 0xFFF;
                ModuleStart = (PUCHAR)addr2;
                //sp("123");
                goto Skip;
            }

            if (SkipByte || byte1 == GetByte(CurPatt)) {
                if (!FirstMatch) FirstMatch = ModuleStart;
                if (SkipByte)
                    CurPatt += 2;
                else
                    CurPatt += 3;
                if (CurPatt[-1] == 0) return FirstMatch;
            }

            else if (FirstMatch) {
                ModuleStart = FirstMatch;
            Skip:
                FirstMatch = nullptr;
                CurPatt = Pattern;
            }
        }

        //failed
        return nullptr;
    }

    PUCHAR FindPatternRange(PVOID Start, u32 size, const char* Pattern)
    {
        //get sect range
        ULONG SectSize;
        PUCHAR ModuleStart = (PUCHAR)Start;
        PUCHAR ModuleEnd = ModuleStart + size;

        //scan pattern main
        PUCHAR FirstMatch = nullptr;
        const char* CurPatt = Pattern;
        if (*Pattern == '\0')
            CurPatt++;

        for (; ModuleStart < ModuleEnd; ++ModuleStart)
        {
            bool SkipByte = (*CurPatt == '\?');

            //hp(ModuleStart);
            UCHAR byte1;
            if (!readByte(ModuleStart, &byte1)) {
                auto addr2 = (u64)ModuleStart;
                addr2 &= 0xFFFFFFFFFFFFF000;
                addr2 += 0xFFF;
                ModuleStart = (PUCHAR)addr2;
                //sp("123");
                goto Skip;
            }

            if (SkipByte || byte1 == GetByte(CurPatt)) {
                if (!FirstMatch) FirstMatch = ModuleStart;
                SkipByte ? CurPatt += 2 : CurPatt += 3;
                if (CurPatt[-1] == 0) return FirstMatch;
            }

            else if (FirstMatch) {
                ModuleStart = FirstMatch;
            Skip:
                FirstMatch = nullptr;
                CurPatt = Pattern;
            }
        }

        //failed
        return nullptr;
    }

    NTSTATUS ReadFile(IN const wchar_t* FileName, OUT char** DataFreeByCaller, OUT SIZE_T* DataSize)
    {
        HANDLE hFile = NULL;
        IO_STATUS_BLOCK sb = { 0 };
        NTSTATUS status = 0;
        LARGE_INTEGER Offset = { 0 };
        OBJECT_ATTRIBUTES object_attr = { 0 };
        //ANSI_STRING anFilePath = { 0 };
        UNICODE_STRING unFilePathName = { 0 };
        FILE_STANDARD_INFORMATION fsi = { 0 };
        LARGE_INTEGER Size = { 0 };

        ImpCall(RtlInitUnicodeString, &unFilePathName, FileName);
        
        InitializeObjectAttributes(&object_attr, &unFilePathName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = ImpCall(ZwCreateFile, &hFile, GENERIC_READ, &object_attr, &sb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
            FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }

        memset(&sb, 0, sizeof(sb));
        status = ImpCall(ZwQueryInformationFile, hFile, &sb, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
        if (!NT_SUCCESS(status))
        {
            ImpCall(ZwClose, hFile);
            return status;
        }
        Size.QuadPart = fsi.EndOfFile.QuadPart;

        
        *DataFreeByCaller = (CHAR*)KAlloc(Size.QuadPart);
        if (*DataFreeByCaller == NULL)
        {
            ImpCall(ZwClose, hFile);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

       
        status = ImpCall(ZwReadFile, hFile, NULL, NULL, NULL, &sb, (PVOID)*DataFreeByCaller, (ULONG)Size.QuadPart, &Offset, NULL);
        if (!NT_SUCCESS(status))
        {
            ImpCall(ZwClose, hFile);
            KFree(*DataFreeByCaller);
            *DataFreeByCaller = 0;
            return status;
        }

        if (DataSize)
            *DataSize = Size.QuadPart;
        return ImpCall(ZwClose, hFile);
    }

    bool DeleteFile(PUNICODE_STRING Path)
    {

        HANDLE hFile = NULL;
        OBJECT_ATTRIBUTES obj = { 0 };
        IO_STATUS_BLOCK IoStatck = { 0 };
        InitializeObjectAttributes(&obj, Path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

        NTSTATUS NtStatus = ImpCall(ZwCreateFile, &hFile, FILE_READ_ACCESS, &obj, &IoStatck, NULL,
            FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, NULL);
        if (!NT_SUCCESS(NtStatus))
            return FALSE;

        PFILE_OBJECT FileObject = NULL;
        NtStatus = ImpCall(ObReferenceObjectByHandle, hFile, FILE_ALL_ACCESS, *(IoFileObjectType), KernelMode, (PVOID*)&FileObject, NULL);
        if (!NT_SUCCESS(NtStatus))
        {
            ImpCall(ZwClose, hFile);
            return FALSE;
        }
        ImpCall(ZwClose, hFile);

        FileObject->DeletePending = 0;
        FileObject->DeleteAccess = 1;
        FileObject->SharedDelete = 1;
        FileObject->SectionObjectPointer->DataSectionObject = NULL;
        FileObject->SectionObjectPointer->ImageSectionObject = NULL;
        FileObject->SectionObjectPointer->SharedCacheMap = NULL;
        NtStatus = ImpCall(ZwDeleteFile, &obj);
        ObDeref(FileObject);
        if (!NT_SUCCESS(NtStatus))
        {
            return FALSE;
        }
        return TRUE;
    }

    NTSTATUS WriteFile(PUNICODE_STRING filePath, PVOID data, ULONG length)
    {
        NTSTATUS status;
        HANDLE fileHandle;
        OBJECT_ATTRIBUTES objAttr;
        IO_STATUS_BLOCK ioStatusBlock;

        // Initialize the object attributes to open the file
        InitializeObjectAttributes(&objAttr, filePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

        // Open the file
        status = ZwCreateFile(&fileHandle, GENERIC_WRITE, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

        if (!NT_SUCCESS(status))
        {
            // File open failed
            return status;
        }

        // Write the data to the file
        status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, data, length, NULL, NULL);

        if (!NT_SUCCESS(status))
        {
            // Write operation failed
            ZwClose(fileHandle);
            return status;
        }

        // Close the file handle
        ZwClose(fileHandle);

        return STATUS_SUCCESS;
    }

    bool IsValidFileObject(PFILE_OBJECT FileObject)
    {
        if (!IsValid(FileObject))
            return false;

        if (FileObject->Type != 5)
            return false;

        return true;
    }

    //Data free by caller, ret = C:\Users\Pipi\Desktop\1.exe 
    POBJECT_NAME_INFORMATION GetFileNameInfo(PFILE_OBJECT FileObject)
    {
        if (!IsValidFileObject(FileObject))
            return 0;

        POBJECT_NAME_INFORMATION ObjectNameInformation = 0;

        ImpCall(IoQueryFileDosDeviceName, FileObject, &ObjectNameInformation);

        if (ObjectNameInformation)
            *(PWCH)((u64)ObjectNameInformation->Name.Buffer + ObjectNameInformation->Name.Length) = L'\0';

        return ObjectNameInformation;
    }
}
