#include "global.h"
#include "hook.h"

using NtCreateFile_t = decltype(&NtCreateFile);

PVOID NtBase;
ULONG NtSize;

typedef NTSTATUS(*NtCreateFile_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
NtCreateFile_t g_NtCreateFile = 0;
NTSTATUS MyNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
	if (ObjectAttributes &&
		ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Buffer)
	{
		PUCHAR eProc = (PUCHAR)IoGetCurrentProcess();
		LPCSTR ImageName = (LPCSTR)(eProc + 0x5A8);
		Log(E("NtCreateFile called with % ws, from% s\n"), ObjectAttributes->ObjectName->Buffer, ImageName);
	}

	return g_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

void __fastcall SyscallStub(ULONG SyscallIndex, void** SystemCallFunction)
{
	// Log("SYSCALL %lu: 0x%p\n", SyscallIndex, *SystemCallFunction);
	if (*SystemCallFunction == g_NtCreateFile)
		*SystemCallFunction = MyNtCreateFile;
}

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	Hook::Finalize();
	Log(E("Unload driver.\n"));
}

bool InitGlobals()
{
	Log(E("Initialize global values.\n"));
	NtBase = util::GetNtBase(&NtSize);
	if (!NtBase) {
		Log("Failed to get ntbase.\n");
		return false;
	}

	Log(E("ntoskrnl: 0x%p, dwSize: 0x%X\n"), NtBase, NtSize);
	return true;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);
	pDriverObj->DriverUnload = DriverUnload;

	Log(E("Hello from driver!\n"));

	if (!InitGlobals())
		return STATUS_UNSUCCESSFUL;

	UNICODE_STRING str;
	WCHAR name[256]{ L"NtCreateFile" };
	RtlInitUnicodeString(&str, name);
	g_NtCreateFile = (NtCreateFile_t)MmGetSystemRoutineAddress(&str);
	Log(E("g_NtCreateFile : %p\n"), g_NtCreateFile);
	Hook::Initialize(SyscallStub);

	return STATUS_SUCCESS;
}