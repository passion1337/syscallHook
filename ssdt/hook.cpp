#include "hook.h"
#include "hde/hde64.h"

#define INFINITYHOOK_MAGIC_1 ((ULONG)0x501802)
#define INFINITYHOOK_MAGIC_2 ((USHORT)0xF33)

using fn_t = __int64(*)();


namespace Hook
{
	callback_t SyscallCllback = nullptr;

	PUCHAR HalpStallCounter = nullptr;
	fn_t OldHalpHvCounterQueryCounter = nullptr;
	
	PUCHAR EtwpDebuggerData = nullptr;
	PUCHAR SystemCallEntryPage = nullptr;
	PVOID CkclWmiLoggerContext = nullptr; 
	u64* pGetCpuClockFlag = nullptr;
	u64 OldFlag = 0;

	bool bInit = false; 

	static __int64 HookHalpHvCounterQueryCounter()
	{
		if(KeGetCurrentIrql() != PASSIVE_LEVEL ||ExGetPreviousMode() == KernelMode) 
			return OldHalpHvCounterQueryCounter();
		
		PUCHAR CurrentThread = (PUCHAR)__readgsqword(0x188);
		ULONG SystemCallNumber = *(ULONG*)(CurrentThread + 0x80);

		PVOID* StackMax = (PVOID*)__readgsqword(0x1a8); // kpcr->kprcb->RspBase
		PVOID* StackFrame = (PVOID*)_AddressOfReturnAddress(); // returnaddress 

		// search [StackMax <= Range < StackFrame]
		for (PVOID* StackCurrent = StackMax; StackFrame < StackCurrent; --StackCurrent)
		{
			// to find values before "PerfInfoLogSysCallEntry", walk -way stack 
			// EtwTraceSiloKernelEvent(ThreadServerSilo, v5, 1, 0x40000040u, 0xF33, 0x501802); 
			PULONG AsUlong = (PULONG)StackCurrent;
			if (*AsUlong != INFINITYHOOK_MAGIC_1)
				continue; 

			--StackCurrent;
			PUSHORT AsShort = (PUSHORT)StackCurrent;
			if (*AsShort != INFINITYHOOK_MAGIC_2)
				continue; 

			// to find syscall address, walk +way
			for (; StackCurrent < StackMax; ++StackCurrent)
			{	
				PULONGLONG AsUlonglong = (PULONGLONG)StackCurrent;

				if (!(SystemCallEntryPage <= PAGE_ALIGN(*AsUlonglong) && PAGE_ALIGN(*AsUlonglong) < SystemCallEntryPage + PAGE_SIZE*2))
					continue;

				void** SystemCallFunction = &StackCurrent[9];
				if (SyscallCllback)
					SyscallCllback(SystemCallNumber, SystemCallFunction);
				
				break;
			}
			break;
		}

		return OldHalpHvCounterQueryCounter();
	}

	static PVOID GetSyscallEntry()
	{
		PVOID SyscallEntry = (PVOID)__readmsr(0xC0000082);

		ULONG SizeOfSection;
		PVOID SectionBase = pe::FindSection(NtBase, E("KVASCODE"), &SizeOfSection);
		if (!SectionBase)
		{
			return SyscallEntry;
		}

		if (!(SyscallEntry >= SectionBase && SyscallEntry < (PVOID)((uintptr_t)SectionBase + SizeOfSection)))
		{
			return SyscallEntry;
		}

		hde64s HDE;
		for (PCHAR KiSystemServiceUser = (PCHAR)SyscallEntry; /* */; KiSystemServiceUser += HDE.len)
		{
			if (!hde64_disasm(KiSystemServiceUser, &HDE))
				break;

			if (HDE.opcode != 0xE9)
				continue;

			PVOID PossibleSyscallEntry = (PVOID)((intptr_t)KiSystemServiceUser + (int)HDE.len + (int)HDE.imm.imm32);
			if (PossibleSyscallEntry >= SectionBase && PossibleSyscallEntry < (PVOID)((uintptr_t)SectionBase + SizeOfSection))
				continue;

			SyscallEntry = PossibleSyscallEntry;
			break;
		}

		return SyscallEntry;
	}

	NTSTATUS ModifyTraceSettings(CKCL_TRACE_OPERATION Operation)
	{
		ULONG ReturnLength = 0;
		NTSTATUS status = 0;
		PCKCL_TRACE_PROPERTIES Property = (PCKCL_TRACE_PROPERTIES)util::KAlloc(PAGE_SIZE);
		if (!Property)
			return STATUS_MEMORY_NOT_ALLOCATED;

		memset(Property, 0, PAGE_SIZE);
		Property->Wnode.BufferSize = PAGE_SIZE;
		Property->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		Property->ProviderName = RTL_CONSTANT_STRING(L"Circular Kernel Context Logger");
		Property->Wnode.Guid = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };
		Property->Wnode.ClientContext = 1; // use QPC
		Property->BufferSize = sizeof(ULONG);
		Property->MinimumBuffers = Property->MaximumBuffers = 2;
		Property->LogFileMode = 0x400; // EVENT_TRACE_BUFFERING_MODE

		if (Operation == CKCL_TRACE_OPERATION::EtwUpdateLoggerCode)
			Property->EnableFlags = 0x80; // EVENT_TRACE_FLAG_SYSTEMCALL

		status = ZwTraceControl(Operation, Property, PAGE_SIZE, Property, PAGE_SIZE, &ReturnLength);
		util::KFree(Property);
		return status;
	}

	bool InitializeOffset()
	{
		UNICODE_STRING unKeQueryPerformanceCounter;
		PVOID pKeQueryPerformanceCounter;
		// 1. find EtwpDebuggerData
		do
		{
			EtwpDebuggerData = util::FindPatternSect(NtBase, E(".data"), E("2c 08 04 38 0c"));
			if (EtwpDebuggerData)
				break;

			EtwpDebuggerData = util::FindPatternSect(NtBase, E(".rdata"), E("2c 08 04 38 0c"));
			if (EtwpDebuggerData)
				break;

			Log(E("Failed to find EtwpDebuggerData\n"));
			return false;
		} while (false);
		EtwpDebuggerData -= 2;
		Log(E("EtwpDebuggerData: 0x%p\n"), EtwpDebuggerData);

		// 2. find CkclWmiLoggerContext
		PVOID* EtwpDebuggerDataSilo = *(PVOID**)(EtwpDebuggerData + 0x10);
		CkclWmiLoggerContext = EtwpDebuggerDataSilo[2];
		pGetCpuClockFlag = (u64*)((PUCHAR)CkclWmiLoggerContext + 0x28);
		Log(E("CkclWmiLoggerContext: 0x%p\n"), CkclWmiLoggerContext);
		Log(E("GetCpuClock flag ptr: 0x%p\n"), pGetCpuClockFlag);

		// 3. find SystemCallEntryPage
		SystemCallEntryPage = (PUCHAR)PAGE_ALIGN(GetSyscallEntry());
		if (!SystemCallEntryPage) {
			Log(E("Failed to find SystemCallEntry\n"));
			return false;
		}
		Log(E("SystemCallEntryPage: 0x%p\n"), SystemCallEntryPage);

		// 4. find HalpPerformanceCounter
		ImpCall(RtlInitUnicodeString, &unKeQueryPerformanceCounter, E(L"KeQueryPerformanceCounter"));
		pKeQueryPerformanceCounter = ImpCall(MmGetSystemRoutineAddress, &unKeQueryPerformanceCounter);
		if (!pKeQueryPerformanceCounter) {
			Log(E("Failed to get KeQueryPerformanceCounter address\n"));
			return false;
		}
		Log(E("KeQueryPerformanceCounter: 0x%p\n"), pKeQueryPerformanceCounter);

		PUCHAR match = util::FindPatternRange(pKeQueryPerformanceCounter, 0x50, E("48 8B 3D ? ? ? ?"));
		if (!match) {
			Log(E("Failed to find 'HalpPerformanceCounter' pattern\n"));
			return false;
		}

		HalpStallCounter = *(PUCHAR*)(RVA(match, 7));
		OldHalpHvCounterQueryCounter = *(fn_t*)(HalpStallCounter + 0x70);
		Log(E("HalpStallCounter: 0x%p\n"), HalpStallCounter);
		Log(E("HalpHvCounterQueryCounter: 0x%p\n"), OldHalpHvCounterQueryCounter);

		return HalpStallCounter && OldHalpHvCounterQueryCounter;
	}

	bool Initialize(callback_t CallbackFunction)
	{
		if (bInit) return false;

		if (!InitializeOffset()) 
			return false;

		if (!MmIsAddressValid(OldHalpHvCounterQueryCounter)) {
			Log(E("OldHalpHvCounterQueryCounter is invalid function pointer.\n"));
			return false;
		}

		NTSTATUS status = ModifyTraceSettings(EtwUpdateLoggerCode);
		if (!NT_SUCCESS(status))
		{
			status = ModifyTraceSettings(EtwStartLoggerCode);
			if (!NT_SUCCESS(status))
			{
				Log(E("ModifyTraceSettings failed, Err: 0x%X\n"), status);
				return false;
			}

			status = ModifyTraceSettings(EtwUpdateLoggerCode);
			if (!NT_SUCCESS(status))
			{
				Log(E("ModifyTraceSettings failed, Err: 0x%X\n"), status);
				return false;
			}
		}
		
		SyscallCllback = CallbackFunction;
		OldFlag = *pGetCpuClockFlag;
		*pGetCpuClockFlag = 1;
		*(PVOID*)(HalpStallCounter + 0x70) = HookHalpHvCounterQueryCounter;
		
		Log(E("====Initialize result====\n"));
		Log(E("*(pGetCpuClockFlag): %llx\n"), *pGetCpuClockFlag);
		Log(E("*(&HalpHvCounterQueryCounter): %p\n"), HookHalpHvCounterQueryCounter);
		bInit = true;
		return bInit;
	}

	void Finalize()
	{
		*pGetCpuClockFlag = OldFlag;
		*(PVOID*)(HalpStallCounter + 0x70) = OldHalpHvCounterQueryCounter;
		Log(E("====Finalize result====\n"));
		Log(E("*(pGetCpuClockFlag): %llx\n"), *pGetCpuClockFlag);
		Log(E("*(&HalpHvCounterQueryCounter): %p\n"), OldHalpHvCounterQueryCounter);
	}

}