#pragma once 
#include "global.h"
#include <wmistr.h>

using callback_t = void(*)(ULONG SyscallIndex, void** SystemCallFunction);

typedef struct _EVENT_TRACE_PROPERTIES {
	WNODE_HEADER Wnode;
	ULONG        BufferSize;
	ULONG        MinimumBuffers;
	ULONG        MaximumBuffers;
	ULONG        MaximumFileSize;
	ULONG        LogFileMode;
	ULONG        FlushTimer;
	ULONG        EnableFlags;
	union {
		LONG AgeLimit;
		LONG FlushThreshold;
	} DUMMYUNIONNAME;
	ULONG        NumberOfBuffers;
	ULONG        FreeBuffers;
	ULONG        EventsLost;
	ULONG        BuffersWritten;
	ULONG        LogBuffersLost;
	ULONG        RealTimeBuffersLost;
	HANDLE       LoggerThreadId;
	ULONG        LogFileNameOffset;
	ULONG        LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, * PEVENT_TRACE_PROPERTIES;

// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/traceapi/control/index.htm 
enum CKCL_TRACE_OPERATION
{
	EtwStartLoggerCode = 1,
	EtwStopLoggerCode = 2,
	EtwUpdateLoggerCode = 4,
};

typedef struct _CKCL_TRACE_PROPERIES : EVENT_TRACE_PROPERTIES
{
	ULONG64					Unknown[3];
	UNICODE_STRING			ProviderName;
} CKCL_TRACE_PROPERTIES, * PCKCL_TRACE_PROPERTIES;


namespace Hook
{
	bool Initialize(callback_t CallbackFunction);
	void Finalize();
}