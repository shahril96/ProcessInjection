#pragma once

#include <Windows.h>

/* Thread Information Classes */
typedef enum _THREADINFOCLASS {
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    MaxThreadInfoClass
} THREADINFOCLASS;

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    IN HANDLE       ProcessHandle,
    THREADINFOCLASS ProcessInformationClass,
    OUT PVOID       ProcessInformation,
    IN ULONG        ProcessInformationLength,
    OUT PULONG      ReturnLength OPTIONAL
);