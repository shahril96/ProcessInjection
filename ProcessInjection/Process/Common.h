#pragma once

// winapi
#include <phnt_windows.h>
#include <phnt.h>
#include <conio.h>
#include <Psapi.h>
#include <dbghelp.h>
#include <tlhelp32.h>

// c++ std
#include <map>
#include <set>
#include <chrono>
#include <string>
#include <locale>
#include <memory>
#include <vector>
#include <random>
#include <codecvt>
#include <algorithm>
#include <functional>

// LIB definition
#pragma comment( lib, "dbghelp.lib" )

//
// typedef
//

typedef __kernel_entry NTSTATUS(WINAPI* fnNtQuerySystemInformation)(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef __kernel_entry NTSTATUS(WINAPI* fnNtQueryInformationProcess)(
    IN HANDLE           ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID           ProcessInformation,
    IN ULONG            ProcessInformationLength,
    OUT PULONG          ReturnLength
    );

typedef __kernel_entry NTSTATUS(WINAPI* fnNtQueryInformationThread)(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef NTSYSCALLAPI NTSTATUS(NTAPI *fnNtMapViewOfSection)(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect
);

// common MACROs
#define GetStlContainerBufferSize(x) (x.size() * sizeof(x[0]))

// define typename
namespace Process
{
    using ByteArray_t = std::vector<BYTE>;
    using PointerArray_t = std::vector<PVOID>;
    using MemoryInfoList_t = std::vector<MEMORY_BASIC_INFORMATION>;
}