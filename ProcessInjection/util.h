#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <dbghelp.h>

#include <algorithm>
#include <string>
#include <locale>
#include <codecvt>
#include <vector>
#include <map>
#include <set>

#include "nt.h"
#include "win_raii.h"

namespace Util
{
    std::string getLastErrorAsString();
    void hexDump(LPCVOID data, size_t size, DWORD address = 0);

    // return negative if false, check using FAILED()
    DWORD findWithProcessName(LPCWSTR name);

    using ModuleInfoList = std::map<std::wstring, MODULEINFO>;
    HRESULT enumModuleInfo(
        const HANDLE hProcess,
        Util::ModuleInfoList* ModuleInfoList
    );

    std::string getModuleFromAddress(HANDLE hProcess, PVOID addr);
    std::string getSymbolFromAddress(HANDLE hProcess, PVOID addr);

    HRESULT getThreadStartAddress(DWORD tid, PVOID* addr);

    HRESULT findPageByProtection(
        const HANDLE hProcess,
        std::vector<MEMORY_BASIC_INFORMATION>* MemoryInfoList,
        DWORD Protection = NULL
    );

    HRESULT findPatternTargetMemory(
        const HANDLE hProcess,
        OUT std::vector<PVOID>* PatternList,
        IN const std::string& Pattern,
        DWORD Protection,
        DWORD LimitList = 10
    );

    PVOID findInstruction(
        const HANDLE hProcess,
        const std::string& Pattern
    );

    PVOID findWritableAddress(
        const HANDLE hProcess,
        size_t size,
        size_t Alignment = 1
    );

    HRESULT isProcessNative(DWORD pid, PBOOL result);
    HRESULT enumProcessThreads(DWORD pid, std::vector<DWORD>* ThreadIDs);
    DWORD findAlertableThread(const HANDLE hProcess);

    PBYTE findPattern(
        const PBYTE rangeStart,
        const PBYTE rangeEnd,
        const char* pattern
    );

    std::string  ToUtf8(const std::wstring& wstr);
    std::wstring ToUtf16(const std::string& str);
}