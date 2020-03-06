#pragma once

#include <Windows.h>
#include <Psapi.h>

#include <string>
#include <vector>

#include "win_raii.h"

namespace Util
{
    std::string getLastErrorAsString();
    void hexDump(LPCVOID data, size_t size, DWORD address = 0);


    HRESULT getAllModuleInfo(
        const RAII::HandlePtr& hProcess,
        std::vector<MODULEINFO>& ModuleInfoVec
    );

    HRESULT findPage(
        const RAII::HandlePtr& hProcess,
        std::vector<MEMORY_BASIC_INFORMATION>& MemoryInfoList,
        DWORD Protection = NULL
    );

    HRESULT findInstruction(
        const RAII::HandlePtr& hProcess,
        std::vector<LPVOID>& GadgetList,
        LPCSTR Pattern
    );

    HRESULT isProcessNative(DWORD pid, PBOOL result);
    HRESULT enumProcessThreads(DWORD pid, std::vector<DWORD>& ThreadIDs);
    DWORD findAlertableThread(const RAII::HandlePtr& hProcess);

    PBYTE findPattern(
        const PBYTE rangeStart,
        const PBYTE rangeEnd,
        const char* pattern
    );
}