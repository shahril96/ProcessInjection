#pragma once

#include <Windows.h>

#include <string>
#include <vector>

#include "win_raii.h"

namespace Util
{
    std::string GetLastErrorAsString();
    HRESULT IsProcessNative(DWORD pid, PBOOL result);
    HRESULT EnumProcessThreads(DWORD pid, std::vector<DWORD>& ThreadIDs);
    DWORD FindAlertableThread(const RAII::HandlePtr& hProcess);
}