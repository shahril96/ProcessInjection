#pragma once

#include <Windows.h>

#include <string>

namespace Injector
{
	HRESULT WriteProcessMemory_CreateRemoteThread(
		DWORD pid,
		const std::string& dllPath
	);

	HRESULT WriteProcessMemory_APCInjector(
		DWORD pid,
		const std::string& dllPath
	);
}