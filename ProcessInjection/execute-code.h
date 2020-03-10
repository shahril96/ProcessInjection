#pragma once

#include <Windows.h>

#include "util.h"
#include "win_raii.h"

namespace ExecuteCode
{
	HRESULT CreateRemoteThread_LoadLibrary(
		const RAII::HandlePtr& hProcess,
		PVOID Argv
	);

	HRESULT APC_Injection(
		const RAII::HandlePtr& hProcess,
		PVOID Argv
	);

	HRESULT SuspendThreadResume(
		const RAII::HandlePtr& hProcess,
		PVOID Argv
	);
};