
#include <Windows.h>

#include "execute-code.h"

HRESULT ExecuteCode::CreateRemoteThread_LoadLibrary(
	const RAII::HandlePtr& hProcess,
	LPVOID ArgvAddr
)
{
	LPVOID LoadLibraryProc;

	LoadLibraryProc = (LPVOID)GetProcAddress(
		GetModuleHandle(L"kernel32.dll"), 
		"LoadLibraryA"
	);

	if (!LoadLibraryProc) {
		printf("GetProcAddress: %s\n", Util::GetLastErrorAsString().c_str());
		return E_FAIL;
	}

	//
	// Create remote thread in target process
	// with "LoadLibraryA" as its code execution address
	//
	
	RAII::HandlePtr hThread{
		CreateRemoteThread(
			hProcess.get(),
			NULL,
			0,
			(LPTHREAD_START_ROUTINE)LoadLibraryProc,
			ArgvAddr,
			0,
			NULL
		)
	};

	if (!hThread.get()) {
		printf("CreateRemoteThread: %s\n", Util::GetLastErrorAsString().c_str());
		return E_FAIL;
	}

	return S_OK;
}

HRESULT ExecuteCode::APC_Injection(
	const RAII::HandlePtr& hProcess,
	LPVOID ArgvAddr
)
{
	DWORD dRet;
	DWORD AlertableTid;
	LPVOID LoadLibraryProc;
	
	LoadLibraryProc = (LPVOID)GetProcAddress(
		GetModuleHandle(L"kernel32.dll"),
		"LoadLibraryA"
	);

	if (!LoadLibraryProc) {
		printf(
			"GetProcAddress: %s\n",
			Util::GetLastErrorAsString().c_str()
		);
		return E_FAIL;
	}

	// Find if they are any alertable thread in the process
	AlertableTid = Util::FindAlertableThread(hProcess);

	if (!AlertableTid) {
		printf(
			"Failed to find any alertable thread in PID [%d]\n", 
			::GetProcessId(hProcess.get())
		);
		return E_FAIL;
	}

	RAII::HandlePtr hThread(
		OpenThread(THREAD_SET_CONTEXT, FALSE, AlertableTid)
	);

	// Queue our APC into target alertable thread
	dRet = QueueUserAPC(
		(PAPCFUNC)LoadLibraryProc,
		hThread.get(),
		(ULONG_PTR)ArgvAddr
	);

	if (!dRet) {
		printf(
			"QueueUserAPC: %s\n",
			Util::GetLastErrorAsString().c_str()
		);
		return E_FAIL;
	}

	return S_OK;
}