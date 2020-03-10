
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
		printf(
			"GetProcAddress: %s\n",
			Util::getLastErrorAsString().c_str()
		);
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
		printf(
			"CreateRemoteThread: %s\n",
			Util::getLastErrorAsString().c_str()
		);
		return E_FAIL;
	}

	return S_OK;
}

HRESULT ExecuteCode::APC_Injection(
	const RAII::HandlePtr& hProcess,
	LPVOID ArgvAddr
)
{
	DWORD  dRet;
	DWORD  AlertableTid;
	LPVOID LoadLibraryProc;
	
	LoadLibraryProc = (LPVOID)::GetProcAddress(
		::GetModuleHandle(L"kernel32.dll"),
		"LoadLibraryA"
	);

	if (!LoadLibraryProc) {
		printf(
			"GetProcAddress: %s\n",
			Util::getLastErrorAsString().c_str()
		);
		return E_FAIL;
	}

	// Find if they are any alertable thread in the process
	AlertableTid = Util::findAlertableThread(hProcess.get());

	if (!AlertableTid) {
		printf(
			"Failed to find any alertable thread in PID [0x%x]\n", 
			::GetProcessId(hProcess.get())
		);
		return E_FAIL;
	}

	RAII::HandlePtr hThread(
		::OpenThread(THREAD_SET_CONTEXT, FALSE, AlertableTid)
	);

	if (!hThread.get()) {
		printf(
			"OpenThread: %s\n",
			Util::getLastErrorAsString().c_str()
		);
		return E_FAIL;
	}

	// Queue our APC into target alertable thread
	dRet = ::QueueUserAPC(
		(PAPCFUNC)LoadLibraryProc,
		hThread.get(),
		(ULONG_PTR)ArgvAddr
	);

	if (!dRet) {
		printf(
			"QueueUserAPC: %s\n",
			Util::getLastErrorAsString().c_str()
		);
		return E_FAIL;
	}

	return S_OK;
}

HRESULT ExecuteCode::SuspendThreadResume(
	const RAII::HandlePtr& hProcess,
	PVOID Argv
)
{
	BOOL				bRet;
	DWORD				dRet;
	CONTEXT				ctx = { 0 };
	std::vector<DWORD>  ThreadIDs;

	Util::enumProcessThreads(
		::GetProcessId(hProcess.get()),
		&ThreadIDs
	);

	if (ThreadIDs.empty()) {
		printf("Util::EnumProcessThreads(): Failed to get list of threads\n");
		return E_FAIL;
	}

	// TODO!: currently using last element as chosen thread, which is not safe
	// RESEARCH: how to pick up the good thread (which will not affect the entire program)
	RAII::HandlePtr hThread(
		::OpenThread(
			THREAD_GET_CONTEXT | THREAD_SET_CONTEXT 
			| THREAD_SUSPEND_RESUME,
			FALSE,
			ThreadIDs.back()
		)
	);

	if (!hThread.get()) {
		printf(
			"OpenThread: %s\n",
			Util::getLastErrorAsString().c_str()
		);
		return E_FAIL;
	}

	dRet = ::SuspendThread(hThread.get());

	if (FAILED(dRet)) {
		printf(
			"SuspendThread: %s\n",
			Util::getLastErrorAsString().c_str()
		);
		return E_FAIL;
	}

	ctx.ContextFlags = CONTEXT_ALL;
	bRet = ::GetThreadContext(hThread.get(), &ctx);

	if (!bRet) {
		printf(
			"GetThreadContext: %s\n",
			Util::getLastErrorAsString().c_str()
		);
		return E_FAIL;
	}

#ifdef _WIN64
	
	printf("\n\n");
	printf("rax = 0x%llx\n", ctx.Rax);
	printf("rbx = 0x%llx\n", ctx.Rbx);
	printf("rcx = 0x%llx\n", ctx.Rcx);
	printf("rdx = 0x%llx\n", ctx.Rdx);
	printf("\n");

#else

	printf("\n\n");
	printf("eax = 0x%x\n", ctx.Eax);
	printf("ebx = 0x%x\n", ctx.Ebx);
	printf("ecx = 0x%x\n", ctx.Ecx);
	printf("edx = 0x%x\n", ctx.Edx);
	printf("\n");



#endif

	return S_OK;
}