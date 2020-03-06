


#include <string>

#include <Windows.h>

#include "execute-code.h"
#include "win_raii.h"
#include "util.h"
#include "injector.h"


HRESULT Injector::WriteProcessMemory_CreateRemoteThread(
	DWORD pid,
	const std::string& dllPath
)
{
	BOOL    bRet;
	HRESULT hRet;
	RAII::VirtualAllocExWrapper MemAddr;

	RAII::HandlePtr hProcess{
		::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)
	};

	if (!hProcess.get()) {
		printf(
			"OpenProcess: %s\n",
			Util::getLastErrorAsString().c_str()
		);
		return E_FAIL;
	}

	MemAddr.reset(hProcess.get(), dllPath.size());

	if (MemAddr.isError()) {
		return E_FAIL;
	}

	bRet = ::WriteProcessMemory(
		hProcess.get(),
		MemAddr.get(),
		dllPath.c_str(),
		dllPath.size(),
		NULL
	);

	if (!bRet) {
		printf(
			"WriteProcessMemory: %s\n",
			Util::getLastErrorAsString().c_str()
		);
	}

	hRet = ExecuteCode::CreateRemoteThread_LoadLibrary(hProcess, MemAddr.get());

	return SUCCEEDED(hRet);
}

HRESULT Injector::WriteProcessMemory_APCInjector(
	DWORD pid,
	const std::string& dllPath
)
{
	BOOL    bRet;
	HRESULT hRet;
	RAII::VirtualAllocExWrapper MemAddr;

	RAII::HandlePtr hProcess{
		::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)
	};

	if (!hProcess.get()) {
		printf(
			"OpenProcess: %s\n",
			Util::getLastErrorAsString().c_str()
		);
		return E_FAIL;
	}

	MemAddr.reset(hProcess.get(), dllPath.size());

	if (MemAddr.isError()) {
		return E_FAIL;
	}

	bRet = ::WriteProcessMemory(
		hProcess.get(),
		MemAddr.get(),
		dllPath.c_str(),
		dllPath.size(),
		NULL
	);

	if (!bRet) {
		printf(
			"WriteProcessMemory: %s\n",
			Util::getLastErrorAsString().c_str()
		);
	}

	hRet = ExecuteCode::APC_Injection(hProcess, MemAddr.get());

	return SUCCEEDED(hRet);
}

HRESULT Injector::WriteProcessMemory_SuspendThreadResume(
	DWORD pid,
	const std::string& dllPath
)
{
	HRESULT hRet;
	BOOL    bRet;
	RAII::VirtualAllocExWrapper MemAddr;

	RAII::HandlePtr hProcess{
		::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)
	};

	if (!hProcess.get()) {
		printf(
			"OpenProcess: %s\n",
			Util::getLastErrorAsString().c_str()
		);
		return E_FAIL;
	}

	MemAddr.reset(hProcess.get(), dllPath.size());

	if (MemAddr.isError()) {
		return E_FAIL;
	}

	bRet = ::WriteProcessMemory(
		hProcess.get(),
		MemAddr.get(),
		dllPath.c_str(),
		dllPath.size(),
		NULL
	);

	if (!bRet) {
		printf(
			"WriteProcessMemory: %s\n",
			Util::getLastErrorAsString().c_str()
		);
	}

	// search for "pop esp; ret"
	std::vector<LPVOID> GadgetList;
	hRet = Util::findInstruction(hProcess, GadgetList, "5C C3");

	if (FAILED(hRet)) {
		printf("Failed to find ROP gadget in the target process memory space\n");
		return E_FAIL;
	}

	printf("Found (%u) rop gadget!\n", GadgetList.size());

	//hRet = ExecuteCode::SuspendThreadResume(hProcess, MemAddr.get());

	return SUCCEEDED(hRet);
}