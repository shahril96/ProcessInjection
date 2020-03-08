
#include <iostream>

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
	RAII::VirtualAllocEx dllPathMem;

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

	dllPathMem.reset(hProcess.get(), dllPath.size());

	if (dllPathMem.isError()) {
		return E_FAIL;
	}

	bRet = ::WriteProcessMemory(
		hProcess.get(),
		dllPathMem.get(),
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

	hRet = ExecuteCode::CreateRemoteThread_LoadLibrary(hProcess, dllPathMem.get());

	return SUCCEEDED(hRet);
}

HRESULT Injector::WriteProcessMemory_APCInjector(
	DWORD pid,
	const std::string& dllPath
)
{
	BOOL    bRet;
	HRESULT hRet;
	RAII::VirtualAllocEx dllPathMem;

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

	dllPathMem.reset(hProcess.get(), dllPath.size());

	if (dllPathMem.isError()) {
		return E_FAIL;
	}

	bRet = ::WriteProcessMemory(
		hProcess.get(),
		dllPathMem.get(),
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

	hRet = ExecuteCode::APC_Injection(hProcess, dllPathMem.get());

	return SUCCEEDED(hRet);
}

HRESULT Injector::WriteProcessMemory_SuspendThreadResume(
	DWORD pid,
	const std::string& dllPath
)
{
	HRESULT hRet;
	BOOL    bRet;
	DWORD   dRet;
	BOOL    ExitSignal = FALSE;
	
	std::vector<DWORD>   ThreadID;
	CONTEXT				 ctx;
	CONTEXT				 OriginalContext;
	Util::ModuleInfoList ModuleInfoList;

	std::wstring				TargetBaseName(MAX_PATH, L'\0');
	

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

	hRet = Util::enumProcessThreads(GetProcessId(hProcess.get()), &ThreadID);

	if (FAILED(hRet)) {
		printf("Failed to enumerate target process threads\n");
		return E_FAIL;
	}

	RAII::VirtualAllocEx ShellcodeBuf(
		hProcess.get(),
		0x1024,
		PAGE_EXECUTE_READWRITE
	);

	//
	// TODO: when injector exit, OS automatically calls VirtualFreeEx()
	//       decommitting page and zeroing all the data in the page.
	//
	//       find a way to prevent OS from zeroing the area.
	//

	if (ShellcodeBuf.isError()) {
		printf("Failed to allocate memory into the target process\n");
		return E_FAIL;
	}

	printf("shellcode addr: %p\n", ShellcodeBuf.addr);

#ifdef _WIN64


	// TODO: validate shellcode correctness
	BYTE shellcode[] = {
		0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// movabs rcx, <dll-path>
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// movabs rax, <loadlibrarya>
		0xFF, 0xD0,														// call rax
		0xEB, 0xFE														// self-loop
	};

	*(PVOID*)(shellcode +  2) = (PVOID) dllPathMem.get(); // dll path
	*(PVOID*)(shellcode + 12) = (PVOID) GetProcAddress(  // Kernel32.dll!LoadLibraryA
		GetModuleHandle(L"Kernel32.dll"),
		"LoadLibraryA"
	);

#else

	BYTE shellcode[0x1024] = {
		0xB8, 0x00, 0x00, 0x00, 0x00,		// movabs eax, <dll-path>
		0x50,								// push eax
		0xB8, 0x00, 0x00, 0x00, 0x00,		// movabs eax, <loadlibrarya>
		0xFF, 0xD0,							// call eax
		0xEB, 0xFE							// self-loop
	};

	// copy dll path into our shellcode
	memcpy(shellcode + 15, dllPath.c_str(), dllPath.size());

	*(PVOID*)(shellcode + 1) = (PVOID) ((PBYTE)ShellcodeBuf.get() + 15); // dll path
	*(PVOID*)(shellcode + 7) = (PVOID) GetProcAddress(   // Kernel32.dll!LoadLibraryA
		GetModuleHandle(L"Kernel32.dll"),
		"LoadLibraryA"
	);

#endif

	bRet = ::WriteProcessMemory(
		hProcess.get(),
		ShellcodeBuf.get(),
		shellcode,
		sizeof shellcode,
		NULL
	);

	if (!bRet) {
		printf(
			"WriteProcessMemory: %s\n",
			Util::getLastErrorAsString().c_str()
		);
		return E_FAIL;
	}

	// 
	// check entrypoint of the thread
	//
	// if thread is started not from our target process, then don't inject
	//
	// this is to improve stability, as thread starting from important module
	// might crash if we try to "disturb" its thread context
	//

	hRet = Util::enumModuleInfo(hProcess.get(), &ModuleInfoList);

	if (FAILED(hRet) || ModuleInfoList.empty()) {
		printf("Failed to enumerate target process module info\n");
		return E_FAIL;
	}

	dRet = GetModuleBaseName(
		hProcess.get(),
		NULL,
		&TargetBaseName[0],
		TargetBaseName.size() * sizeof(TargetBaseName[0])
	);
	if (!dRet) false;

	// resize accordingly with true size
	TargetBaseName.resize(dRet);

	ThreadID.erase(
		std::remove_if(ThreadID.begin(), ThreadID.end(), [&](const DWORD tid) -> bool {

			PVOID ThreadStartAddress;
		
			hRet = Util::getThreadStartAddress(tid, &ThreadStartAddress);
			if (FAILED(hRet)) false;

			// get MODULEINFO for target process
			MODULEINFO ProcessModuleInfo = ModuleInfoList[TargetBaseName];

			size_t StartAddress = (size_t)ProcessModuleInfo.lpBaseOfDll;
			size_t EndAddress = (size_t)ProcessModuleInfo.lpBaseOfDll + (size_t)ProcessModuleInfo.SizeOfImage;

			// check if start address is out from main target module address range
			if ((size_t)ThreadStartAddress < StartAddress || EndAddress <= (size_t)ThreadStartAddress) {
				return false;
			}

			return true;
		})
	);

	for (const DWORD tid : ThreadID)
	{
		ZeroMemory(&ctx, sizeof ctx);

		// jgn lupa, tid! bukan pid bodo
		RAII::HandlePtr hThread{
			::OpenThread(
				THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
				NULL,
				tid
			)
		};

		if (!hThread.get()) continue;

		dRet = ::SuspendThread(hThread.get());
		if (FAILED(dRet)) continue;

		ctx.ContextFlags = CONTEXT_ALL;
		bRet = ::GetThreadContext(hThread.get(), &ctx);
		if (!bRet) continue;

		OriginalContext = ctx;

#ifdef _WIN64
		ctx.Rip = (DWORD64) ShellcodeBuf.get();
#else
		ctx.Eip = (DWORD) ShellcodeBuf.get();
#endif

		// set thread with our modified thread context
		bRet = ::SetThreadContext(hThread.get(), &ctx);
		if (!bRet) continue;

		dRet = ::ResumeThread(hThread.get());
		if (FAILED(dRet)) continue;

		//
		// TODO: if lower, then target process will crash
		// because suddenly the shellcode area is suddenly emptied...
		// might possible that virtualFree() completely wipe the area
		//
		// NOTE: find a way to replace this hack
		//
		Sleep(100);

		dRet = ::SuspendThread(hThread.get());
		if (FAILED(dRet)) continue;

		ctx.ContextFlags = CONTEXT_ALL;
		bRet = ::GetThreadContext(hThread.get(), &ctx);
		if (!bRet) continue;

#ifdef _WIN64
		ExitSignal = (DWORD64)ShellcodeBuf.get() + sizeof(shellcode) - 2 == ctx.Rip;
#else
		printf("Eip = %p\n", ctx.Eip);
		ExitSignal = (DWORD)ShellcodeBuf.get() != ctx.Eip;
#endif

		bRet = ::SetThreadContext(hThread.get(), &OriginalContext);
		if (!bRet) continue;

		dRet = ::ResumeThread(hThread.get());
		if (FAILED(dRet)) continue;

		if (ExitSignal) {
			printf("\n");
			printf("Gained code execution with thread [0x%x]\n", tid);
			break;
		}
	}

	return ExitSignal ? S_OK : E_FAIL;
}