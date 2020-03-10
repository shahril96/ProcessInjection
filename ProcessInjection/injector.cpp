
#include <iostream>

#include <string>

#include <Windows.h>
#include <conio.h>

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

	if (dllPathMem.error) {
		return E_FAIL;
	}

	bRet = ::WriteProcessMemory(
		hProcess.get(),
		dllPathMem.addr,
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

	hRet = ExecuteCode::CreateRemoteThread_LoadLibrary(hProcess, dllPathMem.addr);

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

	if (dllPathMem.error) {
		return E_FAIL;
	}

	bRet = ::WriteProcessMemory(
		hProcess.get(),
		dllPathMem.addr,
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

	hRet = ExecuteCode::APC_Injection(hProcess, dllPathMem.addr);

	return SUCCEEDED(hRet);
}

HRESULT Injector::WriteProcessMemory_SuspendThreadResume(
	DWORD pid,
	const std::string& dllPath
)
{
	HRESULT			     hRet;
	BOOL				 bRet;
	PVOID                LoadLibraryPtr;
	BOOL				 ExitSignal = FALSE;
	BOOL				 IpMoved    = FALSE;
	std::vector<DWORD>   ThreadID;
	CONTEXT				 ctx;
	CONTEXT				 OriginalContext;
	Util::ModuleInfoList ModuleInfoList;
	std::wstring		 TargetBaseName(MAX_PATH, L'\0');
	
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

	//
	// find writable address which is aligned with 16-bytes
	//
	// this is because we're imitating the stack, so we need
	// to align to avoid problem with modern CPU instructions
	//

	PVOID WritableAddress = Util::findWritableAddress(hProcess.get(), 0x512, 16);

	if (!WritableAddress) {
		printf("Failed to find writable buffer to hold ROP gadget\n");
		return E_FAIL;
	}

	//
	// BELOW EXPERIMENT
	//

	LoadLibraryPtr = (PVOID)GetProcAddress(  // Kernel32.dll!LoadLibraryA
		GetModuleHandle(L"Kernel32.dll"),
		"LoadLibraryA"
	);

	// general
	PVOID PushSpRet;
	PVOID SelfLoop;

	// x86
	PVOID PopEaxRet;
	PVOID CallEaxRet;

	// x64
	PVOID PopRaxRet;
	PVOID CallRaxRet;


#ifdef _WIN64

	// TODO: validate shellcode correctness
	BYTE shellcode[0x1024] = {
		0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// movabs rcx, <dll-path>
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// movabs rax, <loadlibrarya>
		0xFF, 0xD0,														// call rax
		0xEB, 0xFE														// self-loop
	};

	// copy dll path into our shellcode
	memcpy(shellcode + 24, dllPath.c_str(), dllPath.size());

	*(PVOID*)(shellcode +  2) = (PVOID)((PBYTE)ShellcodeBuf.get() + 24); // dll path
	*(PVOID*)(shellcode + 12) = (PVOID) GetProcAddress(  // Kernel32.dll!LoadLibraryA
		GetModuleHandle(L"Kernel32.dll"),
		"LoadLibraryA"
	);

#else

	PushSpRet  = Util::findInstruction(hProcess.get(), "\x5C\xC3");      // pop esp; ret
	SelfLoop   = Util::findInstruction(hProcess.get(), "\xEB\xFE");      // jmp short -2
	PopEaxRet  = Util::findInstruction(hProcess.get(), "\x58\xC3");      // pop eax; ret
	CallEaxRet = Util::findInstruction(hProcess.get(), "\xFF\xD0\xC3");  // call eax; ret

	if (!PushSpRet || !SelfLoop || !PopEaxRet || !CallEaxRet) {
		printf("Failed to find ROP gadgets\n");
		return E_FAIL;
	}

	printf("\n");
	printf("Writable mem  -> %p\n", WritableAddress);
	printf("\n");
	printf("Gadget address\n");
	printf("----------------\n");
	printf("pop esp; ret  -> %p | %s\n", PushSpRet, Util::getSymbolFromAddress(hProcess.get(), PushSpRet).c_str());
	printf("jmp short -2  -> %p | %s\n", SelfLoop, Util::getSymbolFromAddress(hProcess.get(), SelfLoop).c_str());
	printf("pop eax; ret  -> %p | %s\n", PopEaxRet, Util::getSymbolFromAddress(hProcess.get(), PopEaxRet).c_str());
	printf("call eax; ret -> %p | %s\n", CallEaxRet, Util::getSymbolFromAddress(hProcess.get(), CallEaxRet).c_str());

	PVOID RopGadgets[0x512 / sizeof(PVOID)] = { 0 };
	PVOID DLLPathAddress = (PBYTE)WritableAddress + 5 * sizeof(PVOID);

	RopGadgets[0] = PopEaxRet;		// pop eax; ret
	RopGadgets[1] = LoadLibraryPtr; //		<argv> -- <loadLibraryA>
	RopGadgets[2] = CallEaxRet;		// call eax; ret
	RopGadgets[3] = DLLPathAddress;	//		<argv> -- dll path
	RopGadgets[4] = SelfLoop;		// <self-loop>

	// copy dll path to the end of ROP gadgets
	memcpy_s(
		&RopGadgets[5],
		sizeof(RopGadgets) - (&RopGadgets[5] - RopGadgets),
		&dllPath[0],
		dllPath.size()
	);

#endif

	bRet = ::WriteProcessMemory(
		hProcess.get(),
		WritableAddress,
		RopGadgets,
		sizeof(RopGadgets[0]) * 5 + dllPath.size(),
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

	/*hRet = Util::enumModuleInfo(hProcess.get(), &ModuleInfoList);

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
	);*/

	printf("\nFound %d thread(s)\n\n", ThreadID.size());

	for (const DWORD tid : ThreadID)
	{
		ZeroMemory(&ctx, sizeof ctx);
		ExitSignal = FALSE;

		RAII::HandlePtr hThread{
			::OpenThread(
				THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
				NULL,
				tid
			)
		};

		if (!hThread.get()) continue;

		RAII::SuspendThread suspend_thread(hThread.get());
		if (suspend_thread.m_error) continue;

		ctx.ContextFlags = CONTEXT_ALL;
		bRet = ::GetThreadContext(hThread.get(), &ctx);

		if (!bRet) continue;

		OriginalContext = ctx;

#ifdef _WIN64
		ctx.Rip = (DWORD64)PushSpRet;
		ctx.Rsp -= sizeof(PVOID);       // allocate area for ROP gadget
#else
		ctx.Eip = (DWORD)PushSpRet;
		ctx.Esp -= sizeof(PVOID);       // allocate area for ROP gadget
#endif

		//
		// NOTE:
		// how to fix this fuckup
		// ideas:
		//
		// 1) check threads start base address, if it is coming from
		//    let say ntdll, then it might be not safe to suspend
		//    the thread
		//    
		//    NOTE: walk up the stack, check if value in stack is
		//          address and it points to executable page
		//
		// 2) redo the ROP gadget. return back to previous code and
		//    continue execution after we've finished our DLL loading
		//
		//   NOTE: concern about how to know if our DLL is loaded is 
		//         simple. if let say, we set context to thread and 
		//         resume it back. If it doesn't work, IP register
		//         will not move. If it does, our code does work
		//         but then it is up to the program if it crashes
		//         or not.
		//
		//   IDEA: maybe we don't need to suspend/resume at all
		//         to check if our thread IP reg moves. If it doesn't
		//         move, then every registers will not affect either.
		//         This is just a theory, we need to test this.
		//
		// 3) check if we need to align the stack into 16-byte, this
		//    is especially important if library code uses modern CPU
		//    instruction (eq; FPU)
		//   Ref: https://stackoverflow.com/a/53519429/1768052
		//   UPDATE: succeed
		//

		// write trampoline addr to stack
		bRet = ::WriteProcessMemory(
			hProcess.get(),
#ifdef _WIN64
			(PVOID) ctx.Rsp,
#else
			(PVOID) ctx.Esp,
#endif
			&WritableAddress,
			sizeof(PVOID),
			NULL
		);

		if (!bRet) {
			printf(
				"WriteProcessMemory: %s\n",
				Util::getLastErrorAsString().c_str()
			);
			continue;
		}

		// set thread with our modified thread context
		suspend_thread.set_context(&ctx);

		// resume thread here
		suspend_thread.resume();

		DWORD total_sleep = 0;
		DWORD counter = 1;

		// control 
		const DWORD SLEEP_TIME_PER_WAIT = 1000;
		const DWORD SLEEP_TOTAL_LIMIT   = 3000;

		do {

			Sleep(SLEEP_TIME_PER_WAIT);

			//RAII::SuspendThread suspend_thread(hThread.get());
			//if (suspend_thread.error) break;

			ctx.ContextFlags = CONTEXT_ALL;
			bRet = ::GetThreadContext(hThread.get(), &ctx);
			if (!bRet) break;

			// resume immediately
			//suspend_thread.resume();

			printf(
				"\rThread 0x%05x [Trial: %d/%d] - IP: %p | %s",
				tid,
				counter,
				SLEEP_TOTAL_LIMIT / SLEEP_TIME_PER_WAIT,
#ifdef _WIN64
				(PVOID) ctx.Rip,
				Util::GetSymbolFromAddr(hProcess.get(), (PVOID)ctx.Rip).c_str()
#else
				(PVOID)ctx.Eip,
				Util::getSymbolFromAddress(hProcess.get(), (PVOID)ctx.Eip).c_str()
#endif
			);

#ifdef _WIN64
			ExitSignal = (DWORD64)SelfLoop == ctx.Rip;
#else
			IpMoved    = ctx.Eip != (DWORD) PushSpRet;
			ExitSignal = ctx.Eip == (DWORD) SelfLoop;
#endif
			total_sleep += SLEEP_TIME_PER_WAIT;
			counter++;

			if (IpMoved)
			{
				printf("\n");
				printf("\n");
				printf("Instruction pointer in thread [0x%x] moved\n", tid);
				printf("DllMain is currently blocking the hijacked thread\n");
				printf("\n");
				printf("Wait or finish up the DllMain execution\n");
				printf("Then press any button to restore thread context\n");
				printf("\n");
				printf("Don't continue if DllMain is not finished, or else crash will happen\n");
				printf("\n");

				// block current thread execution
				_getch();

				break;
			}

		} while (!ExitSignal && total_sleep < SLEEP_TOTAL_LIMIT);

		printf("\n");

		if (ExitSignal || IpMoved) {
			printf("\n");
			printf("Gained code execution with thread [0x%x]\n", tid);
			printf("\n");
			break;
		}
	}

	return ExitSignal ? S_OK : E_FAIL;
}