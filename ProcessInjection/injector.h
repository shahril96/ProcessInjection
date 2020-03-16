
#include "Common.h"
#include "Process/Process.h"

namespace Injector
{
	HRESULT WriteProcessMemory_CreateRemoteThread(
		Process::Process process,
		const std::string& dllPath
	)
	{
		// allocate memory on target process
		Process::RAII::allocateMemory buffer = process.allocate(dllPath.size() + 1);

		// write our dll path into target memory
		process.writeMemory(*buffer, (PVOID)dllPath.c_str(), dllPath.size() + 1);

		// run LoadLibraryA(dll) in remote process through ::CreateRemoteThread()
		Process::Thread RemoteThread = process.CreateRemoteThread(
			Process::getFunctionAddress(L"Kernel32.dll", "LoadLibraryA"),
			*buffer
		);

		//
		// TODO: check thread state after execution
		//

		//return SUCCEEDED(hRet);

		return 0;
	}

	HRESULT WriteProcessMemory_APCInjector(
		Process::Process process,
		const std::string& dllPath
	)
	{
		DWORD dwRet;

		// allocate memory on target process
		Process::RAII::allocateMemory buffer = process.allocate(dllPath.size() + 1);

		// write our dll path into target memory space
		process.writeMemory(*buffer, (PVOID)dllPath.c_str(), dllPath.size() + 1);

		// do APC injection to the target process
		dwRet = process.APC_Injection(
			Process::getFunctionAddress(L"Kernel32.dll", "LoadLibraryA"),
			*buffer
		);

		return !dwRet ? S_OK : E_FAIL;
	}

	HRESULT WriteProcessMemory_SuspendThreadResume(
		Process::Process process,
		const std::string& dllPath
	)
	{
		DWORD               dwRet;
		BOOL				ExitSignal = FALSE;
		BOOL				IpMoved = FALSE;
		std::vector<DWORD>  ThreadID;
		CONTEXT				ctx;
		CONTEXT				OriginalContext;
		std::wstring		TargetBaseName(MAX_PATH, L'\0');

		//
		// find writable address which is aligned with 16-bytes
		//
		// this is because we're imitating the stack, so we need
		// to align to avoid problem with modern CPU instructions
		//

		PVOID WritableAddress = process.findWritableAddress(0x512, 16);

		if (!WritableAddress) {
			printf("Failed to find writable buffer to hold ROP gadget\n");
			return E_FAIL;
		}

		//
		// BELOW EXPERIMENT
		//

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

		//
		//
		//

#else

		PushSpRet = process.findInstruction("\x5C\xC3");      // pop esp; ret
		SelfLoop = process.findInstruction("\xEB\xFE");      // jmp short -2
		PopEaxRet = process.findInstruction("\x58\xC3");      // pop eax; ret
		CallEaxRet = process.findInstruction("\xFF\xD0\xC3");  // call eax; ret

		if (!PushSpRet || !SelfLoop || !PopEaxRet || !CallEaxRet) {
			printf("Failed to find ROP gadgets\n");
			return E_FAIL;
		}

#ifdef _DEBUG

		printf("\n");
		printf("Writable mem  -> %p\n", WritableAddress);
		printf("\n");
		printf("Gadget address\n");
		printf("----------------\n");
		printf("pop esp; ret  -> %p | %s\n", PushSpRet, process.getSymbolFromAddress(PushSpRet).c_str());
		printf("jmp short -2  -> %p | %s\n", SelfLoop, process.getSymbolFromAddress(SelfLoop).c_str());
		printf("pop eax; ret  -> %p | %s\n", PopEaxRet, process.getSymbolFromAddress(PopEaxRet).c_str());
		printf("call eax; ret -> %p | %s\n", CallEaxRet, process.getSymbolFromAddress(CallEaxRet).c_str());

#endif

		PVOID RopGadgets[0x512 / sizeof(PVOID)] = { 0 };
		PVOID DLLPathAddress = (PBYTE)WritableAddress + 5 * sizeof(PVOID);
		PVOID LoadLibraryPtr = Process::getFunctionAddress(L"Kernel32.dll", "LoadLibraryA");

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

		process.writeMemory(
			WritableAddress,
			RopGadgets,
			sizeof(RopGadgets[0]) * 5 + dllPath.size()
		);


		Process::ThreadList_t ThreadList = process.getThreadList();

		printf("\nFound %d thread(s)\n\n", ThreadList.size());

		for (auto& [tid, thread] : ThreadList)
		{
			ExitSignal = FALSE;

			//
			// EXPERIMENT
			//

			// check if thread is suspended even after resuming
			//Util::isThreadSuspended(tid);

			//break;

			dwRet = thread.Suspend();

			if (dwRet == (DWORD)-1) {
				continue;
			}

			ctx = thread.getContext();

			OriginalContext = ctx;  // backup original context

#ifdef _WIN64
			PVOID OriginalIP = (PVOID)ctx.Rip;
			ctx.Rip = (DWORD64)PushSpRet;
			ctx.Rsp -= sizeof(PVOID);       // allocate area for ROP gadget
#else
			PVOID OriginalIP = (PVOID)ctx.Eip;
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
		//		UPDATE: done, but i check for current EIP not in ntdll, not call stack
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
		//			UPDATE: DONE
		//
		//	 IDEA: Maybe after resuming, we check status of thread after
		//         that. If thread is stuck (EIP not moving), maybe
		//         can we know from there.
		//
		// 3) check if we need to align the stack into 16-byte, this
		//    is especially important if library code uses modern CPU
		//    instruction (eq; FPU)
		//   Ref: https://stackoverflow.com/a/53519429/1768052
		//   
		//		UPDATE: DONE
		//


			process.writeMemory(
#ifdef _WIN64
			(PVOID) ctx.Rsp,
#else
				(PVOID)ctx.Esp,
#endif
				& WritableAddress,
				sizeof(PVOID)
			);

			//
			// set our custom context and resume thread
			//

			thread.setContext(&ctx);
			dwRet = thread.Resume();

			if (dwRet == (DWORD)-1) {
				continue;
			}

			//
			// now we want to check its progression (whether it works or not)
			//

			DWORD total_sleep = 0;
			DWORD counter = 1;

			// control 
			const DWORD SLEEP_TIME_PER_WAIT = 1000;
			const DWORD SLEEP_TOTAL_LIMIT = 3000;

			printf("Thread 0x%05x:\n", tid);
			printf("  -> Original IP  : %p | %s\n",
				OriginalIP,
				process.getSymbolFromAddress(OriginalIP).c_str()
			);


			do {

				Sleep(SLEEP_TIME_PER_WAIT);

				ctx = thread.getContext();

				printf(
					"\r  -> Current IP   : %p | %-20s (%d/%d)",
#ifdef _WIN64
					(PVOID) ctx.Rip,
					process.getSymbolFromAddress((PVOID)ctx.Rip).c_str(),
#else
					(PVOID)ctx.Eip,
					process.getSymbolFromAddress((PVOID)ctx.Eip).c_str(),
#endif
					counter,
					SLEEP_TOTAL_LIMIT / SLEEP_TIME_PER_WAIT
				);

#ifdef _WIN64
				ExitSignal = (DWORD64)SelfLoop == ctx.Rip;
#else
				IpMoved = ctx.Eip != (DWORD)PushSpRet;
				ExitSignal = ctx.Eip == (DWORD)SelfLoop;
#endif
				total_sleep += SLEEP_TIME_PER_WAIT;
				counter++;

				if (IpMoved)
				{
					printf("\n\n");
					printf("IP in thread (0x%x) moved but not hitting our\n", tid);
					printf("end signal. Chance to succeed or crashed is equal\n");

					break;
				}

			} while (!ExitSignal && total_sleep < SLEEP_TOTAL_LIMIT);

			printf("\n");

			//
			// replace with ROP gadget that returns to main execution
			//
			//RAII::SuspendThread clean_context(hThread.get());
			//clean_context.set_context(&OriginalContext);
			//clean_context.resume();

			if (ExitSignal || IpMoved) {
				printf("Gained code execution within thread [0x%x]\n", tid);
				printf("\n");
				break;
			}
		}

		return ExitSignal ? S_OK : E_FAIL;
	}

};