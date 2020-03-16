
#include "Common.h"
#include "Process/Process.h"

namespace Injector
{

	HRESULT WriteProcessMemory_CreateRemoteThread(
		Process::Process process,
		const std::string& dllPath
	)
	{
		DWORD dwRet;

		// allocate memory on target process
		Process::RAII::allocateMemory buffer = process.allocate(dllPath.size() + 1);

		// write our dll path into target memory
		process.writeMemory(*buffer, (PVOID)dllPath.c_str(), dllPath.size() + 1);

		// run LoadLibraryA(dll) in remote process through ::CreateRemoteThread()
		Process::Thread RemoteThread = process.CreateRemoteThread(
			Process::getFunctionAddress(L"Kernel32.dll", "LoadLibraryA"),
			*buffer
		);

		// wait until thread is terminated (signaled)
		// TODO: if thread is blocking (eq; GUI), then this will be an infinite wait
		dwRet = WaitForSingleObject(*RemoteThread, INFINITE);

		return dwRet == WAIT_OBJECT_0 ? S_OK : E_FAIL;
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
		DWORD    dwRet;
		BOOL	 ExitSignal = FALSE;
		BOOL	 IpMoved = FALSE;
		CONTEXT	 ctx;
		CONTEXT	 OriginalContext;

		// allocate memory in target process
		Process::RAII::allocateMemory RopGadgetMemory = process.allocate(0x1000);
		Process::RAII::allocateMemory DllPathMemory   = process.allocate(0x1000);

		// general
		PVOID PushSpRet;
		PVOID SelfLoop;
		PVOID PopAxRet;
		PVOID PopCxRet;

		// x86
		PVOID CallAxRet;

		// x64
		PVOID PushRaxJmpRbx;

		// both x86 and x64 uses the same opcodes
		PushSpRet  = process.findInstruction("\x5C\xC3");      // pop esp; ret
		SelfLoop   = process.findInstruction("\xEB\xFE");      // jmp short -2
		PopAxRet   = process.findInstruction("\x58\xC3");      // pop [e|r]ax; ret
		PopCxRet   = process.findInstruction("\x59\xC3");      // pop [e|r]cx; ret
		
#ifdef _WIN64

		PushRaxJmpRbx = process.findInstruction("\xFF\xD0\x90\x48\x83\xC4\x28\xC3"); 

		if (!PushSpRet || !SelfLoop || !PopAxRet || !PopCxRet || !PushRaxJmpRbx) {
			printf("Failed to find ROP gadgets\n");
			return E_FAIL;
		}

		PVOID  RopGadgets[0x512 / sizeof(PVOID)] = { 0 };
		PVOID  LoadLibraryPtr  = Process::getFunctionAddress(L"Kernel32.dll", "LoadLibraryA");
		PVOID  LoadLibraryLoc  = (PBYTE)*RopGadgetMemory + 7 * sizeof(PVOID);

		RopGadgets[0] = PopAxRet;        // pop rax; ret
		RopGadgets[1] = LoadLibraryPtr;  //		<argv> -- LoadLibraryPtr
		RopGadgets[2] = PopCxRet;        // pop rcx; ret
		RopGadgets[3] = *DllPathMemory;  //		<argv> -- dll path
		RopGadgets[4] = PushRaxJmpRbx;   // call rax; nop; add rsp, 0x28; ret; 
		RopGadgets[5] = NULL;
		RopGadgets[6] = NULL;
		RopGadgets[7] = NULL;            // 5 padding for "add rsp, 0x28"
		RopGadgets[8] = NULL;
		RopGadgets[9] = NULL;
		RopGadgets[10] = SelfLoop;

		// write dll path
		process.writeMemory(
			*DllPathMemory,
			(PVOID) &dllPath[0],
			dllPath.size()
		);

		// write rop gadgets
		process.writeMemory(
			*RopGadgetMemory,
			RopGadgets,
			11 * sizeof(RopGadgets[0])
		);

#else

		CallAxRet = process.findInstruction("\xFF\xD0\xC3");  // call [e|r]ax; ret
		
		if (!PushSpRet || !SelfLoop || !PopAxRet || !CallAxRet) {
			printf("Failed to find ROP gadgets\n");
			return E_FAIL;
		}

		size_t DllPathOffset = 64;

		PVOID RopGadgets[0x512 / sizeof(PVOID)] = { 0 };
		PVOID LoadLibraryPtr = Process::getFunctionAddress(L"Kernel32.dll", "LoadLibraryA");

		RopGadgets[0] = PopAxRet;		// pop eax; ret
		RopGadgets[1] = LoadLibraryPtr; //		<argv> -- <loadLibraryA>
		RopGadgets[2] = CallAxRet;		// call eax; ret
		RopGadgets[3] = *DllPathMemory;	//		<argv> -- dll path
		RopGadgets[4] = SelfLoop;		// <self-loop>

		// write dll pat
		process.writeMemory(
			*DllPathMemory,
			(PVOID)&dllPath[0],
			dllPath.size()
		);

		// write rop gadgets
		process.writeMemory(
			*RopGadgetMemory,
			RopGadgets,
			5 * sizeof(RopGadgets[0])
		);

#endif

		//
		// enumerate all threads in target process
		//

		Process::ThreadList_t ThreadList = process.getThreadList();

		printf("\nFound %d thread(s)\n\n", ThreadList.size());

		for (auto& [tid, thread] : ThreadList)
		{
			ExitSignal = FALSE;

			Process::ThreadState state = thread.getState();

			// continue if we find unsuitable thread
			if (
				state.state != Waiting ||
				state.wait_reason != DelayExecution &&
				state.wait_reason != UserRequest
				)
			{
				continue;
			}

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

			process.writeMemory(
#ifdef _WIN64
				(PVOID) ctx.Rsp,
#else
				(PVOID)ctx.Esp,
#endif
				&RopGadgetMemory.addr,
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
			// now we want to check hijacked thread progression (whether it works or not)
			//

			DWORD total_sleep = 0;
			DWORD counter = 1;

			// control on how to wait for thread to get "signaled"
			const DWORD SLEEP_TIME_PER_WAIT = 1000;
			const DWORD SLEEP_TOTAL_LIMIT = 3000;

			printf("Thread 0x%05x:\n", tid);
			printf("  -> Original IP  : %p | %s\n",
				OriginalIP,
				process.getSymbolFromAddress(OriginalIP).c_str()
			);

			// periodically check hijacked thread state
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
				IpMoved = ctx.Rip != (DWORD)PushSpRet;
				ExitSignal = (DWORD64)SelfLoop == ctx.Rip;
#else
				IpMoved = ctx.Eip != (DWORD)PushSpRet;
				ExitSignal = ctx.Eip == (DWORD)SelfLoop;
#endif
				total_sleep += SLEEP_TIME_PER_WAIT;
				counter++;

				if (!ExitSignal && IpMoved)
				{
					printf("\n\n");
					printf("IP in thread (0x%x) moved but not hitting our\n", tid);
					printf("end signal. Chance to succeed or crashed is equal\n");

					break;
				}

			} while (!ExitSignal && total_sleep < SLEEP_TOTAL_LIMIT);

			printf("\n");

			// restore thread original context
			thread.Suspend();
			thread.setContext(&OriginalContext);
			thread.Resume();

			if (ExitSignal || IpMoved) {
				printf("\n");
				printf("Gained code execution within thread [0x%x]\n", tid);
				printf("\n");
				break;
			}
		}

		return ExitSignal ? S_OK : E_FAIL;
	}

};