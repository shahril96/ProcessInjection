
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

	// status:
	//   x86 = minor possibility to crash
	//   x64 = high chance to crash
	//
	// TODO: just use direct shellcode instead of ROP gadgets
	//
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

		// x64
		PVOID PushRaxJmpRbx;

		// x86
		PVOID CallAxRet;

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
		size_t RopGagetSize   = 11 * sizeof(RopGadgets[0]);
		PVOID  LoadLibraryPtr = Process::getFunctionAddress(L"Kernel32.dll", "LoadLibraryA");
		PVOID  RopGadgetAddr  = (PVOID)((PBYTE)*RopGadgetMemory + RopGadgetMemory.size - RopGagetSize);

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
			RopGadgetAddr,
			RopGadgets,
			RopGagetSize
		);

#else

		CallAxRet = process.findInstruction("\xFF\xD0\xC3");  // call [e|r]ax; ret
		
		if (!PushSpRet || !SelfLoop || !PopAxRet || !CallAxRet) {
			printf("Failed to find ROP gadgets\n");
			return E_FAIL;
		}

		size_t DllPathOffset = 64;

		PVOID RopGadgets[0x512 / sizeof(PVOID)] = { 0 };
		size_t RopGagetSize  = 5 * sizeof(RopGadgets[0]);
		PVOID LoadLibraryPtr = Process::getFunctionAddress(L"Kernel32.dll", "LoadLibraryA");
		PVOID RopGadgetAddr  = (PVOID)((PBYTE)*RopGadgetMemory + RopGadgetMemory.size - RopGagetSize);

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
			RopGadgetAddr,
			RopGadgets,
			RopGagetSize
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

			//
			// DEBUG (don't remove until stable)
			//

			// HEURISTIC: if thread is too busy, avoid hijacking
			/*if (thread.getContextSwitchDelta(1000) > 0xa0)
			{
				printf("Thread too busy. Skipping...");

				// restore thread original context
				thread.setContext(&OriginalContext);
				thread.Resume();
				continue;
			}*/

			/*state = thread.getState();
			printf("\n");
			printf("[Before] State  = %s\n", state.state.c_str());
			printf("[Before] Reason = %s\n", state.wait_reason.c_str());
			printf("\n");*/

			//
			// END DEBUG
			//


			// continue if we find unsuitable thread
			if (
				state.state != "Waiting" ||
				state.wait_reason != "DelayExecution" &&
				state.wait_reason != "UserRequest"
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

			//
			// EXPERIMENT
			//


			/*
#ifdef _WIN64
			std::string modName = process.getModuleNameByVA((PVOID)ctx.Rip);
			std::string symbolName = process.getSymbolFromAddress((PVOID)ctx.Rip);
#else
			std::string modName = process.getModuleNameByVA((PVOID)ctx.Eip);
			std::string mod_name = process.getSymbolFromAddress((PVOID)ctx.Eip);
#endif

			printf(
				"\nStart address: %s\n",
				process.getSymbolFromAddress(thread.getEntryPointVA()).c_str()
			);

			
			printf("\n\nModule: %s\n\n", symbolName.c_str());
			
			if (!_stricmp(modName.c_str(), "ntdll.dll")) {
				thread.setContext(&OriginalContext);
				thread.Resume();
				continue;
			}*/

			//
			// END EXPERIMENT
			//

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
				&RopGadgetAddr,
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
			// DEBUG (don't remove until stable)
			//

			/*state = thread.getState();
			printf("\n");
			printf("[After] State  = %s\n", state.state.c_str());
			printf("[After] Reason = %s\n", state.wait_reason.c_str());
			printf("\n");
			printf("PushSpRet : 0x%p\n", PushSpRet);
			printf("SelfLoop  : 0x%p\n", SelfLoop);
			printf("\n");

			if (state.state == "Waiting" && state.wait_reason == "Executive") {
				// restore thread original context
				thread.Suspend();
				thread.setContext(&OriginalContext);
				thread.Resume();
				continue;
			}*/

			//
			// END DEBUG
			//

			//
			// now we want to check hijacked thread progression (whether it works or not)
			//

			printf("Thread 0x%05x:\n", tid);
			printf("  -> Original IP  : %p | %s\n",
				OriginalIP,
				process.getSymbolFromAddress(OriginalIP).c_str()
			);

			Sleep(1000);

			ctx = thread.getContext();

			printf(
				"\r  -> Current IP   : %p | %-20s",
#ifdef _WIN64
				(PVOID) ctx.Rip,
				process.getSymbolFromAddress((PVOID)ctx.Rip).c_str()
#else
				(PVOID)ctx.Eip,
				process.getSymbolFromAddress((PVOID)ctx.Eip).c_str()
#endif
			);

#ifdef _WIN64
			IpMoved = ctx.Rip != (DWORD)PushSpRet;
			ExitSignal = (DWORD64)SelfLoop == ctx.Rip;
#else
			IpMoved = ctx.Eip != (DWORD)PushSpRet;
			ExitSignal = ctx.Eip == (DWORD)SelfLoop;
#endif
			if (!ExitSignal && IpMoved)
			{
				printf("\n\n");
				printf("IP in thread (0x%x) moved but not hitting our\n", tid);
				printf("end signal. Chance to succeed or crashed is equal\n");
			}

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