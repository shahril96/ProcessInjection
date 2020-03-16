// main.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "Common.h"

#include "Injector.h"
#include "Process\Process.h"



int main(int argc, char* argv[])
{
	DWORD   pid = NULL;
	LPCSTR  dll;
	HRESULT hRet;

	if (argc != 3) {
		printf("\n");
		printf("%s <process-name> <dll-path>", argv[0]);
		printf("\n");
		return EXIT_FAILURE;
	}

	Process::ProcessList Processes;
	auto ProcessIterator = Processes.findProcessByName(argv[1]);

	if (ProcessIterator == Processes.end()) {
		printf("\nFailed to find process id for '%s'\n", argv[1]);
		return EXIT_FAILURE;
	}

	dll = argv[2];
	pid = ProcessIterator->second.getPid();

	//hRet = Injector::WriteProcessMemory_APCInjector(Process::Process(pid), dll);
	hRet = Injector::WriteProcessMemory_SuspendThreadResume(pid, dll);

	if (hRet != S_OK) {
		printf("\nDLL Injection failed!\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}