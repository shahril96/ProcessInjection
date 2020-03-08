// main.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>

#include <iostream>

#include "util.h"
#include "injector.h"

int main(int argc, char* argv[])
{
	DWORD   pid = NULL;
	LPCSTR  dll;
	HRESULT hRet;

	// to determine bitness
	BOOL currProcess;
	BOOL targProcess;

	if (argc != 3) {
		printf("\n");
		printf("%s <process-name> <dll-path>", argv[0]);
		printf("\n");
		return EXIT_FAILURE;
	}

	dll = argv[2];
	pid = Util::findWithProcessName(Util::ToUtf16(argv[1]).c_str());

	if (FAILED(pid)) {
		printf("\nFailed to find process id for '%s'\n", argv[1]);
		return EXIT_FAILURE;
	}

	Util::isProcessNative(::GetCurrentProcessId(), &currProcess);
	Util::isProcessNative(pid, &targProcess);

	if (currProcess != targProcess) {
		printf("\nThis injector bitness is incompatible with target process\n");
		return EXIT_FAILURE;
	}

	//hRet = Injector::WriteProcessMemory_CreateRemoteThread(pid, dll);
	hRet = Injector::WriteProcessMemory_SuspendThreadResume(pid, dll);

	if (hRet != S_OK) {
		printf("\nDLL Injection failed!\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}