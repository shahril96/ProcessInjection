// main.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>

#include <iostream>

#include "util.h"
#include "injector.h"

int main(int argc, char* argv[])
{
	DWORD pid;
	LPCSTR dllPath;
	HRESULT ret;

	// to determine bitness
	BOOL currProcess;
	BOOL targProcess;

	if (argc != 3) {
		printf("\n");
		printf("%s <pid> <dll-path>", argv[0]);
		printf("\n");
		return EXIT_FAILURE;
	}

	sscanf_s(argv[1], "%d", &pid);
	dllPath = argv[2];

	Util::IsProcessNative(::GetCurrentProcessId(), &currProcess);
	Util::IsProcessNative(pid, &targProcess);

	if (currProcess != targProcess) {
		printf("This injector is incompatible with target process.\n");
		return EXIT_FAILURE;
	}

	ret = Injector::WriteProcessMemory_SuspendThreadResume(pid, dllPath);

	if (ret != S_OK) {
		printf("DLL Injection failed!\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}