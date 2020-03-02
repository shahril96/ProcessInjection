// main.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>

#include <iostream>

#include "injector.h"

int main(int argc, char* argv[])
{
	DWORD pid;
	LPCSTR dllPath;

	if (argc != 3) {
		printf("\n");
		printf("%s <pid> <dll-path>", argv[0]);
		printf("\n");
		return EXIT_FAILURE;
	}

	sscanf_s(argv[1], "%d", &pid);
	dllPath = argv[2];

	HRESULT ret = Injector::WriteProcessMemory_APCInjector(pid, dllPath);

	if (ret != S_OK) {
		printf("DLL Injection failed!");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}