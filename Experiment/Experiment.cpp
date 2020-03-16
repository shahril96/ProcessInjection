// Experiment.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <vector>

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
    SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
    SystemPathInformation, // not implemented
    SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
}  SYSTEM_INFORMATION_CLASS;

typedef __kernel_entry NTSTATUS(WINAPI* fnNtQuerySystemInformation)(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

int main()
{
    DWORD                      dwRet;
    NTSTATUS                   nRet;
    std::vector<BYTE>          InfoBuffer(1024 * 50, '\0');
    fnNtQuerySystemInformation _NtQuerySystemInformation;

    _NtQuerySystemInformation  = (fnNtQuerySystemInformation)GetProcAddress(
        GetModuleHandle(L"ntdll.dll"),
        "NtQuerySystemInformation"
    );

    // first time read
    nRet = _NtQuerySystemInformation(
        SystemProcessInformation,
        &InfoBuffer[0],
        InfoBuffer.size(),
        &dwRet
    );
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
