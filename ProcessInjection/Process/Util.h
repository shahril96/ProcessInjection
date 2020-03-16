#pragma once

#include "Common.h"

namespace Process
{
    PVOID getFunctionAddress(PCWSTR ModuleName, PCSTR FunctionName)
    {
        return ::GetProcAddress(::GetModuleHandle(ModuleName), FunctionName);
    }

    BOOL isWow64(DWORD pid)
    {
        BOOL result;
        HANDLE hProcess;

        hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        ::IsWow64Process(hProcess, &result);
        CloseHandle(hProcess);

        return result;
    }

    // credit: https://stackoverflow.com/a/17387176/1768052
    std::string getLastErrorAsString()
    {
        size_t size;
        DWORD  errorMessageID;
        LPSTR  messageBuffer;

        // Get the error message, if any
        errorMessageID = ::GetLastError();

        if (!errorMessageID) {
            return std::string(); // No error message has been recorded
        }

        messageBuffer = nullptr;

        size = ::FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
            | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            errorMessageID,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&messageBuffer,
            0,
            NULL
        );

        std::string message(messageBuffer, size);

        // Free the buffer
        ::LocalFree(messageBuffer);

        return std::move(message);
    }

    // Convert a wide Unicode string to an UTF8 string
    std::string ToUtf8(const std::wstring& wstr)
    {
        if (wstr.empty()) return std::string();
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string strTo(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
        return strTo;
    }

    // Convert an UTF8 string to a wide Unicode String
    std::wstring ToUtf16(const std::string& str)
    {
        if (str.empty()) return std::wstring();
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
        std::wstring wstrTo(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
        return wstrTo;
    }

    // credit: https://gist.github.com/ccbrown/9722406
    void hexDump(LPCVOID data, size_t size, DWORD address)
    {
        char ascii[17];
        size_t i, j;
        ascii[16] = '\0';
        for (i = 0; i < size; ++i) {

            if (i % 16 == 0) {
                printf("0x%016x ", address + 16 * (i / 16));
            }

            printf("%02X ", ((PUCHAR)data)[i]);
            if (((PUCHAR)data)[i] >= ' ' && ((PUCHAR)data)[i] <= '~') {
                ascii[i % 16] = ((PUCHAR)data)[i];
            }
            else {
                ascii[i % 16] = '.';
            }
            if ((i + 1) % 8 == 0 || i + 1 == size) {
                printf(" ");
                if ((i + 1) % 16 == 0) {
                    printf("|  %s \n", ascii);
                }
                else if (i + 1 == size) {
                    ascii[(i + 1) % 16] = '\0';
                    if ((i + 1) % 16 <= 8) {
                        printf(" ");
                    }
                    for (j = (i + 1) % 16; j < 16; ++j) {
                        printf("   ");
                    }
                    printf("|  %s \n", ascii);
                }
            }
        }
    }

    //
    //
    //

    ByteArray_t QuerySystemInformation(
        SYSTEM_INFORMATION_CLASS InfoClass,
        size_t StructureSize = 0       // 0 if size is unspecified
    )
    {
        DWORD                      dwRet = StructureSize ? StructureSize : 32;
        NTSTATUS                   nRet;
        ByteArray_t                Buffer(dwRet, '\0');
        fnNtQuerySystemInformation _NtQuerySystemInformation;

        _NtQuerySystemInformation = (fnNtQuerySystemInformation)::GetProcAddress(
            ::GetModuleHandle(L"ntdll.dll"),
            "NtQuerySystemInformation"
        );

        do {
            Buffer.resize(dwRet);
            nRet = _NtQuerySystemInformation(
                InfoClass,
                &Buffer[0],
                Buffer.size(),
                &dwRet
            );
        } while (FAILED(nRet) && nRet == STATUS_INFO_LENGTH_MISMATCH);

        // resize accordingly
        if (dwRet != -16) { // HACK
            Buffer.resize(dwRet);
        }

        return std::move(Buffer);
    }

    ByteArray_t QueryInformationProcess(
        HANDLE hProcess,
        PROCESSINFOCLASS InfoClass,
        size_t StructureSize = 0       // 0 if size is unspecified
    )
    {
        DWORD                       dwRet = StructureSize ? StructureSize : 32;
        NTSTATUS                    nRet;
        ByteArray_t                 Buffer(dwRet, '\0');
        fnNtQueryInformationProcess _NtQueryInformationProcess;

        _NtQueryInformationProcess = (fnNtQueryInformationProcess)::GetProcAddress(
            ::GetModuleHandle(L"ntdll.dll"),
            "NtQueryInformationProcess"
        );

        do {
            Buffer.resize(dwRet);
            nRet = _NtQueryInformationProcess(
                hProcess,
                InfoClass,
                &Buffer[0],
                Buffer.size(),
                &dwRet
            );
        } while (FAILED(nRet) && nRet == STATUS_INFO_LENGTH_MISMATCH);

        // resize accordingly
        if (dwRet != -16) { // HACK
            Buffer.resize(dwRet);
        }

        return std::move(Buffer);
    }

    ByteArray_t QueryInformationThread(
        HANDLE hThread,
        THREADINFOCLASS InfoClass,
        size_t StructureSize = 0       // 0 if size is unspecified
    )
    {
        DWORD                       dwRet = StructureSize ? StructureSize : 32;
        NTSTATUS                    nRet;
        ByteArray_t                 Buffer(dwRet, '\0');
        fnNtQueryInformationThread _NtQueryInformationThread;

        _NtQueryInformationThread = (fnNtQueryInformationThread)::GetProcAddress(
            ::GetModuleHandle(L"ntdll.dll"),
            "NtQueryInformationThread"
        );

        do {
            Buffer.resize(dwRet);
            nRet = _NtQueryInformationThread(
                hThread,
                InfoClass,
                &Buffer[0],
                Buffer.size(),
                &dwRet
            );

        } while (FAILED(nRet) && nRet == STATUS_INFO_LENGTH_MISMATCH);

        // resize accordingly
        if (dwRet != -16) { // HACK
            Buffer.resize(dwRet);
        }

        return std::move(Buffer);
    }

    void enumExtendedProcessInfo(
        std::function<bool(
            const PSYSTEM_PROCESS_INFORMATION,
            const PSYSTEM_EXTENDED_THREAD_INFORMATION
        )> callback
    )
    {
        ByteArray_t InfoBuffer = QuerySystemInformation(SystemExtendedProcessInformation);

        PSYSTEM_PROCESS_INFORMATION         pProcessInfo;
        PSYSTEM_EXTENDED_THREAD_INFORMATION pExThreadInfoList;

        PBYTE start = &InfoBuffer[0];
        PBYTE   end = start + InfoBuffer.size();

        bool stop = false;

        // enumerate SYSTEM_PROCESS_INFORMATION array
        for (
            PBYTE offset = start;
            !stop && offset < end;
            offset += pProcessInfo->NextEntryOffset
            )
        {
            pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)offset;
            pExThreadInfoList = (PSYSTEM_EXTENDED_THREAD_INFORMATION)&pProcessInfo->Threads;

            stop = callback(pProcessInfo, pExThreadInfoList);

            if (!pProcessInfo->NextEntryOffset) break;
        }
    }
}