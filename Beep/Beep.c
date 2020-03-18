// Beep.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <subauth.h>
#include <stdio.h>
#include <stdbool.h>
#include <conio.h>

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG Flags;                    //Reserved.
    PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.
    PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
    PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
    ULONG SizeOfImage;              //The size of the DLL image, in bytes.
} LDR_DLL_LOADED_NOTIFICATION_DATA, * PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
    ULONG Flags;                    //Reserved.
    PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.
    PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
    PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
    ULONG SizeOfImage;              //The size of the DLL image, in bytes.
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, * PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
    LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, * PLDR_DLL_NOTIFICATION_DATA;

typedef const LDR_DLL_NOTIFICATION_DATA* PCLDR_DLL_NOTIFICATION_DATA;

typedef VOID(NTAPI *PLDR_DLL_NOTIFICATION_FUNCTION)(
    _In_      ULONG NotificationReason,
    _In_      PCLDR_DLL_NOTIFICATION_DATA NotificationData,
    _In_opt_  PVOID Context
);

typedef NTSTATUS(NTAPI *LdrRegisterDllNotification)(
    _In_     ULONG                          Flags,
    _In_     PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    _In_opt_ PVOID                          Context,
    _Out_    PVOID* Cookie
);

typedef HMODULE(NTAPI *fnLoadLibraryA) (
    LPCSTR lpLibFileName
);


VOID NTAPI DllNotificationCallback(
    _In_      ULONG NotificationReason,
    _In_      PCLDR_DLL_NOTIFICATION_DATA NotificationData,
    _In_opt_  PVOID Context
)
{
    printf("\n");
    printf("Reason: %s\n", NotificationReason == 1 ? "Loaded" : "Unloaded");
    wprintf(L"Basename: %s\n", NotificationData->Loaded.BaseDllName->Buffer);
    printf("DLL Size: %u\n", NotificationData->Loaded.SizeOfImage);
}


BOOL Exit;


DWORD WINAPI PrintDot(PVOID lpParameter)
{
    UNREFERENCED_PARAMETER(lpParameter);

    printf("\n");
    printf("Thread ID = 0x%x\n", GetCurrentThreadId());
    printf("\n");

    for (size_t i = 1; !Exit; i++) {
        Sleep(500);
        printf("*");
        if (i % 20 == 0) printf("\n");
    }

    return S_OK;
}

int main()
{
    DWORD    tid;
    NTSTATUS nRet;
    HANDLE   hThread;
    PVOID    cookie;

    LdrRegisterDllNotification _LdrRegisterDllNotification = (LdrRegisterDllNotification) GetProcAddress(
        GetModuleHandle(L"ntdll.dll"),
        "LdrRegisterDllNotification"
    );

    if (!_LdrRegisterDllNotification) {
        printf("GetProcAddress: 0x%x\n", GetLastError());
        return EXIT_FAILURE;
    }

    nRet = _LdrRegisterDllNotification(0, DllNotificationCallback, NULL, &cookie);

    if (nRet != STATUS_SUCCESS) {
        printf("LdrRegisterDllNotification: 0x%x\n", nRet);
        return EXIT_FAILURE;
    }

    if (!(hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PrintDot, NULL, 0, &tid))) {
        printf("CreateThread: 0x%x\n", GetLastError());
        return EXIT_FAILURE;
    }

    while (!_getch()) {
        Exit = TRUE;
    }

    CloseHandle(hThread);

    return EXIT_SUCCESS;
}