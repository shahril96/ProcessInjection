// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

BOOL APIENTRY DllMain(HINSTANCE hInstDLL, DWORD fdwReason, PVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        printf("DLL_PROCESS_ATTACH: Hello From The Injected DLL\n");
        Beep(750, 300);
        break;

    case DLL_THREAD_ATTACH:
        printf("DLL_THREAD_ATTACH: Hello From The Injected DLL\n");
        Beep(750, 300);
        break;

    case DLL_THREAD_DETACH:
        printf("DLL_THREAD_DETACH: Hello Again From The Injected DLL\n");
        Beep(750, 300);
        break;

    case DLL_PROCESS_DETACH:
        printf("DLL_PROCESS_DETACH: Hello Again From The Injected DLL\n");
        Beep(750, 300);
        break;
    }

    return TRUE;
}
