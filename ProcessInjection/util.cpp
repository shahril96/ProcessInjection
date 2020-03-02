
#include <Windows.h>
#include <tlhelp32.h>

#include <string>
#include <vector>

#include "util.h"

std::string Util::GetLastErrorAsString()
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

HRESULT Util::EnumProcessThreads(DWORD pid, std::vector<DWORD>& ThreadIDs)
{
    BOOL          bRet;
    THREADENTRY32 ThreadEntry;

     RAII::HandlePtr hSnap{
         ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
     };

    if (hSnap.get() == INVALID_HANDLE_VALUE) {
        return E_FAIL;
    }

    ThreadEntry.dwSize = sizeof(THREADENTRY32);

    for (bRet = ::Thread32First(hSnap.get(), &ThreadEntry);
        bRet && ::Thread32Next(hSnap.get(), &ThreadEntry);
        )
    {
        if (ThreadEntry.th32OwnerProcessID == pid) {
            ThreadIDs.push_back(ThreadEntry.th32ThreadID);
        }
    }

    return S_OK;
}


//
// Find first thread in process `pid` whose currently in 
// alertable state, which is a requirement for queing an APC
// procedure.
// 
// The method presented here is based on write-up by @odzhan:
// https://modexp.wordpress.com/2019/08/27/process-injection-apc/
//

DWORD Util::FindAlertableThread(const RAII::HandlePtr& hProcess)
{
    BOOL   bRet;
    DWORD  tid;
    DWORD  dRet;
    DWORD  idxThread;
    HANDLE hEvent;
    HANDLE TargetHandle;
    LPVOID SetEventProc;

    std::vector<DWORD>           ThreadIDs;
    std::vector<HANDLE>          StoreEventHandle;
    std::vector<RAII::HandlePtr> StoreHandle;

    // set default value to NULL
    tid = NULL;

    SetEventProc = (LPVOID)::GetProcAddress(
        GetModuleHandle(L"kernel32.dll"),
        "SetEvent"
    );

    Util::EnumProcessThreads(
        ::GetProcessId(hProcess.get()),
        ThreadIDs
    );

    for (size_t i = 0; i < ThreadIDs.size(); i++) {

        RAII::HandlePtr hThread{
            ::OpenThread(
                THREAD_ALL_ACCESS,
                FALSE,
                ThreadIDs[i]
            )
        };
        
        if (!hThread.get()) {
            continue;
        }

        // create an empty event
        hEvent = ::CreateEvent(NULL, FALSE, FALSE, NULL);

        if (!hEvent) {
            continue;
        }

        // duplicate our event's handle to the target thread
        bRet = ::DuplicateHandle(
            ::GetCurrentProcess(),   // source process
            hEvent,                  // source event to duplicate
            hProcess.get(),          // target process
            &TargetHandle,           // target handle
            0,
            false,
            DUPLICATE_SAME_ACCESS
        );

        if (!bRet) {
            continue;
        }

        // queue APC to trigger thread which passes 
        // our dummy event
        dRet = ::QueueUserAPC(
            (PAPCFUNC)SetEventProc,
            hThread.get(),
            (ULONG_PTR)TargetHandle
        );

        if (!dRet) {
            continue;
        }

        // we store thread handle into std::vector
        // to prevent handle from closing itself 
        // because of RAII
        StoreHandle.push_back(std::move(hThread));

        // we store this into seperate vector for the 
        // use of WaitForMultipleObjects later
        StoreEventHandle.push_back(hEvent);
    }

    // now we wait for any of 
    // alertable thread to trigger
    idxThread = WaitForMultipleObjects(
        StoreEventHandle.size(),
        &StoreEventHandle[0],
        FALSE, // stop wait if any thread is alerted
        1000
    );

    // return thread ID which is alertable state
    if (idxThread != WAIT_TIMEOUT) {
        if (idxThread < ThreadIDs.size()) {
            tid = ThreadIDs[idxThread];
        }
    }

    // manually clean-up event object
    for (const HANDLE& handle : StoreEventHandle) {
        CloseHandle(handle);
    }

    return tid;
}