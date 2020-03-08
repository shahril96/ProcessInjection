
#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <string>
#include <vector>

#include "util.h"

// credit: https://stackoverflow.com/a/17387176/1768052
std::string Util::getLastErrorAsString()
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

// credit: https://gist.github.com/ccbrown/9722406
void Util::hexDump(LPCVOID data, size_t size, DWORD address)
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

DWORD Util::findWithProcessName(LPCWSTR name)
{
    BOOL                  bRet;
    HRESULT               hRet;
    DWORD                 byteReads;
    DWORD                 pid         = E_FAIL;
    std::wstring          NameWide    = name;
    std::vector<DWORD>    ProcessesPID(1024);
    Util::ModuleInfoList  ModuleInfoList;

    bRet = EnumProcesses(
        &ProcessesPID[0],
        ProcessesPID.size() * sizeof ProcessesPID,
        &byteReads
    );

    if (!bRet) {
        printf(
            "EnumProcesses: %s\n",
            Util::getLastErrorAsString().c_str()
        );
        return pid;
    }

    // re-adjust to real size
    ProcessesPID.resize(byteReads / sizeof(DWORD));

    for (const DWORD ProcessID: ProcessesPID)
    {
        RAII::HandlePtr hProcess{
            ::OpenProcess(
                PROCESS_ALL_ACCESS,
                FALSE,
                ProcessID
            )
        };

        if (!hProcess.get()) continue;

        hRet = Util::enumModuleInfo(hProcess.get(), &ModuleInfoList);

        if (FAILED(hRet)) continue;

        if (ModuleInfoList.find(NameWide) != ModuleInfoList.end()) {
            pid = GetProcessId(hProcess.get());
            break;
        }
    }

    return pid;
}

void printPageInfo(
    const PMEMORY_BASIC_INFORMATION info,
    LPCVOID addr)
{
    printf(
        "%10p (%6uK)\t",
        addr,
        info->RegionSize / 1024
    );

    switch (info->State) {
    case MEM_COMMIT:
        printf("Committed");
        break;
    case MEM_RESERVE:
        printf("Reserved");
        break;
    case MEM_FREE:
        printf("Free");
        break;
    }
    printf("\t");
    switch (info->Type) {
    case MEM_IMAGE:
        printf("Code Module");
        break;
    case MEM_MAPPED:
        printf("Mapped     ");
        break;
    case MEM_PRIVATE:
        printf("Private    ");
    }
    printf("\t");

    int guard = 0, nocache = 0;

    if (info->AllocationProtect & PAGE_NOCACHE)
        nocache = 1;
    if (info->AllocationProtect & PAGE_GUARD)
        guard = 1;

    info->AllocationProtect &= ~(PAGE_GUARD | PAGE_NOCACHE);

    switch (info->Protect) {
    case PAGE_READONLY:
        printf("Read Only");
        break;
    case PAGE_READWRITE:
        printf("Read/Write");
        break;
    case PAGE_WRITECOPY:
        printf("Copy on Write");
        break;
    case PAGE_EXECUTE:
        printf("Execute only");
        break;
    case PAGE_EXECUTE_READ:
        printf("Execute/Read");
        break;
    case PAGE_EXECUTE_READWRITE:
        printf("Execute/Read/Write");
        break;
    case PAGE_EXECUTE_WRITECOPY:
        printf("COW Executable");
        break;
    }

    if (guard)
        printf("\tguard page");
    if (nocache)
        printf("\tnon-cachable");

    printf("\n");
}

HRESULT Util::enumModuleInfo(
    const HANDLE hProcess,
    Util::ModuleInfoList* ModuleInfoList
)
{
    BOOL         bRet;
    DWORD        dRet;
    DWORD        nModule;
    MODULEINFO   ModeInfo;

    std::vector<HMODULE> hModuleList(1024, '\0');

    bRet = ::EnumProcessModules(
        hProcess,
        &hModuleList[0],
        hModuleList.size() * sizeof hModuleList[0],
        &nModule
    );

    if (!bRet) return E_FAIL;

    // re-adjust true size of module list
    hModuleList.resize(nModule / sizeof(HMODULE));

    for (const HMODULE Module : hModuleList)
    {
        ::ZeroMemory((LPVOID)&ModeInfo, sizeof ModeInfo);

        std::wstring ModuleName(MAX_PATH, L'\0');

        dRet = GetModuleBaseName(
            hProcess, 
            Module, 
            &ModuleName[0], 
            ModuleName.size() * sizeof(ModuleName[0])
        );

        if (!dRet) continue;

        // resize to true string size
        ModuleName.resize(dRet);

        bRet = ::GetModuleInformation(
            hProcess,
            Module,
            &ModeInfo,
            sizeof ModeInfo
        );

        if (!bRet) continue;

        ModuleInfoList->insert({ ModuleName, ModeInfo });
    }

    return 1 - (HRESULT)(ModuleInfoList->size() > 0);
}

HRESULT Util::getThreadStartAddress(DWORD tid, PVOID* addr)
{
    DWORD dRet;

    auto __NtQueryInformationThread = (_NtQueryInformationProcess)GetProcAddress(
        GetModuleHandle(L"ntdll.dll"),
        "NtQueryInformationThread"
    );

    if (!__NtQueryInformationThread) {
        printf(
            "GetProcAddress: %s\n",
            Util::getLastErrorAsString().c_str()
        );
        return E_FAIL;
    }

    RAII::HandlePtr hThread{
        ::OpenThread(
            THREAD_ALL_ACCESS,
            NULL,
            tid
        )
    };

    if (!hThread.get()) {
        printf(
            "OpenThread: %s\n",
            Util::getLastErrorAsString().c_str()
        );
        return E_FAIL;
    }

    dRet = __NtQueryInformationThread(
        hThread.get(),
        ThreadQuerySetWin32StartAddress,
        addr,
        sizeof(addr),
        NULL
    );

    if (FAILED(dRet)) {
        printf(
            "NtQueryInformationProcess: %s\n",
            Util::getLastErrorAsString().c_str()
        );
        return E_FAIL;
    }

    return S_OK;
}

HRESULT Util::findPageByProtection(
    const HANDLE hProcess,
    std::vector<MEMORY_BASIC_INFORMATION>* MemoryInfoList,
    DWORD Protection
)
{
    BOOL    bRet;
    size_t  sRet;
    HRESULT hRet;
    
    MEMORY_BASIC_INFORMATION  MemoryInfo;
    Util::ModuleInfoList      ModuleInfoList;

    PIMAGE_DOS_HEADER         dosHeader;
    PIMAGE_NT_HEADERS         ntHeader;
    PIMAGE_SECTION_HEADER     sectionList;

    hRet = Util::enumModuleInfo(hProcess, &ModuleInfoList);

    if (FAILED(hRet)) {
        printf("Failed to fetch foreign process module info\n");
        return E_FAIL;
    }

    // enumerate every modules
    for (const auto& [ModuleName, ModuleInfo] : ModuleInfoList)
    {
        ::ZeroMemory((LPVOID)&MemoryInfo, sizeof MemoryInfo);

        // get size of PE header memory page
        sRet = ::VirtualQueryEx(
            hProcess,
            ModuleInfo.lpBaseOfDll,
            &MemoryInfo,
            sizeof(MemoryInfo)
        );

        if (sRet != sizeof(MemoryInfo)) {
            continue;
        }

        // allocate buffer with page size
        std::vector<BYTE> Buffer;
        Buffer.resize(MemoryInfo.RegionSize);

        // read the whole page that contains PE header
        bRet = ::ReadProcessMemory(
            hProcess,
            ModuleInfo.lpBaseOfDll,
            &Buffer[0],
            MemoryInfo.RegionSize,
            NULL
        );

        if (!bRet) continue;

        dosHeader = (PIMAGE_DOS_HEADER)&Buffer[0];
        ntHeader = (PIMAGE_NT_HEADERS)(&Buffer[0] + dosHeader->e_lfanew);
        sectionList = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeader + sizeof(IMAGE_NT_HEADERS));

        // check for "PE" signature
        if (ntHeader->Signature != 0x00004550) {
            continue;
        }

        // enumerate every section in the PE
        for (
            size_t i = 0;
            (PBYTE)&sectionList[i] < (PBYTE)dosHeader + MemoryInfo.RegionSize && // don't exceed page
            sectionList[i].VirtualAddress != NULL;  // if this empty, we've reached end
            i++)
        {
            PBYTE SectionVA = (PBYTE)ModuleInfo.lpBaseOfDll + sectionList[i].VirtualAddress;

            // enumerate every memory pages in section
            for (
                PBYTE p = SectionVA;
                p < SectionVA + sectionList[i].SizeOfRawData && // until end-of-page
                ::VirtualQueryEx(hProcess, p, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo);
                p += MemoryInfo.RegionSize
                )
            {
                // if page's protection match our `Protection` param
                if (MemoryInfo.Protect & Protection) {
                    MemoryInfoList->push_back(MemoryInfo);
                }
            }
        }
    }

    return 1 - (HRESULT)(MemoryInfoList->size() > 0);
}

HRESULT Util::findInstruction(
    const HANDLE hProcess,
    std::vector<LPVOID>* GadgetList,
    LPCSTR Pattern
)
{
    BOOL    bRet;
    PBYTE   pRet;
    HRESULT hRet;

    std::vector<MEMORY_BASIC_INFORMATION> ExecutableMemoryList;
    
    hRet = Util::findPageByProtection(
        hProcess,
        &ExecutableMemoryList,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    );

    if (FAILED(hRet)) {
        printf("Failed to find memory pages on foreign process\n");
        return E_FAIL;
    }

    for (const MEMORY_BASIC_INFORMATION& MemoryInfo : ExecutableMemoryList)
    {
        std::vector<BYTE> PageData(MemoryInfo.RegionSize, 0x0);

        bRet = ::ReadProcessMemory(
            hProcess,
            MemoryInfo.BaseAddress,
            &PageData[0],
            PageData.size() * sizeof PageData[0],
            NULL
        );

        if (!bRet) {
            printf(
                "ReadProcessMemory: %s\n",
                Util::getLastErrorAsString().c_str()
            );
            continue;
        }

        pRet = Util::findPattern(
            (PBYTE)&PageData[0],
            (PBYTE)&PageData[0] + (PageData.size() * sizeof PageData[0]),
            Pattern
        );

        if (!pRet) continue;

        GadgetList->push_back((PBYTE)MemoryInfo.BaseAddress + (pRet - &PageData[0]));
    }

    return 1 - (HRESULT)(GadgetList->size() > 0);
}

HRESULT Util::isProcessNative(DWORD pid, PBOOL result)
{
    *result = FALSE;

    RAII::HandlePtr hProcess{
        ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)
    };

    if (!hProcess.get()) {
        printf(
            "OpenProcess: %s\n",
            Util::getLastErrorAsString().c_str()
        );
        return E_FAIL;
    }

    if (!::IsWow64Process(hProcess.get(), result)) {
        printf(
            "IsWow64Process: %s\n",
            Util::getLastErrorAsString().c_str()
        );
        return E_FAIL;
    }

    return S_OK;
}

HRESULT Util::enumProcessThreads(DWORD pid, std::vector<DWORD>* ThreadIDs)
{
    BOOL          bRet;
    THREADENTRY32 ThreadEntry = { 0 };

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
            ThreadIDs->push_back(ThreadEntry.th32ThreadID);
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

DWORD Util::findAlertableThread(const HANDLE hProcess)
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

    Util::enumProcessThreads(
        ::GetProcessId(hProcess),
        &ThreadIDs
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
            hProcess,                // target process
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

    if (!StoreEventHandle.empty()) {

        // now we wait for any of 
        // alertable thread to trigger
        idxThread = WaitForMultipleObjects(
            (DWORD)StoreEventHandle.size(),
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
    }

    return tid;
}

// http://www.unknowncheats.me/forum/c-and-c/77419-findpattern.html#post650040
// Original code by learn_more
// Fix based on suggestion from stevemk14ebr : http://www.unknowncheats.me/forum/1056782-post13.html

#define INRANGE(x,a,b)		(x >= a && x <= b) 
#define getBits( x )		(INRANGE(x,'0','9') ? (x - '0') : ((x&(~0x20)) - 'A' + 0xa))
#define getByte( x )		(getBits(x[0]) << 4 | getBits(x[1]))

// return addr on first pattern match
PBYTE Util::findPattern(
    const PBYTE rangeStart,
    const PBYTE rangeEnd,
    const char* pattern
)
{
    const unsigned char* pat = reinterpret_cast<const unsigned char*>(pattern);
    PBYTE firstMatch = 0;
    for (PBYTE pCur = rangeStart; pCur < rangeEnd; ++pCur) {
        if (*(PBYTE)pat == (BYTE)'\?' || *pCur == getByte(pat)) {
            if (!firstMatch) {
                firstMatch = pCur;
            }
            pat += (*(PWORD)pat == (WORD)'\?\?' || *(PBYTE)pat != (BYTE)'\?') ? 3 : 2;
            if (!*pat) {
                return firstMatch;
            }
        }
        else if (firstMatch) {
            pCur = firstMatch;
            pat = reinterpret_cast<const unsigned char*>(pattern);
            firstMatch = 0;
        }
    }
    return NULL;
}

// Convert a wide Unicode string to an UTF8 string
std::string Util::ToUtf8(const std::wstring& wstr)
{
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

// Convert an UTF8 string to a wide Unicode String
std::wstring Util::ToUtf16(const std::string& str)
{
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}