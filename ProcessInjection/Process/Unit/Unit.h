#pragma once

#include "..\Common.h"
#include "..\Util.h"
#include "..\RAII.h"
#include "..\Module\Module.h"
#include "..\Thread\Thread.h"

namespace Process
{

class Process
{
private:

    // common
    BOOL   _ShouldCloseHandle;
    HANDLE hProcess;

    // internal
    PROCESS_BASIC_INFORMATION ProcessBasicInfo;
    SECTION_IMAGE_INFORMATION SectionImageInfo;

    // error handling
    BOOL        Error;
    std::string ErrorStr;

    template <typename T>
    inline void UpdateInternalStruct(T& structure, HANDLE hProcess, PROCESSINFOCLASS infoClass)
    {
        ZeroMemory(&structure, sizeof(structure));
        ByteArray_t buf_imageInfo = QueryInformationProcess(
            hProcess,
            infoClass,
            sizeof(T)
        );
        
        structure = *(T*)(&buf_imageInfo[0]);
    }

    void UpdateProcessByPid(DWORD pid)
    {
        if (hProcess) {
            CloseHandle(hProcess);
        }

        //
        // TODO: only support process which has the same bitness
        // TODO: study wow64
        //
        if (Error = (isWow64(pid) != isWow64(::GetCurrentProcessId()))) {
            ErrorStr = "This injector bitness is incompatible with target process";
            return;
        }

        hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, false, pid);

        if (Error = !hProcess) {
            ErrorStr = getLastErrorAsString();
            return;
        }

        UpdateInternalStruct(ProcessBasicInfo, hProcess, ProcessBasicInformation);
        UpdateInternalStruct(SectionImageInfo, hProcess, ProcessImageInformation);
    }

public:

    Process() = default;

    Process(DWORD pid)
        : hProcess(NULL)
        , _ShouldCloseHandle(TRUE)
    {
        UpdateProcessByPid(pid);
    }

    Process(HANDLE _hProcess, bool ShouldCloseHandle = FALSE)
        : hProcess(_hProcess)
        , _ShouldCloseHandle(ShouldCloseHandle)
    {
        if (Error = !hProcess) {
            ErrorStr = "Null handle";
        }

        UpdateInternalStruct(ProcessBasicInfo, hProcess, ProcessBasicInformation);
        UpdateInternalStruct(SectionImageInfo, hProcess, ProcessImageInformation);
    }

    Process(const Process& other)
        : hProcess(NULL)
        , _ShouldCloseHandle(TRUE)
    {
        UpdateProcessByPid(other.getPid());
    }


    ~Process()
    {
        if (_ShouldCloseHandle) {
            CloseHandle(hProcess);
        }
    }

    Process& operator=(const Process& other) noexcept { 
        UpdateProcessByPid(other.getPid());
        return *this;
    }

    HANDLE operator*() const noexcept
    {
        return hProcess;
    }

    BOOL isError() noexcept
    {
        if (!Error && hProcess == NULL) {
            Error = true;
            ErrorStr = "Thread handle is NULL";
        }

        return Error;
    }

    const std::string& getErrorStr() const noexcept
    {
        return ErrorStr;
    }

    //
    //
    //
        
    DWORD getPid() const noexcept
    {
        return (DWORD) ProcessBasicInfo.UniqueProcessId;
    }

    DWORD getParentPid() const noexcept
    {
        return ::GetProcessId(hProcess);
    }

    PPEB getPebVA() const noexcept
    {
        return ProcessBasicInfo.PebBaseAddress;
    }

    PVOID getEntryPointVA() const noexcept
    {
        return SectionImageInfo.TransferAddress;
    }

    std::string getBaseName() const noexcept
    {
        DWORD dwRet;
        std::wstring wBaseName(MAX_PATH, '\0');
        dwRet = GetModuleBaseName(hProcess, NULL, &wBaseName[0], (DWORD) wBaseName.size());

        if (!dwRet)
        {
            printf("Error! Code: 0x%x\n", ::GetLastError());
            //printf("%s\n", Util::getLastErrorAsString().c_str());
            return std::string();
        }

        wBaseName.resize(wcslen(&wBaseName[0]));

        return std::move(ToUtf8(wBaseName));
    }

    BOOL isAslrEnabled() const noexcept
    {
        return SectionImageInfo.ImageDynamicallyRelocated;
    }

    ThreadList_t getThreadList() const noexcept
    {
        ThreadList_t _ThreadList;

        enumExtendedProcessInfo([&](
            const PSYSTEM_PROCESS_INFORMATION pProcessInfo,
            const PSYSTEM_EXTENDED_THREAD_INFORMATION pExThreadInfoList
            ) -> bool
        {
            if ((DWORD)pProcessInfo->UniqueProcessId == getPid()) {

                // enumerate SYSTEM_EXTENDED_THREAD_INFORMATION array
                for (size_t i = 0; i < pProcessInfo->NumberOfThreads; i++)
                {
                    DWORD _tid = (DWORD)pExThreadInfoList[i].ThreadInfo.ClientId.UniqueThread;

                    Thread t(_tid);
                    if (!t.isError()) {
                        _ThreadList[_tid] = t;
                    }
                }
            }

            return false;
        });

        return std::move(_ThreadList);
    }

    ModuleList_t getModuleList() const noexcept
    {
        BOOL                    bRet;
        DWORD                   dRet;
        ModuleList_t            ModuleList;
        
        DWORD                   ModCount = 2048;
        MODULEINFO              ModInfo;
        ByteArray_t             ModBuffer;
        
        ModBuffer.resize(ModCount);

        bRet = ::EnumProcessModulesEx(
            hProcess,
            (HMODULE*) &ModBuffer[0],
            (DWORD) ModBuffer.size(),
            &ModCount,
            LIST_MODULES_DEFAULT
        );

        if (!bRet) {
            //printf("Error! Code: 0x%x\n", ::GetLastError());
            printf("%s\n", getLastErrorAsString().c_str());
            return ModuleList_t();
        }

        // re-adjust true size of module list
        ModBuffer.resize(ModCount);
        HMODULE* modlistr = (HMODULE*) &ModBuffer[0];
            
        // for every module(s)
        for (size_t i = 0; i < ModCount / sizeof(HMODULE); i++)
        {
            ::ZeroMemory((PVOID)&ModInfo, sizeof(ModInfo));

            std::wstring ModuleBaseName(MAX_PATH, L'\0');
            std::wstring ModuleFileName(MAX_PATH, L'\0');

            dRet = ::GetModuleBaseName(
                hProcess,
                modlistr[i],
                &ModuleBaseName[0],
                (DWORD) GetStlContainerBufferSize(ModuleBaseName)
            );

            if (!dRet) {
                ModuleBaseName = L"";
            }
            else {
                ModuleBaseName.resize(dRet);
            }

            // resize to true string size
            ModuleBaseName.resize(dRet);

            dRet = ::GetModuleFileName(
                modlistr[i],
                &ModuleFileName[0],
                (DWORD) GetStlContainerBufferSize(ModuleFileName)
            );

            if (!dRet) {
                ModuleFileName = L"";
            }
            else {
                ModuleFileName.resize(dRet);
            }

            bRet = ::GetModuleInformation(
                hProcess,
                modlistr[i],
                &ModInfo,
                sizeof(ModInfo)
            );

            Module module;
            module.BaseName    = ToUtf8(ModuleBaseName);
            module.FileName    = ToUtf8(ModuleFileName);
            module.BaseAddress = ModInfo.lpBaseOfDll;
            module.EntryPoint  = ModInfo.EntryPoint;
            module.Size        = ModInfo.SizeOfImage;

            ModuleList.push_back(std::move(module));
        }

        return std::move(ModuleList);
    }

    std::string getModuleNameByVA(PVOID addr) const noexcept
    {
        std::string  ModuleName;
        ModuleList_t ModuleList = getModuleList();

        for (const Module& module: ModuleList)
        {
            PBYTE start = (PBYTE) module.BaseAddress;
            PBYTE   end = start + module.Size;

            // is in range of this module
            if (start <= addr && addr < end) {
                ModuleName = module.BaseName;
                break;
            }
        }

        return std::move(ModuleName);
    }

    std::string getSymbolFromAddress(PVOID addr) const noexcept
    {
        DWORD64      dwDisplacement = 0;
        PSYMBOL_INFO pSymbol;

        BYTE buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)] = { 0 };

        pSymbol = (PSYMBOL_INFO)buffer;
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;

        // automatically release sym object for us
        RAII::SymbolHandler sym(hProcess);

        std::string ModuleName = getModuleNameByVA(addr);

        // fetch function name from symbol
        // if failed to get symbol, return module name only
        if (!::SymFromAddr(hProcess, (DWORD64)addr, &dwDisplacement, pSymbol)) {
            return ModuleName;
        }

        ModuleName += "!" + std::string(pSymbol->Name, pSymbol->Name + pSymbol->MaxNameLen);

        // return moduleName!functionName
        return std::move(ModuleName);
    }

    //
    // memory functions
    //

    RAII::allocateMemory allocate(
        size_t size,
        DWORD protect = PAGE_READWRITE,
        DWORD allocation_type = MEM_RESERVE | MEM_COMMIT
    )
    {
        return RAII::allocateMemory(hProcess, size, protect, allocation_type);
    }

    BOOL writeMemory(PVOID addr, PVOID buf, size_t size)
    {
        BOOL   bRet;
        SIZE_T dwRet;
        bRet = ::WriteProcessMemory(hProcess, addr, buf, size, &dwRet);
        
        if (!bRet) {
            printf("WriteProcessMemory: 0x%x\n", ::GetLastError());
        }

        return !bRet || dwRet != size;
    }

    ByteArray_t readMemory(PVOID addr, size_t size)
    {
        BOOL        bRet;
        SIZE_T      dwRet;
        ByteArray_t buf(size, 0);
        bRet = ::ReadProcessMemory(hProcess, addr, &buf[0], buf.size(), &dwRet);
        return std::move(buf);
    }

    MemoryInfoList_t getPagesInfo(DWORD protection = NULL)
    {
        MemoryInfoList_t         MemoryInfoList;
        MEMORY_BASIC_INFORMATION MemoryInfo = { 0 };

        for (
            PBYTE p = 0;
            ::VirtualQueryEx(hProcess, p, &MemoryInfo, sizeof(MemoryInfo)) == sizeof(MemoryInfo);
            p += MemoryInfo.RegionSize
            )
        {
            if (protection && (MemoryInfo.Protect & protection) == 0) {
                continue;
            }

            MemoryInfoList.push_back(MemoryInfo);
        }

        return std::move(MemoryInfoList);
    }

    PointerArray_t findPatternInMemory(
        const std::string& Pattern,
        DWORD CountLimit,
        DWORD Protect = PAGE_EXECUTE_READWRITE
    )
    {
        PointerArray_t        PatternList;
        ByteArray_t::iterator Start;
        ByteArray_t           patternByteArray(Pattern.begin(), Pattern.end());

        for (const auto& page : getPagesInfo())
        {
            if ((page.Protect & Protect) == 0) continue;

            ByteArray_t buffer = readMemory(page.BaseAddress, page.RegionSize);
            
            for (
                Start = buffer.begin();
                PatternList.size() < CountLimit;
                Start += Pattern.size()
                )
            {
                // we can use performant std::boyer_moore_searcher() in c++17
                Start = std::search(
                    Start,
                    buffer.end(),
                    std::boyer_moore_searcher(patternByteArray.begin(), patternByteArray.end())
                );

                // no pattern anymore
                if (Start == buffer.end()) break;

                PatternList.push_back(
                    (PBYTE)page.BaseAddress + std::distance(buffer.begin(), Start)
                );
            }

            if (PatternList.size() >= CountLimit) break;
        }

        return std::move(PatternList);
    }

    PVOID findInstruction(const std::string& Pattern)
    {
        PointerArray_t PatternList = findPatternInMemory(
            Pattern,
            1,
            PAGE_EXECUTE_READ
        );

        if (PatternList.empty()) return NULL;
        return PatternList[0];
    }

    PVOID findWritableAddress(size_t size, size_t Alignment = 1)
    {
        const size_t   LIMIT = 5;
        PVOID          ZeroStart;
        PointerArray_t FreeAreaList;

        for (const auto& page : getPagesInfo())
        {
            if (
                FreeAreaList.size() < LIMIT
                && page.RegionSize <= 1024 * 512          // limit to page under 512kb size
                && page.Type != MEM_PRIVATE               // if not in private area
                && page.Protect & PAGE_READWRITE          // must have r/w permission
                )
            {
                ByteArray_t buffer = readMemory(page.BaseAddress, page.RegionSize);

                ZeroStart = NULL;

                //
                // do linear search for memory buffer which is empty
                //

                Alignment = (std::max)(Alignment, (size_t)1);

                // split memory by Alignment block
                for (
                    size_t Address = buffer.size() / Alignment * (Alignment - 1);
                    FreeAreaList.size() < LIMIT;
                    Address -= Alignment
                    )
                {
                    size_t idx = Address;

                    // now search for NULL area with `size` width
                    for (
                        /**/;
                        idx < buffer.size() && idx < Address + size && buffer[idx] == '\0';
                        idx++
                        )
                    {
                    }

                    //
                    // if we have no problem (no non-NULL byte memory area)
                    // then return its virtual address
                    //

                    if (idx - Address == size) {
                        FreeAreaList.push_back((PBYTE)page.BaseAddress + Address);
                        break;
                    }
                }
            }
        }

        if (FreeAreaList.empty()) {
            return NULL;
        }

        std::random_device rd; // obtain a random number from hardware
        std::mt19937 eng(rd()); // seed the generator
        std::uniform_int_distribution<> distr(0, FreeAreaList.size()-1); // define the range

        return FreeAreaList[distr(eng)];
    }

    //
    // operation
    //

    //
    // Find first thread in process `pid` whose currently in 
    // alertable state, which is a requirement for queing an APC
    // procedure.
    // 
    // The method presented here is based on write-up by @odzhan:
    // https://modexp.wordpress.com/2019/08/27/process-injection-apc/
    //

    Thread findAlertableThread()
    {
        BOOL   bRet;
        DWORD  tid;
        DWORD  dRet;
        DWORD  idx;
        HANDLE hEvent;
        HANDLE TargetHandle;

        std::vector<HANDLE>  StoreEventHandle;
        std::vector<DWORD>   TidInOrder;

        // set default value to -1
        tid = -1;

        ThreadList_t ThreadList = getThreadList();

        for (const auto& [tid, thread] : ThreadList)
        {
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
                (PAPCFUNC)::GetProcAddress(GetModuleHandle(L"kernel32.dll"), "SetEvent"),
                thread.get(),
                (ULONG_PTR)TargetHandle
            );

            if (!dRet) {
                continue;
            }

            // we store this into seperate vector for the 
            // use of WaitForMultipleObjects later
            StoreEventHandle.push_back(hEvent);

            TidInOrder.push_back(tid);
        }

        if (!StoreEventHandle.empty()) {

            // now we wait for any of 
            // alertable thread to trigger
            idx = WaitForMultipleObjects(
                (DWORD)StoreEventHandle.size(),
                &StoreEventHandle[0],
                FALSE, // stop wait if any thread is alerted
                1000
            );

            // return thread ID which is alertable state
            if (idx != WAIT_TIMEOUT) {
                if (idx < ThreadList.size()) {
                    tid = TidInOrder[idx];
                }
            }

            // manually clean-up event object
            for (HANDLE handle : StoreEventHandle) {
                CloseHandle(handle);
            }
        }

        if (tid >= 0) {
            return std::move(ThreadList[tid]);
        }
        else {
            return Thread();
        }
    }

    //
    // injections
    //

    Thread CreateRemoteThread(PVOID addr, PVOID argv)
    {
        return Thread(
            ::CreateRemoteThread(
                hProcess,
                NULL,
                0,
                (LPTHREAD_START_ROUTINE)addr,
                argv,
                0,
                NULL
            ),
            TRUE
        );
    }

    DWORD APC_Injection(PVOID addr, PVOID argv)
    {
        Thread AlertableThread = findAlertableThread();
        
        if (AlertableThread.isError()) {
            return E_FAIL;
        }
        
        // Queue our APC into target alertable thread
        return ::QueueUserAPC(
            (PAPCFUNC)addr,
            *AlertableThread,
            (ULONG_PTR)argv
        );
    }



};

using ProcessList_t  = std::map<DWORD, Process>;

}