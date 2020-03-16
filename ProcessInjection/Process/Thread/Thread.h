#pragma once

#include "..\Common.h"
#include "..\Util.h"

namespace Process
{
    struct ThreadState
    {
        KTHREAD_STATE state;
        KWAIT_REASON reason;
    };

    class Thread
    {
    private:

        // common
        BOOL   _ShouldCloseHandle;
        HANDLE hThread;
        PVOID  StartAddress;

        // internal
        SYSTEM_EXTENDED_THREAD_INFORMATION ExSystemThreadInfo;
        SYSTEM_THREAD_INFORMATION          SystemThreadInfo;
        THREAD_BASIC_INFORMATION           ThreadBasicInfo;

        // error handling
        BOOL        Error;
        std::string ErrorStr;

        template <typename T>
        inline void UpdateInternalStruct(T& structure, HANDLE hThread, THREADINFOCLASS infoClass)
        {
            ZeroMemory(&structure, sizeof(structure));
            ByteArray_t buf_imageInfo = QueryInformationThread(
                hThread,
                infoClass,
                sizeof(T)
            );
            structure = *(T*)(&buf_imageInfo[0]);
        }

        void UpdateQueryInfo()
        {
            enumExtendedProcessInfo([&](
                const PSYSTEM_PROCESS_INFORMATION pProcessInfo,
                const PSYSTEM_EXTENDED_THREAD_INFORMATION pExThreadInfoList
                ) -> bool
            {
                if ((DWORD)pProcessInfo->UniqueProcessId == getPid()) {

                    // enumerate SYSTEM_EXTENDED_THREAD_INFORMATION array
                    for (size_t i = 0; i < pProcessInfo->NumberOfThreads; i++) {

                        DWORD _tid = (DWORD)pExThreadInfoList[i].ThreadInfo.ClientId.UniqueThread;

                        if (_tid == getTid()) {
                            ExSystemThreadInfo = pExThreadInfoList[i];
                            SystemThreadInfo = ExSystemThreadInfo.ThreadInfo;
                            return true;
                        }

                    }
                }

                return false;
            });
            
            UpdateInternalStruct(ThreadBasicInfo, hThread, ThreadBasicInformation);
        }

        void UpdateThread(DWORD tid)
        {
            if (hThread) {
                ::CloseHandle(hThread);
            }

            hThread = ::OpenThread(THREAD_ALL_ACCESS, NULL, tid);

            if (Error = !hThread) {
                ErrorStr = getLastErrorAsString();
                return;
            }

            UpdateQueryInfo();
        }

    public:

        Thread() = default;

        Thread(DWORD tid)
            : hThread(NULL)
            , _ShouldCloseHandle(TRUE)
        {
            UpdateThread(tid);
        }

        Thread(HANDLE _hThread, bool ShouldCloseHandle = FALSE)
            : hThread(_hThread)
            , _ShouldCloseHandle(ShouldCloseHandle)
        {
            if (Error = !hThread) {
                ErrorStr = "Null handle";
            }

            UpdateQueryInfo();
        }

        Thread(const Thread& other)
            : hThread(NULL)
            , _ShouldCloseHandle(TRUE)
        {
            UpdateThread(other.getTid());
        }

        ~Thread()
        {
            if (_ShouldCloseHandle) {
                ::CloseHandle(hThread);
            }
        }

        Thread& operator=(const Thread& other) noexcept {
            UpdateThread(other.getTid());
            return *this;
        }

        HANDLE operator*() const noexcept
        {
            return hThread;
        }

        HANDLE get() const noexcept {
            return hThread;
        }

        BOOL isError() noexcept
        {
            if (!Error && hThread == NULL) {
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

        DWORD getTid() const noexcept
        {
            return ::GetThreadId(hThread);
        }

        DWORD getPid() const noexcept
        {
            return ::GetProcessIdOfThread(hThread);
        }

        PTEB getTebAddress()
        {
            return ThreadBasicInfo.TebBaseAddress;
        }

        PVOID getEntryPointVA() const noexcept
        {
            PVOID       StartAddress = SystemThreadInfo.StartAddress;
            PVOID       StartAddressQuery;
            ByteArray_t buffer;
            
            // fetch from this API where possibly can
            buffer = QueryInformationThread(hThread, ThreadQuerySetWin32StartAddress);
            StartAddressQuery = *(PVOID*)&buffer[0];

            if (StartAddressQuery) {
                StartAddress = StartAddressQuery;
            }
            
            return StartAddress;
        }

        CONTEXT getContext() const noexcept
        {
            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_ALL;
            ::GetThreadContext(hThread, &ctx);
            return std::move(ctx);
        }

        BOOL setContext(const CONTEXT* ctx) noexcept
        {
            UpdateQueryInfo();

            // don't set context while thread is running
            if (SystemThreadInfo.ThreadState != Running) {
                return ::SetThreadContext(hThread, ctx);
            }

            return FALSE;
        }

        ThreadState getState()
        {
            UpdateQueryInfo();
            return {
                SystemThreadInfo.ThreadState,
                SystemThreadInfo.WaitReason
            };
        }

        BOOL isSuspended() noexcept
        {
            ThreadState state = getState();
            return state.state == Waiting && state.reason == Suspended;
        }

        DWORD Suspend() noexcept
        {
            if (!isSuspended()) {
                return ::SuspendThread(hThread);
            }

            return (DWORD)-1;
        }

        DWORD Resume() noexcept
        {
            if (isSuspended()) {
                return ::ResumeThread(hThread);
            }

            return (DWORD)-1;
        }
    };

    using ThreadList_t = std::map<DWORD, Thread>;
};