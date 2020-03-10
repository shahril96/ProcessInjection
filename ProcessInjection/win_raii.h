#pragma once

#include <Windows.h>
#include <dbghelp.h>

#include <memory>

#pragma comment( lib, "dbghelp.lib" )

namespace RAII {

	// -------------------------------------
	// Custom deleters for Windows Handle
	//

	struct HandleDeleter {
		using pointer = HANDLE;
		void operator()(HANDLE h)
		{
			if (h != INVALID_HANDLE_VALUE) {
				::CloseHandle(h);
			}
		}
	};

	// -------------------------------------
	// Custom class for managing resume 
	// thread after it has been suspended
	//

	struct SuspendThread
	{
		BOOL    m_error;
		HANDLE  m_hThread;

		SuspendThread(const HANDLE _handle)
			: m_error(FALSE)
			, m_hThread(_handle)
		{
			m_error = ::SuspendThread(m_hThread) == -1;
		}

		~SuspendThread()
		{
			resume();
		}

		BOOL get_context(PCONTEXT context)
		{
			ZeroMemory(context, sizeof(*context));
			context->ContextFlags = CONTEXT_ALL;
			return ::GetThreadContext(m_hThread, context) != 0;
		}

		BOOL set_context(PCONTEXT context)
		{
			context->ContextFlags = CONTEXT_ALL;
			return ::SetThreadContext(m_hThread, context) != 0;
		}

		void resume()
		{
			m_error = ::ResumeThread(m_hThread) == -1;
		}
	};

	// -------------------------------------
	// Very simple RAII wrapper class for 
	// SymInitialize / SymCleanup
	//

	struct SymbolHandler
	{
		HANDLE m_hProcess;

		SymbolHandler(HANDLE _handle)
			: m_hProcess(_handle)
		{
			::SymInitialize(m_hProcess, NULL, TRUE);
		}

		~SymbolHandler()
		{
			::SymCleanup(m_hProcess);
		}
	};

	// ------------------------------------------------
	// Custom class to manage allocation/deallocation
	// of memory of foreign process
	//

	struct VirtualAllocEx
	{
		HANDLE hProcess;
		PVOID addr;
		size_t size;
		DWORD  protect;
		DWORD  allocation_type;
		BOOL   error;

		VirtualAllocEx()
			: hProcess(NULL)
			, addr(NULL)
			, size(0)
			, protect(PAGE_READWRITE)
			, allocation_type(MEM_RESERVE | MEM_COMMIT)
			, error(false)
		{
		}

		VirtualAllocEx(
			HANDLE _hProcess, 
			size_t _size, 
			DWORD _protect = PAGE_READWRITE,
			DWORD _allocation_type = MEM_RESERVE | MEM_COMMIT
		)
			: hProcess(NULL)
			, error(false)
		{
			this->reset(_hProcess, _size, _protect, _allocation_type);
		}

		~VirtualAllocEx()
		{
			this->free();
		}

		void free()
		{
			if (this->addr) {
				::VirtualFreeEx(this->hProcess, this->addr, 0, MEM_RELEASE);
			}

			this->addr = NULL;
			this->hProcess = NULL;
			this->size = NULL;
			this->protect = NULL;
			this->allocation_type = NULL;
		}

		void reset(
			HANDLE _hProcess,
			size_t _size,
			DWORD _protect = PAGE_READWRITE,
			DWORD _allocation_type = MEM_RESERVE | MEM_COMMIT
		)
		{
			if (_hProcess && _size) {

				this->free();

				this->hProcess			= _hProcess;
				this->size				= _size;
				this->protect			= _protect;
				this->allocation_type	= _allocation_type;

				this->addr = ::VirtualAllocEx(
					this->hProcess,
					NULL,
					this->size,
					this->allocation_type,
					this->protect
				);

				if (!this->addr) {
					// TODO: circular dependency bug
					//printf("VirtualAllocEx: %s\n", Util::GetLastErrorAsString().c_str());
					this->free();
					this->error = true;
				}
			}
		}

		void reset(VirtualAllocEx& inst)
		{
			if (inst.hProcess && inst.addr) {
				this->free();
				this->hProcess			= inst.hProcess;
				this->addr				= inst.addr;
				this->protect			= inst.protect;
				this->allocation_type	= inst.allocation_type;
				inst.hProcess			= 0;
				inst.addr				= 0;
				inst.protect			= NULL;
				inst.allocation_type	= NULL;
			}
		}

		// TODO: use one from util::
		// currently cant because dependency loop
		void info()
		{
			size_t					  sRet;
			MEMORY_BASIC_INFORMATION  info = { 0 };

			sRet = ::VirtualQueryEx(
				this->hProcess,
				this->addr,
				&info,
				sizeof(info)
			);

			if (sRet != sizeof(info)) {
				return;
			}

			printf(
				"%10p (%6uK)\t",
				this->addr,
				info.RegionSize / 1024
			);

			switch (info.State) {
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
			switch (info.Type) {
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

			if (info.AllocationProtect & PAGE_NOCACHE)
				nocache = 1;
			if (info.AllocationProtect & PAGE_GUARD)
				guard = 1;

			info.AllocationProtect &= ~(PAGE_GUARD | PAGE_NOCACHE);

			switch (info.Protect) {
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
	};

	// make our life a little bit easier
	using HandlePtr = std::unique_ptr<HANDLE, HandleDeleter>;
}