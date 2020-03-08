#pragma once

#include <Windows.h>
#include <memory>

namespace RAII {

	// -------------------------------------
	// Custom deleter for Windows Handle
	// that requiring CloseHandle() to close
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

	// ----------------------------------------------
	// Custom class to manage allocation/deallocation
	// of memory with VirtulAllocEx
	//

	struct VirtualAllocEx
	{
		HANDLE hProcess;
		LPVOID addr;
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

		LPVOID get()
		{
			return this->addr;
		}
		
		BOOL isError()
		{
			return this->error;
		}
	};

	// make our life a little bit easier
	using HandlePtr = std::unique_ptr<HANDLE, HandleDeleter>;
}