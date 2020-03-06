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

	struct VirtualAllocExWrapper
	{
		HANDLE hProcess;
		LPVOID addr;
		BOOL   error;

		VirtualAllocExWrapper()
			: hProcess(NULL)
			, addr(NULL)
			, error(false)
		{
		}

		VirtualAllocExWrapper(HANDLE _hProcess, size_t size)
			: hProcess(NULL)
			, error(false)
		{
			this->reset(_hProcess, size);
		}

		~VirtualAllocExWrapper()
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
		}

		void reset(HANDLE _hProcess, size_t size)
		{
			if (_hProcess && size) {

				this->free();

				this->hProcess = _hProcess;
				this->addr = ::VirtualAllocEx(
					this->hProcess,
					NULL,
					size,
					MEM_RESERVE | MEM_COMMIT,
					PAGE_READWRITE
				);

				if (!this->addr) {
					// TODO: circular dependency bug
					//printf("VirtualAllocEx: %s\n", Util::GetLastErrorAsString().c_str());
					this->free();
					this->error = true;
				}
			}
		}

		void reset(VirtualAllocExWrapper& inst)
		{
			if (inst.hProcess && inst.addr) {
				this->free();
				this->hProcess = inst.hProcess;
				this->addr = inst.addr;
				inst.hProcess = 0;
				inst.addr = 0;
			}
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