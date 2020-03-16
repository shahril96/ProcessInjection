#pragma once

#include "Common.h"

namespace Process
{
	namespace RAII
	{

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

		struct allocateMemory
		{
			HANDLE hProcess;
			PVOID  addr;
			size_t size;
			DWORD  protect;
			DWORD  allocation_type;

			allocateMemory()
				: hProcess(NULL)
				, addr(NULL)
				, size(0)
				, protect(PAGE_READWRITE)
				, allocation_type(MEM_RESERVE | MEM_COMMIT)
			{
			}

			allocateMemory(
				HANDLE _hProcess,
				size_t _size,
				DWORD _protect = PAGE_READWRITE,
				DWORD _allocation_type = MEM_RESERVE | MEM_COMMIT
			)
				: hProcess(NULL)
			{
				reset(_hProcess, _size, _protect, _allocation_type);
			}

			void operator=(allocateMemory& other)
			{
				hProcess = other.hProcess;
				addr = other.addr;
				protect = other.protect;
				allocation_type = other.allocation_type;

				// reset other object
				other.hProcess = NULL;
				other.addr = NULL;
				other.protect = NULL;
				other.allocation_type = NULL;
			}

			~allocateMemory()
			{
				this->free();
			}

			PVOID operator*() const noexcept
			{
				return addr;
			}

			//
			//
			//

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

					this->hProcess = _hProcess;
					this->size = _size;
					this->protect = _protect;
					this->allocation_type = _allocation_type;

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
					}
				}
			}
		};

		// make our life a little bit easier
		using HandlePtr = std::unique_ptr<HANDLE, HandleDeleter>;
	}
}