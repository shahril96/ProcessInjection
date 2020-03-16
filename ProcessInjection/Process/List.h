#pragma once

#include "Common.h"
#include "Util.h"
#include "Unit\Unit.h"

namespace Process
{

class ProcessList
{
private:

    using iterator = ProcessList_t::iterator;
    using const_iterator = ProcessList_t::const_iterator;

    // common
    ProcessList_t _ProcessList;

    // error handling
    BOOL        Error;
    std::string ErrorStr;

    void UpdateQueryInfo() noexcept
    {
        enumExtendedProcessInfo([&](
            const PSYSTEM_PROCESS_INFORMATION pProcessInfo,
            const PSYSTEM_EXTENDED_THREAD_INFORMATION pExThreadInfoList
            ) -> bool
        {
            DWORD _pid = (DWORD)pProcessInfo->UniqueProcessId;

            Process p(_pid);
            if (!p.isError()) {
                _ProcessList[_pid] = p;
            }

            return false;
        });
    }

public:

    ProcessList()
    {
        UpdateQueryInfo();
    }

    ~ProcessList()
    {
    }

    inline iterator begin()                           noexcept { return _ProcessList.begin();  }
    inline iterator end()                             noexcept { return _ProcessList.end();    }
    inline const_iterator cbegin()              const noexcept { return _ProcessList.cbegin(); }
    inline const_iterator cend()                const noexcept { return _ProcessList.cend();   }
    inline Process& operator[](DWORD key)             noexcept { return _ProcessList[key];     }
    inline const Process& operator[](DWORD key) const noexcept { return _ProcessList.at(key);  }

    const_iterator findProcessByName(const std::string& basename) const noexcept
    {
        return std::find_if(
            _ProcessList.begin(),
            _ProcessList.end(),
            [&](const std::pair<const DWORD, Process>& process) -> bool {
                if (process.second.getBaseName() == basename) {
                    return true;
                }
                return false;
            }
        );
    }

    // TODO:
    //  print tree view
};

}