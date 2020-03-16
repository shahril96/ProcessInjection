
#include "..\Common.h"

namespace Process
{
    using namespace std::chrono;

    typedef struct _module
    {
        // common
        std::string              BaseName;
        std::string              FileName;
        PVOID                    BaseAddress;
        PVOID                    EntryPoint;
        size_t                   Size;
        system_clock::time_point Time;

        // info
        std::string              Description;
        std::string              CompanyName;

        // protection
        bool                     ASLR;
        bool                     CFG;

        // verification
        bool                     Trusted;
        std::string              Signer;
    } Module;

    using ModuleList_t = std::vector<Module>;
};