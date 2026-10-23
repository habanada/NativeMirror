#include <windows.h>
#include <pe_sieve_types.h>

struct VersionData {
    char signature[32];
    DWORD value;
};

static const VersionData version_data = {"NativeMirror.PESieve.Version", 0x00040105};

extern "C" const void* __cdecl PESieve_version()
{
    return &version_data.value;
}

extern "C" void __cdecl PESieve_help()
{
}

extern "C" pesieve::t_report __cdecl PESieve_scan(const pesieve::t_params*)
{
    pesieve::t_report report = {};
    report.errors = 1;
    return report;
}

extern "C" pesieve::t_report __cdecl PESieve_scan_ex(const pesieve::t_params* args,
    pesieve::t_report_type, char*, size_t, size_t*)
{
    return PESieve_scan(args);
}
