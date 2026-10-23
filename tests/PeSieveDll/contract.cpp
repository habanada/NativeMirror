#include <windows.h>
#include <pe_sieve_api.h>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

static_assert(sizeof(PEsieve_report) == 60);
static_assert(offsetof(PEsieve_report, scanned) == 8);
static_assert(offsetof(PEsieve_report, errors) == 56);
static_assert(offsetof(PEsieve_params, quiet) == 12);
static_assert(offsetof(PEsieve_params, out_filter) == 16);
static_assert(offsetof(PEsieve_params, shellcode) == 24);
static_assert(offsetof(PEsieve_params, iat) == 36);
static_assert(offsetof(PEsieve_params, dump_mode) == 48);
static_assert(offsetof(PEsieve_params, json_lvl) == 56);
static_assert(offsetof(PEsieve_params, output_dir) == 64);
static_assert(offsetof(PEsieve_params, modules_ignored) == 328);
#ifdef _WIN64
static_assert(sizeof(PEsieve_params) == 360);
static_assert(sizeof(pesieve::PARAM_STRING) == 16);
static_assert(offsetof(PEsieve_params, pattern_file) == 344);
#else
static_assert(sizeof(PEsieve_params) == 344);
static_assert(sizeof(pesieve::PARAM_STRING) == 8);
static_assert(offsetof(PEsieve_params, pattern_file) == 336);
#endif

static unsigned checks = 0;

static void require(bool condition, const char* message)
{
    ++checks;
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        std::exit(1);
    }
}

template<typename T> static T resolve(HMODULE library, const char* name)
{
    FARPROC address = GetProcAddress(library, name);
    require(address != nullptr, name);
    static_assert(sizeof(T) == sizeof(address));
    T result;
    std::memcpy(&result, &address, sizeof(result));
    return result;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2) return 2;
    HMODULE library = LoadLibraryW(argv[1]);
    require(library != nullptr, "LoadLibrary");
    auto scan = resolve<decltype(&PESieve_scan)>(library, "PESieve_scan");
    auto scan_ex = resolve<decltype(&PESieve_scan_ex)>(library, "PESieve_scan_ex");
    resolve<decltype(&PESieve_help)>(library, "PESieve_help");
    auto version = resolve<const DWORD*>(library, "PESieve_version");
    require(*version == 0x00040105, "version data export is 0.4.1.5");

    for (unsigned repetition = 0; repetition < 100; ++repetition) {
        const auto report = scan(nullptr);
        PEsieve_report expected = {};
        expected.errors = 1;
        require(std::memcmp(&report, &expected, sizeof(report)) == 0,
            "C struct return for null arguments");
    }

    char buffer[1024];
    std::memset(buffer, 'X', sizeof(buffer));
    size_t needed = 0x123456;
    auto report = scan_ex(nullptr, pesieve::REPORT_ALL, buffer, sizeof(buffer), &needed);
    require(report.pid == 0 && report.errors == 1, "scan_ex null arguments");
    require(buffer[0] == 'X' && buffer[1023] == 'X' && needed == 0x123456,
        "invalid arguments leave output parameters untouched");
    report = scan(reinterpret_cast<const PEsieve_params*>(1));
    require(report.errors == 1 && report.pid == 0, "unreadable params pointer");

    PEsieve_params params = {};
    params.pid = 0xFFFFFFFC;
    params.quiet = true;
    params.out_filter = pesieve::OUT_NO_DIR;
    params.results_filter = pesieve::SHOW_ALL;
    needed = 0x123456;
    report = scan_ex(&params, pesieve::REPORT_NONE, buffer, sizeof(buffer), &needed);
    require(report.pid == params.pid && report.errors == pesieve::ERROR_SCAN_FAILURE,
        "failed scan summary");
    require(needed == 0 && buffer[0] == 'X' && buffer[1023] == 'X',
        "REPORT_NONE preserves buffer and returns zero needed size");

    report = scan_ex(&params, pesieve::REPORT_ALL, nullptr, 0, &needed);
    require(report.errors == pesieve::ERROR_SCAN_FAILURE && needed > 1,
        "size-only error report request");
    const size_t required = needed;
    std::vector<char> complete(required + 16, 'X');
    report = scan_ex(&params, pesieve::REPORT_ALL, complete.data(), required, &needed);
    require(needed == required && report.errors == pesieve::ERROR_SCAN_FAILURE,
        "complete error report size");
    require(std::strlen(complete.data()) + 1 == required, "needed size includes NUL");
    require(complete[required] == 'X', "complete report respects capacity");
    const std::string json(complete.data());
    require(json.find("\"error_report\"") != std::string::npos &&
        json.find("\"err_message\"") != std::string::npos,
        "error report JSON wrapper");
    for (size_t capacity : {size_t(1), size_t(2), size_t(7), required - 1}) {
        std::vector<char> truncated(capacity + 16, 'X');
        scan_ex(&params, pesieve::REPORT_ALL, truncated.data(), capacity, &needed);
        require(needed == required, "truncation returns complete required size");
        require(std::memcmp(truncated.data(), json.data(), capacity - 1) == 0 &&
            truncated[capacity - 1] == 0, "truncated buffer is a NUL-terminated prefix");
        require(truncated[capacity] == 'X', "truncation respects capacity");
    }
    scan_ex(&params, pesieve::REPORT_ALL, buffer, 0, &needed);
    require(needed == required && buffer[0] == 'X', "zero capacity does not touch buffer");
    scan_ex(&params, pesieve::REPORT_ALL, reinterpret_cast<char*>(1), 32, &needed);
    require(needed == required, "unwritable JSON buffer still reports size");
    scan_ex(&params, pesieve::REPORT_ALL, buffer, sizeof(buffer), reinterpret_cast<size_t*>(1));
    require(buffer[0] == '{', "unwritable size pointer still returns JSON");

    params.results_filter = pesieve::SHOW_SUSPICIOUS;
    scan_ex(&params, pesieve::REPORT_ALL, buffer, sizeof(buffer), &needed);
    require(std::strstr(buffer, "error_report") == nullptr,
        "results filter suppresses error report");
    require(needed == std::strlen(buffer) + 1, "filtered JSON needed size");

    if (argc >= 3) {
        params.pid = std::wcstoul(argv[2], nullptr, 10);
        params.results_filter = pesieve::SHOW_ALL;
        params.no_hooks = false;
        needed = 0;
        report = scan_ex(&params, pesieve::REPORT_SCANNED, nullptr, 0, &needed);
        require(report.pid == params.pid && report.scanned > 0 &&
            report.errors != pesieve::ERROR_SCAN_FAILURE, "live target scan through C ABI");
        std::vector<char> live(needed + 65536);
        report = scan_ex(&params, pesieve::REPORT_SCANNED, live.data(), live.size(), &needed);
        require(report.scanned > 0 && std::strstr(live.data(), "\"scan_report\"") != nullptr,
            "live target scan JSON");
        require(needed == std::strlen(live.data()) + 1, "live JSON byte count");
        require(report.is_64bit == (sizeof(void*) == 8) &&
            !report.is_managed && !report.is_reflection, "C summary architecture and flags");
        if (argc >= 4) {
            FILE* output = nullptr;
            require(_wfopen_s(&output, argv[3], L"wb") == 0, "open live JSON evidence");
            require(std::fwrite(live.data(), 1, needed - 1, output) == needed - 1,
                "write live JSON evidence");
            std::fclose(output);
            const std::wstring summary_path = std::wstring(argv[3]) + L".summary";
            require(_wfopen_s(&output, summary_path.c_str(), L"wb") == 0, "open C summary evidence");
            require(std::fwrite(&report, sizeof(report), 1, output) == 1,
                "write C summary evidence");
            std::fclose(output);
        }
        std::printf("LIVE pid=%lu scanned=%lu suspicious=%lu\n",
            report.pid, report.scanned, report.suspicious);
    }
    FreeLibrary(library);
    std::printf("PASS: %u C ABI checks (%zu-bit)\n", checks, sizeof(void*) * 8);
    return 0;
}
