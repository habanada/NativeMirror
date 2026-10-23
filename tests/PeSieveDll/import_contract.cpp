#include <windows.h>
#include <pe_sieve_api.h>
#include <cstdio>

int main()
{
    if (PESieve_version != 0x00040105) return 1;
    auto report = PESieve_scan(nullptr);
    if (report.pid != 0 || report.errors != 1 || report.scanned != 0) return 1;
    size_t needed = 0x123456;
    char buffer[16] = "unchanged";
    report = PESieve_scan_ex(nullptr, pesieve::REPORT_ALL, buffer, sizeof(buffer), &needed);
    if (report.errors != 1 || needed != 0x123456 || buffer[0] != 'u') return 1;
    std::puts("PASS: imported C functions, struct return and version data");
    return 0;
}
