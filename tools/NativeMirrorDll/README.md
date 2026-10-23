# NativeMirror as a PE-sieve DLL

The Python step for the version data export is documented separately: [Why Python runs during the DLL build](README-PYTHON-BUILD-STEP.md).

Open `pe-sieve.dproj` in Delphi 12 and build **Win64 / Debug** or **Win32 / Debug** (Release also exists). Output: `bin\<Platform>\Debug\pe-sieve.dll`. The CLI/EXE does not need to be rebuilt for this.

The adapter in `src/Api/NativeMirror.Api.PeSieve.pas` calls the same `ScanAndDump` function and reports used by the Delphi library and CLI. It runs no scans of its own and passes no Delphi strings, objects, or dynamic arrays across the DLL boundary; the caller owns the JSON buffer memory.

## Contract and reference

Based on the unmodified local PE-sieve 0.4.1.5 files:

- `include/pe_sieve_api.h`, `include/pe_sieve_types.h`: C functions, records, enum values
- `pe_sieve_api.cpp`: argument checks, error returns, JSON buffer, size query, truncation, help
- `pe_sieve_ver_short.h`: version value `0x00040105`
- `main.def`: export names
- `postprocessors/report_formatter.cpp`: scan/dump/error report selection

Exports: `PESieve_help`, `PESieve_scan`, `PESieve_scan_ex`, and the **data export** `PESieve_version`. The two scan functions use the Windows C ABI for a 60-byte return record. The Delphi adapter declares the implicit return buffer explicitly and returns it as a pointer - these internal Pascal declarations are **not** DLL import declarations; C/C++ callers keep using the unmodified reference headers with record return.

Delphi cannot export a plain variable or an external data symbol with `exports` (E2121/E2276). So the DLL project exports a marked version DWORD via a placeholder helper function, and `finalize_exports.py` repoints the `PESieve_version` export entry at the real data address after linking, then updates the PE checksum (per the [Microsoft PE spec](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)). This helper implements no scanner or PE logic itself.

The post-build step is wired into `pe-sieve.dproj` and needs the `py` launcher. It fails the build on error, requires the four expected API exports, exactly one marked `0x00040105` version constant, and an unsigned x86/x64 DLL. It only touches the version export entry and the checksum; everything else is untouched. The freshly linked DLL is backed up first as `pe-sieve.dll.before-version-export`. The finished DLL needs no Python or extra runtime DLL.

Delphi's RTL also exports `__dbk_fcall_wrapper` and `dbkFCallWrapperAddr` (from `SysInit.pas` in Delphi 12). The build helper accepts the four API exports alone or together with exactly these two RTL exports; any other name is rejected. The RTL exports stay for the Delphi debugger - a documented extra surface beyond the four reference exports.

`pe-sieve.dll.exports.json` records the finished export address and SHA-256 hash. The test runner waits for a DLL with a matching record so it never loads a half-finished build. Running the build helper again on an already-finished file is a no-op.

Parameters are 360 bytes on Win64 and 344 bytes on Win32. Enum fields are 32-bit, C++ `bool` fields are one byte, `size_t`/pointers are architecture-dependent. ANSI input is converted to Delphi strings; a `PARAM_STRING`'s declared length only gates validation, the text itself still ends at NUL.

`PESieve_scan_ex` still performs a full scan even for a pure size query. `needed_size` counts UTF-8 bytes including NUL. A too-small buffer gets a terminated prefix. `REPORT_NONE` leaves the buffer untouched and returns size zero. An invalid parameter pointer returns `errors = 1` without touching any output pointer; a scan that cannot run returns `errors = 0xFFFFFFFF`.

JSON uses the existing shared serializer; its compact whitespace is not byte-identical to the indented C++ reports, but field names/values/report selection are checked, and the needed buffer size is computed from the real output bytes. Existing scanner parity gaps are not fixed by a matching DLL contract.

`PESieve_help` shows a MessageBox like the reference and writes to stdout; it is not exercised by the automated tests. The build date is refreshed in `NativeMirror.Api.BuildDate.inc` before each build.

## HollowsHunter

[HollowsHunter's build config](https://github.com/hasherezade/hollows_hunter/blob/master/CMakeLists.txt) defaults to `HH_PESIEVE_LINK_MODE=STATIC`; a DLL build needs `-DHH_PESIEVE_LINK_MODE=DLL` and a matching architecture/header contract - swapping files into a statically linked EXE does not work.

[HollowsHunter's scanner](https://github.com/hasherezade/hollows_hunter/blob/master/hh_scanner.cpp) calls `PESieve_scan` with `t_params` and reads the returned `t_report`. For a matching DLL build, NativeMirror's `pe-sieve.dll` can be placed next to HollowsHunter in a separate test directory without overwriting any existing install. The downloaded HollowsHunter 0.4.1.1 x64 DLL build was verified against NativeMirror on 2026-10-17: all six test states (Win64 Clean/HeaderPatch/CodePatch/PrivatePe, WOW64 Clean/PrivatePe) pass, with matching exit codes and full JSON (after normalizing the three time fields) against the bundled PE-sieve 0.4.1.1 DLL. This covers those integration cases only, not a full options/dump/duration test.

## Tests

The full HollowsHunter comparison is also a standalone Delphi/DUnitX run: [HollowsHunterIntegration](../../tests/HollowsHunterIntegration/README.md).

`tests/PeSieveDll` has two independent MSVC C++ callers against the unmodified reference headers - one loads exports dynamically, the other links a real import library including the data import. `pe-sieve.def` describes that import library and is not used to patch a built DLL.

The version build step is also tested against real MSVC test DLLs for Win32 and Win64: C data import fails before the step and works after; byte diff, PE checksum, repeatability, and rejection of bad markers/versions/exports/signed-or-corrupt files are all covered:

```powershell
py -m unittest discover -s tests/PeSieveDll -p test_version_export.py -v
```

Then, after the same CMake build:

```powershell
cmake -S tests/PeSieveDll -B parity-work/dll-contract-build-x64 -G "Visual Studio 17 2022" -A x64
cmake --build parity-work/dll-contract-build-x64 --config Debug
cmake -S tests/PeSieveDll -B parity-work/dll-contract-build-x86 -G "Visual Studio 17 2022" -A Win32
cmake --build parity-work/dll-contract-build-x86 --config Debug
py tests/PeSieveDll/run_contract.py --arch both
```

The runner checks ABI, data export, pointer errors, and buffer limits, plus `Clean`/`HeaderPatch`/`PrivatePe` against our own test targets, comparing the full parsed scan JSON between DLL and CLI without dropping fields. No third-party PE-sieve samples are run. Logs and DLL hashes land in a new `parity-work/dll-runtime-*` directory; `--wait 3600` lets the runner wait for an IDE build.

Win64 uses `bin\Win64\Debug\NativeMirrorTestTarget.exe` and `NativeMirrorScan.exe`; Win32 uses the existing Win32 test target. A DLL runtime result is only reported after an actual Delphi build; Win32, Win64, and the optional NativeASM path are separate proofs.
