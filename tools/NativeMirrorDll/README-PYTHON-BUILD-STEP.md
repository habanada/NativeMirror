# Why Python runs during the DLL build

NativeMirror and its DLL are implemented in Delphi. Python runs on the build machine only for the version data export and for tests. The finished `pe-sieve.dll` needs no Python and contains no Python interpreter.

This describes PE-sieve **0.4.1.5**. General build instructions are in the [DLL README](README.md).

## What `PESieve_version` is

PE-sieve exports its version as a 32-bit value. For 0.4.1.5:

```text
DWORD: 0x00040105
Bytes in the DLL image: 05 01 04 00
```

A C++ caller expects the export `PESieve_version` to be the **address of this value**, and reads four data bytes there directly (`extern const DWORD` in `include/pe_sieve_api.h`, defined in `pe_sieve_api.cpp`).

Delphi 12's compiler/linker cannot export a plain variable via `exports` (E2121/E2276), and exporting an external data symbol from an object file was rejected the same way. A function that returns the version number would have the wrong contract: its export address would point at executable code, not at the raw value.

## Build flow

```text
pe-sieve.dpr + Delphi units
        |
        v
Delphi compiles and links pe-sieve.dll
  - scanner, dumper, and API are Delphi
  - the version number already exists as a data value in the DLL
  - PESieve_version initially points at a local helper function
        |
        v
PostBuildEvent runs finalize_exports.py
  - finds the marked data value
  - repoints the export address at that value
  - updates the PE checksum
  - re-verifies the result and writes a hash record
        |
        v
Finished pe-sieve.dll with a real version data export
        |
        v
C/C++ callers (or HollowsHunter) load the DLL,
read the version value, and call the scan functions - no Python needed
```

`NativeMirrorVersionData` in `pe-sieve.dpr` holds a marker (`NativeMirror.PESieve.Version`) plus the version number; `NativeMirrorVersionExport` returns its address. Delphi exports that local helper under the name `PESieve_version`. `finalize_exports.py` finds the marker, then replaces the export address table entry with the address of the marked value. The helper function stays in the file but is no longer reachable through that export.

## What the script changes

On a freshly linked DLL, the script only changes:

1. The 4-byte address entry for `PESieve_version` in the export address table.
2. The 4-byte PE checksum in the header.

Scanner code, other exports, parameter records, and version data are untouched. (PE export table layout: [Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).)

The script requires an unsigned Win32/Win64 DLL with the four expected API exports and exactly one correctly marked version value. Delphi's RTL exports `__dbk_fcall_wrapper` and `dbkFCallWrapperAddr` are also allowed and kept. Unexpected export names, wrong version data, or an invalid file structure are rejected. It backs up the freshly linked file before patching, verifies the result, and swaps it in via a temp file. Running it again on an already-finalized DLL leaves the bytes unchanged.

## Output files

In the output folder (e.g. `bin\Win64\Debug`):

| File | Meaning |
| --- | --- |
| `pe-sieve.dll` | Finished DLL after the post-build step. This is the file that gets used. |
| `pe-sieve.dll.before-version-export` | Backup of the just-linked file, before the export fix. |
| `pe-sieve.dll.exports.json` | Record of version value, export address, architecture, and SHA-256 hash of the finished DLL. |

A normal DLL caller needs neither of the last two. The test runner checks the JSON record against the DLL hash before loading it.

## How it's invoked

[pe-sieve.dproj](pe-sieve.dproj) runs it as a post-build step:

```text
py "$(MSBuildProjectDirectory)\finalize_exports.py" "$(DCC_ExeOutput)\pe-sieve.dll"
```

This needs Python 3 and the `py` launcher on the build machine. `PostBuildEventIgnoreExitCode=false` makes a helper failure fail the build. `GenDll=true` sets the `.dll` output extension.

A normal Delphi project build runs this automatically. After a direct compiler call that skips the project's PostBuildEvent, finalize it manually, e.g. from the project root:

```powershell
py tools/NativeMirrorDll/finalize_exports.py bin/Win64/Debug/pe-sieve.dll
```

A successful run reports `PESieve_version: data export verified` with the export address. A plain compile alone does not confirm this export.

## Python and C++ in the tests

| Part | Role |
| --- | --- |
| `finalize_exports.py` | One-time build step for the data export. Runs no scan. |
| `tests/PeSieveDll/test_version_export.py` | Tests the build helper: byte changes, checksum, repeatability, rejected error cases. |
| `tests/PeSieveDll/run_contract.py` | Runs our controlled test targets and the C++ callers; compares DLL and CLI results. |
| `contract.cpp` / `import_contract.cpp` | Independent C++ callers using the original PE-sieve headers. Check calling convention, record return, buffers, and data import. |
| `version_fixture.cpp` | Small C++ test DLL used only to test the build helper; not part of the shipped NativeMirror DLL. |

Python drives the tests; C++ checks the DLL the way a real C++ client would. The actual scan functions still call the shared Delphi core, `ScanAndDump`.

After the CMake build described in the [DLL README](README.md#tests):

```powershell
py -m unittest discover -s tests/PeSieveDll -p test_version_export.py -v
py tests/PeSieveDll/run_contract.py --arch both
```

Python was chosen because it was already available for test automation; the build helper could be rewritten in Delphi without changing the exported data.
