# HollowsHunter differential test (Delphi)

This DUnitX project runs HollowsHunter against the original PE-sieve DLL and against NativeMirror's DLL, scanning the same PID of a test process we start ourselves. The controller is Delphi; a normal run needs neither Python nor the C++ contract test programs.

## Build and run

1. `NativeMirrorScan` is not needed for this test. Build `pe-sieve.dproj` as Win64/Debug, including its version post-build step.
2. Build the existing `NativeMirrorTestTarget` and `NativeMirrorTestTarget32` projects.
3. Open `NativeMirrorHollowsHunterTests.dproj` in Delphi 12 and build **Win64/Debug**.
4. Run it (F9, or from the project root):

```powershell
bin\Win64\Debug\NativeMirrorHollowsHunterTests.exe
```

Exit code 0 means pass, nonzero means failure. Missing prerequisites are reported as errors, never silently skipped.

Uses DUnitX and the existing, read-only NativePe library for PE checks. The separate ScannerIntegration suite is its own, independent run.

## Required files

| File | Purpose |
| --- | --- |
| `fixtures\Win64\pe-sieve-C\hollows_hunter.exe` | Original HollowsHunter 0.4.1.1 x64 DLL build from the user-provided download. |
| `fixtures\Win64\pe-sieve-C\pe-sieve.dll` | Unmodified original PE-sieve 0.4.1.1 DLL from the same download. |
| `fixtures\Win64\pe-sieve-C\manifest.json` | Expected versions and SHA-256 hashes for the two files above. |
| `bin\Win64\Debug\pe-sieve.dll` | Current Delphi DLL build of NativeMirror. |
| `bin\Win64\Debug\pe-sieve.dll.exports.json` | Hash/version record from a successful version post-build step. |
| `bin\Win64\Debug\NativeMirrorTestTarget.exe` | Our own Win64 test process. |
| `bin\Win32\Debug\NativeMirrorTestTarget32.exe` | Our own Win32 test process (or next to the test runner). |

`NATIVEMIRROR_TARGET32_EXE` can pin the Win32 test process explicitly; `NATIVEMIRROR_TEST_ROOT` can set the project root (normally derived from `bin\Win64\<Config>`).

The original files already come from the provided download; the test downloads nothing. A version change to the originals needs a new, explicitly verified reference - a different hash is never auto-accepted.

## What is checked before scanning

- all required files exist
- the original EXE/DLL match their recorded SHA-256 hashes
- NativeMirror's DLL matches its export-record hash and reports version data export `0x00040105` (PE-sieve 0.4.1.5)
- the original DLL reports the expected `0x00040101` data export (0.4.1.1)
- host and DLLs are Win64; test targets have the right architecture and EXE/DLL type
- original and NativeMirror are different DLLs; the same HollowsHunter EXE is copied into both comparison folders

PE checks use NativePe without running the loaded code; the actual HollowsHunter run then also exercises real DLL loading and use.

## Per-run output folders

Each run creates a new folder under `parity-work\hollows-hunter-delphi-<time>-<guid>`:

```text
hollows-hunter-delphi-.../
  reference-manifest.json
  native-exports.json
  inputs.json
  pe-sieve-C/
    hollows_hunter.exe
    pe-sieve.dll
  pe-sieve-Pas/
    hollows_hunter.exe
    pe-sieve.dll
  Win64-Clean/
    comparison.json
    pe-sieve-C/
      command.txt
      stdout.txt
      stderr.txt
      process.json
      normalized.json
    pe-sieve-Pas/
      ...
  Win64-HeaderPatch/
  Win64-CodePatch/
  Win64-PrivatePe/
  WOW64-Clean/
  WOW64-PrivatePe/
```

Inputs are copied into both DLL directories before the test and the copies are verified; HollowsHunter loads its DLL from its own EXE's folder. Original files and current build output are never overwritten; a failed comparison keeps its raw data and error messages.

## Test cases

| Target arch | State | Expected detection | HollowsHunter exit code |
| --- | --- | --- | ---: |
| Win64 | Clean | none | 1 |
| Win64 | HeaderPatch | a header change | 2 |
| Win64 | CodePatch | a code change | 2 |
| Win64 | PrivatePe | a private PE image | 2 |
| WOW64 | Clean | none | 1 |
| WOW64 | PrivatePe | a private PE image | 2 |

Per variant:

```text
hollows_hunter.exe /pid <our test PID> /quiet /hooks /ofilter 2 /json /report 7
```

The test requires exactly one scanned process and zero scan errors. On a finding, it checks the specific PID, process name, and every expected detection category - an identical wrong result from both DLLs would still fail these independent checks.

Stdout/stderr are captured separately; stderr must be empty. Banners must match except for the verified PE-sieve version (original 0.4.1.1, NativeMirror 0.4.1.5). The rest of stdout must be fully parseable JSON, compared recursively on all field names, types, and values - object field order doesn't matter, array order does. Extra/missing fields, `null` instead of absence, duplicate fields, and any unknown value difference all fail the test.

## Exactly three normalized time fields

Only these root fields are stripped before the JSON comparison, each after its own validation:

| Field | Validation |
| --- | --- |
| `scan_date_time` | non-empty string in HollowsHunter's `mm/dd/yy hh:nn:ss` format, parsed as local time |
| `scan_timestamp` | integer; must match the parsed local time and fall within the measured process run, with 2s tolerance |
| `scan_time_ms` | integer >= 0, below the 60000 ms process timeout, at most measured runtime + 1000 ms |

Every other field is compared unchanged - no blanket exception for a whole test case or an unknown version difference. Extra DUnitX tests target the comparer itself: new fields, missing-vs-null, swapped arrays, wrong JSON types, unknown diffs, missing files, wrong version banners, and invalid time values.

## Scope and limits

The controller only starts its own six test targets and two HollowsHunter runs per target PID - no system-wide search, kill/suspend, ETW monitoring, or infinite loop. Process calls have a timeout; our test processes are killed even after a failure.

The original comparison DLL is **0.4.1.1**, not 0.4.1.5. This covers the tested HollowsHunter integration cases - it does not replace a full version-matched PE-sieve 0.4.1.5 differential test or the options/dump/reflection/duration tests.

The [Python build step for the version data export](../../tools/NativeMirrorDll/README-PYTHON-BUILD-STEP.md) is still part of building the DLL; this automated comparison run itself is plain Delphi.
