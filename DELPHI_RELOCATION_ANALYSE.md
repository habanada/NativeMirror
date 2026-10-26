# Cause of the bds.exe / DelphiLSP.exe differences

Recorded on 2026-10-25. Evidence files referenced below are in `parity-work/runs/20261025-113134/delphi-analysis/` unless a full project path is given.

The investigation includes **22 successful version-comparison runs and 33 successful control runs using unchanged and deliberately modified captures**. The limits of this evidence are described below.

The additional code-patch findings from the tested original PE-sieve 0.4.1.1 executable are false positives in these cases. Its libpeconv dependency has an upstream-fixed bug: an IMAGE_REL_BASED_ABSOLUTE entry (type 0, padding) prematurely ends processing of the current relocation block. Valid entries after it are not applied.

NativeMirror and NativePe already handle this padding correctly, matching the newer reference used by PE-sieve 0.4.1.5. No NativeMirror or NativePe correction is required for this difference.

## Relevant code path

Both scanners load the original image from disk, relocate it to the target module's load address through `relocateToBase` or `RelocateToBase`, and compare its code sections with process memory.

- NativeMirror: `src/Scanner/NativeMirror.Scanner.Code.pas`, `ScanUsingBase`, line 466; `src/Scanner/NativeMirror.Scanner.ModuleData.pas`, `RelocateToBase`, line 322.
- Local original 0.4.1.5: `pe-sieve-master/pe-sieve-master/scanners/code_scanner.cpp`, `scanUsingBase`; `scanners/module_data.cpp`, `relocateToBase`. The four relevant local scanner files were checked against the saved upstream tree using their Git blob hashes (`source-provenance.json`).
- Old original dependency: `parity-work/relocation-probe/old/libpeconv/src/relocate.cpp`, line 73: `if (type == 0) { break; }`.
- Newer original dependency: `parity-work/relocation-probe/new/libpeconv/src/relocate.cpp`, line 82: advance the entry pointer and `continue`.
- NativePe: `E:/Projects/NativePe/src/NativePe.Relocate.pas`, line 135: for type 0, advance the entry pointer, increment the counter, and `Continue`.

Type 0 does not relocate an address, but valid relocations can follow it in the same block. The old `break` leaves those absolute addresses at the preferred image base in the comparison image, while Windows has already adjusted them to the actual load address in the target process. The scanner then reports these legitimate address differences as code patches.

The tested PE-sieve 0.4.1.1 version references libpeconv commit `7083def3d43f19245b9d7310939f18c01ac4c004`; the 0.4.1.5 reference uses `0fc25f680e03699d33ef3b2034a6724365f3d1a4`. The fix is [libpeconv commit `610a3e8f204341557dc956b7caa203e08df8d874`](https://github.com/hasherezade/libpeconv/commit/610a3e8f204341557dc956b7caa203e08df8d874), dated 2026-03-24. The local Git evidence, including the actual diff, is saved as `upstream-fix.txt`. Versioned online references are also stored under `parity-work/references/delphi-relocations/`.

## Evidence from the affected processes

Fresh process reports reproduced the same additional module findings. The executable sections of the affected DLLs were captured separately. File hashes ensure that the offline checks use the same disk files.

| DLL | Old reference's patch findings per instance | Differing code bytes with old libpeconv | With new libpeconv |
| --- | ---: | ---: | ---: |
| BrcIde.Dll | 704 | 1,408 | 0 |
| dcc32290.dll | 24,603 | 48,896 | 0 |
| dcc64290.dll | 27,770 | 55,424 | 0 |
| boreditu.dll | 581 | 1,152 | 0 |
| sqlite3.dll | 1,152 | 2,304 | 0 |

- bds.exe PID 13272: the first four DLLs.
- bds.exe PID 19348: the same four plus sqlite3.dll.
- DelphiLSP.exe PIDs 18488 and 20156: dcc64290.dll in each process.

These are eleven module instances with 164,008 additional patch records in total. Two checks were performed for each instance: every reported patch start corresponds to a difference explained by the old padding behavior, and all differing bytes left by the old relocation behavior are covered by the original report's patch intervals. Hook heuristics can combine adjacent bytes into one patch, so patch counts and differing-byte counts are not identical.

With all relocations applied, the entire captured `.text` section matches the target process byte for byte. No Delphi-specific exceptions or exclusions of suspicious regions were needed.

## Direct C++ comparison

Both diagnostic programs were rebuilt with `--clean-first`, using MSVC x64/Release. The libpeconv sources were unchanged exports of the two Git commits listed above, placed inside the project directory.

The same small C++ driver (`parity-work/relocation-probe/probe.cpp`) loads the original file using libpeconv, applies relocations at the recorded module base, and compares the captured code section. It neither executes code from the inspected DLLs nor modifies process memory.

**22 of 22 repeated calls passed:** the old and new original libraries were tested for each of the eleven module instances. Every call returned exit code 0 with empty stderr and no timeout. The old C++ library produced exactly the same remaining byte differences as the separate relocation model; the new C++ library produced zero differences in every case.

Results, including stdout, stderr, duration, and executable hash per call: `root-cause-verification.json`. Timing and scope of the repeated run: `probe-run.json`. Source and binary hashes: `source-provenance.json`. The old upstream build emits C4530 warnings about missing `/EHsc`; the successful load/relocation paths tested here do not throw an exception. Both builds succeeded.

Repeat the saved offline verification:

```powershell
py -u parity-work/verify_delphi_relocation_cause.py
```

## Control with a deliberate byte change

In addition to comparing the old and new original libraries, the newer C++ library was tested in three steps for each of the eleven module instances:

1. Unchanged captured code section: **0** differing bytes after relocation.
2. Separate copy with one bit flipped in the first section byte: **1** differing byte.
3. Repeat comparison with the unchanged original capture: **0** differing bytes again.

**33 of 33 control calls passed**, each with exit code 0, empty stderr, and no timeout. The original captured data was subsequently checked byte for byte to confirm it was unchanged. Only separate diagnostic copies were modified; running processes and installed DLL files were not modified. Detailed commands, stdout, stderr, and input hashes are recorded in [positive-control.json](parity-work/runs/20261025-113134/delphi-analysis/positive-control.json).

The control confirms that the old original library produces the explained relocation differences and that the corrected original library still detects an additional real byte change. This evidence covers the tested load/relocation/byte-comparison path. This additional control did not include a new live injection followed by a complete NativeMirror scan.

Reproduce after building the diagnostic programs:

```powershell
py -u parity-work/verify_delphi_relocation_cause.py
py -u parity-work/check_relocation_positive_control.py
```

Additional evidence:

- [Version comparison across eleven module instances](parity-work/runs/20261025-113134/delphi-analysis/root-cause-verification.json)
- [Timing and scope of the 22 calls after rebuilding](parity-work/runs/20261025-113134/delphi-analysis/probe-run.json)
- [Source and binary provenance](parity-work/runs/20261025-113134/delphi-analysis/source-provenance.json)
- [Upstream fix including the diff](parity-work/runs/20261025-113134/delphi-analysis/upstream-fix.txt)

The linked raw data and helper programs are in the Git-ignored `parity-work` directory. Anyone sharing this report or cloning only the repository also needs those local evidence files to reproduce this particular run fully.

## Limits

The result fully explains the eleven additional code-scan findings responsible for the differences in the four processes. It does not establish a general false-positive rate or full parity across all scanner features. The ten shared CLR patches and the shared Private-PE findings in the LSP processes were outside this investigation.

A complete PE-sieve 0.4.1.5 scanner was neither built nor run here; the relevant unchanged C++ dependencies from both versions were executed directly. NativeMirror was rerun against the targets using the existing Win64 Debug executable. This investigation did not include a Delphi rebuild, a Win32 scanner build, or a separate `USE_NATIVEASM` run. The original speed measurements were not repeated as part of the relocation verification.

No production sources of NativeMirror, NativePe, or PE-sieve were changed. This report is in the project root; diagnostic programs, raw data, and the original investigation report are under the already ignored `parity-work` directory.
