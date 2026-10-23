# NativeMirror scanner integration tests

This suite validates NativeMirror against controlled in-process artifacts and compares the main detection categories with PE-Sieve when available. The targets never modify another process, install persistence, contact a network endpoint, or execute an embedded PE image.

Projects:

- `NativeMirrorTestTarget.dproj`: Win64 target that creates stable test states.
- `NativeMirrorTestTarget32.dproj`: Win32 target used for WOW64 scanner parity tests.
- `NativeMirrorScannerTests.dproj`: Win64 DUnitX integration runner.

Core scenarios:

- `Clean`: unmodified control target.
- `HeaderPatch`: changes a DOS-header field in the running image.
- `NtHeaderPatch`: changes the PE optional-header checksum in memory.
- `SectionReplacement`: changes the first section-header file-layout field.
- `LastSectionReplacement`: changes the last section-header file-layout field.
- `CodePatch`: changes one byte in a local executable function.
- `MultipleCodePatches`: changes one byte in two distinct local executable functions and validates the patch count.
- `IatRedirect`: redirects the target's `IsDebuggerPresent` IAT slot to a local inert function.
- `PrivatePe`: maps one copy of the target PE into private memory and never executes it.
- `MultiplePrivatePe`: maps two distinct private PE images and validates both addresses.
- `PrivateExecutable`: creates a private executable region containing a deterministic inert custom SIG pattern.
- `PrivateExecutablePageBoundary`: places the same inert pattern across a 4 KB page boundary inside one executable allocation.
- `PrivateExecutableRegionTail`: places the pattern so it ends exactly at the allocation boundary.
- `MultiplePrivateExecutable`: creates two independent pattern-matched executable regions.
- `PrivateExecutableControl`: creates a private RX region without the custom pattern and expects no shellcode finding.
- `PrivateThread`: starts a private RX stub that only waits on an unsignaled event.
- `Mixed`: combines code patch, IAT redirect, private PE, and private thread artifacts.
- `MixedExtended`: combines two code patches, IAT redirect, two private PEs, a boundary pattern region, and a private thread.

WOW64 coverage runs `Clean`, `CodePatch`, `IatRedirect`, `PrivatePe`, and `PrivateExecutable` against the Win32 target while both scanners remain Win64.

Build output:

- EXE files: `bin\Win32\<Config>` and `bin\Win64\<Config>`.
- DCU files: `dcu\<ProjectName>\<Platform>\<Config>`.

The root `NativeMirror.groupproj` builds the Win32 target explicitly with `Platform=Win32` and the Win64 scanner, target, and DUnitX runner with their normal project platforms.

The test runner locates `NativeMirrorScan.exe` in the active Win64 output directory first. To select a specific scanner explicitly:

`set NATIVEMIRROR_SCAN_EXE=E:\Projects\NativeMirror\bin\Win64\Debug\NativeMirrorScan.exe`

Optional differential comparison against PE-Sieve:

`set PESIEVE_EXE=E:\Projects\NativeMirror\bin\Win64\Debug\pe-sieve64.exe`

Optional explicit Win32 target path:

`set NATIVEMIRROR_TARGET32_EXE=E:\Projects\NativeMirror\bin\Win32\Debug\NativeMirrorTestTarget32.exe`

When PE-Sieve is available, each scenario compares the main detection category counts produced by NativeMirror and PE-Sieve. Positive tests also validate the concrete target module, memory address, thread ID, or code-patch count so unrelated findings cannot satisfy a test accidentally.

Safety model:

- All mutations are confined to the test target itself.
- No remote process is opened or modified by a scenario.
- No persistence, networking, credential access, or destructive behavior is implemented.
- Private PE images are never executed.
- Custom executable patterns are inert data and are never invoked.
- The private thread executes only a local wait stub and is released during target teardown.

## Clean rebuild

If an extracted update contains changed Pascal units, run `CleanScannerIntegration.cmd` before rebuilding. This prevents older DCUs from being reused when their timestamps are newer than the extracted source files.

The test runner prints `NativeMirror ScannerIntegration build: 2026-10-02.2` before the DUnitX banner. If that line is missing, an older executable is running.
