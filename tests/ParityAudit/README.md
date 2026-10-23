# Module comparison: extra reproducible cases

Run from the project root:

```powershell
py tests/ParityAudit/run_module_cases.py
```

Uses the existing Win64 binaries (`NativeMirrorScan.exe` and a local 0.4.1.5 reference from `bin/Win64/Debug`, plus `pe-sieve64.exe` 0.4.1.1). Runs 19 identical argument pairs against our own controlled test processes; the padding case only writes into unused padding of its own test target and never executes that data. All test processes are terminated afterward. No Delphi build needed.

Exit code 1 means differences were found, not that the test passed. Results, stdout/stderr, files, comparison data, and binary hashes go under `parity-work/runs/<time>/module-audit` per run.

Only `scanner_version` is normalized. The known 0.4.1.1/0.4.1.5 thread JSON schema difference is flagged, not hidden by dropping fields; thread stack-frame counts are stored separately. A run with missing target fixtures does not count as passed.

`SectionOrder` checks patch IDs, ordering, and tag files across changes in at least three sections. `evaluate_thread_contract.py <run-dir>` separately checks the local 0.4.1.5 thread schema plus frames, last syscalls, and waiting-thread classification against the 0.4.1.1 EXE. The strict main matrix still reports the known schema difference. Entropy is not normalized; number format and export-alias layout must match the reference exactly.

`terminal-prolog32`/`terminal-prolog64` check that code prologues are still found at an exactly-trimmed buffer length - the general artifact search has its own exclusive end boundary per 0.4.1.5.

```powershell
py tests/ParityAudit/run_console_cases.py
```

Runs seven real scans, including ignored modules, thread scan, and `/quiet`. Normalizes version, banner build date, CRLF/LF, and only the time values of correctly formed scan-time lines - the lines themselves and their stage labels stay required. Region counts, module names, order, stdout/stderr, and exit codes stay strict. The previous EXE only passes `QuietClean`; fixing this needs a rebuild.

Before each console pair, a logged `/quiet` reference scan of the same target process runs first - the first scan changes that process's region layout (confirmed independently with `VirtualQueryEx` in both scanner orders), so the comparison scans start from that prepared state. The region count itself is not normalized.
