# System scan speed and Delphi findings

Build `tools/NativeMirrorScan/NativeMirrorScan.dproj` as **Win64 / Release** in Delphi first. Command line builds may be unavailable with the installed Delphi edition. Keep the existing Win32 and Win64 `Clean` test target EXEs in the paths used by ScannerIntegration.

Run from an administrator terminal at the project root, pointing at a verified original **PE-sieve 0.4.1.5 x64** executable:

```powershell
py tests/ParityAudit/run_system_benchmark.py --reference C:\path\to\original\pe-sieve64.exe
```

The default is three rounds. `--native` selects another NativeMirror build; `--rounds 1 --limit 2` is a short smoke test. `--timeout 30` limits each individual scan. The existing `bin/Win64/Debug/pe-sieve64.exe` reports **0.4.1.1**, so using it must be described as a comparison against that version. The script records version output and hashes; it does not certify the reference's provenance or enforce a particular version.

The script takes one process snapshot and attempts both scanners against every PID in each round, sequentially, alternating which scanner runs first. It excludes its own Python PID and adds two controlled clean Delphi processes (Win32 and Win64). Those fixtures are warmed with both scanners before measurement and stopped afterward. Normal system processes are never stopped, suspended or modified by the controller. Binary copies freeze the scanner inputs for the duration of the benchmark.

Both scanners receive `/pid N /ofilter 2 /quiet /json`; other engine settings use their respective defaults. This measures CLI startup, scan and JSON output together, with no dumps. It is a sequential CLI sweep, not a HollowsHunter DLL throughput measurement. No artificial workload is generated: the recorded process snapshot describes the actual system load.

Evidence is saved under `parity-work/runs/<timestamp>/system-benchmark/`:

- `manifest.json`, `*-version.txt`, `processes.json`: environment, binary identities and initial PID list.
- `round-N/PID/{native,reference}/`: raw stdout, stderr, exact commands, exit codes, elapsed wall time and parsed counters.
- `records.jsonl`: each pair is appended immediately, preserving progress if the controller is interrupted.
- `summary.json`, `summary.md`: completed pairs, errors/exclusions, timings and differences.
- `finding-comparison.json`: the complete emitted finding arrays for comparable pairs, compared strictly on fields, values and order.

Time comparisons include only pairs for which both scans finish successfully, report at least one scanned module and zero scan errors, and the PID creation time still matches the snapshot before and after the pair. Full attempt totals also include inaccessible processes and timeouts; keep these separate from comparable-process timings. An administrator can still lack access to protected processes. The three rounds use one initial snapshot; processes started later are outside this experiment.

`summary_equal` compares exit code and every field in `scanned` (including modified categories), PID, bitness, managed status and reflection status. It does **not** claim full report/module parity. Live processes can change between scans, so investigate differing pairs using their raw reports. Matching summary counts can still describe different modules. The result files retain all differences, including those caused by runtime activity.

Regenerate the summary from saved evidence without scanning again:

```powershell
py tests/ParityAudit/run_system_benchmark.py --summarize parity-work/runs/<timestamp>/system-benchmark
```

`complete` checks whether all planned pairs were recorded; interrupted runs remain partial. Strict finding-array differences can reflect ordering or live addresses as well as detections, and are reported without silent normalization.

To answer the Delphi false-positive question, inspect `controlled_delphi` in `summary.json`: a successful clean fixture should have exit code 1 and all modified counters zero. Report those two tested programs explicitly. Shared system findings are not automatically false positives; their benign cause must be established separately. Neither a port nor a small matching fixture set establishes identical false-positive rates across all Delphi programs.

For a public speed claim, disclose CPU/Windows, actual process coverage, privileges, versions, build configuration, options, median of the three comparable round ratios, exclusions and any differing results. A Debug-vs-release or 0.4.1.5-vs-0.4.1.1 run is exploratory and should be labelled accordingly.
