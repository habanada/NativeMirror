# CLI output source contracts

Run from the workspace root:

```powershell
py tests/CLIOutput/test_source_contract.py
```

These six static tests compare the Delphi summary's text tokens and field order
with the actual local PE-sieve 0.4.1.5 `report_formatter.cpp`. They check the
conditional implanted/error lines, the CLI's early return without a scan report,
the absence of CLI timing output, and unchanged scan exit-code selection.
They do not execute Delphi or prove scanner, JSON, or runtime output parity.
No volatile fields are normalized: the symbolic field mapping retains every
summary field, and text tokens retain spaces and newlines.

The baseline check uses `parity-work/baseline-20261016-output`, checks UTF-8 BOM
and newline preservation plus whitespace on added lines, and writes a unified
file comparison to `parity-work/output-changes.diff`. No Git command is used.

Both changed input files originally used LF and UTF-8 without BOM; that exact
format is retained. `sLineBreak` in the Delphi formatter represents Windows
runtime CRLF independently of the source file's line endings.
