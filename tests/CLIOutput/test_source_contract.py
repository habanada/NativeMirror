import difflib
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / 'pe-sieve-master/pe-sieve-master'
FIELDS = {
    'pid': 'Pid', 'scanned': 'Scanned', 'skipped': 'Skipped',
    'patched': 'Patched', 'replaced': 'Replaced', 'hdr_mod': 'HeaderModified',
    'iat_hooked': 'IatHooked', 'implanted': 'Implanted',
    'implanted_pe': 'ImplantedPe', 'implanted_shc': 'ImplantedShellcode',
    'unreachable_file': 'UnreachableFile', 'other': 'Other',
    'suspicious': 'Suspicious', 'errors': 'Errors',
}


class OutputSourceContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cli = (ROOT / 'tools/NativeMirrorScan/NativeMirrorScan.dpr').read_text()
        cls.tool = (ROOT / 'src/NativeMirrorScan.Tool.pas').read_text()
        cls.formatter = (ROOT / 'src/Core/NativeMirror.Core.Text.pas').read_text()
        cls.formatter = cls.formatter.split('implementation', 1)[1]
        cls.formatter = cls.formatter.split('function FormatScanSummary(', 1)[1]
        cls.formatter = cls.formatter.split('function ToLowerInvariant', 1)[0]
        cls.reference = (REFERENCE / 'postprocessors/report_formatter.cpp').read_text()
        cls.reference = cls.reference.split('std::string pesieve::err_report_to_json', 1)[0]
        cls.summary = cls.tool.split('procedure TNativeMirrorScanTool.EmitSummary(', 1)[1].split('function TNativeMirrorScanTool.CalculateExitCode(', 1)[0]

    def test_pinned_reference_version(self):
        version = (REFERENCE / 'pe_sieve_ver_short.h').read_text()
        self.assertRegex(version, r'#define PESIEVE_VERSION_STR\s+"0\.4\.1\.5"')

    def test_all_text_tokens_and_fields_match_reference(self):
        expected = []
        for statement in re.findall(r'\bstream\s*<<(.*?);', self.reference, re.S):
            for item in re.finditer(r'"([^"\\]*(?:\\.[^"\\]*)*)"|report\.(\w+)|\b(other)\b|std::(endl)', statement):
                literal, field, other, endl = item.groups()
                if literal is not None:
                    expected.append(bytes(literal, 'utf-8').decode('unicode_escape'))
                elif field or other:
                    expected.append('{' + FIELDS[field or other] + '}')
                elif endl:
                    expected.append('\n')
        actual = []
        for item in re.finditer(r"'([^']*)'|UIntToStr\(Summary\.(\w+)\)|\b(sLineBreak)\b", self.formatter):
            literal, field, newline = item.groups()
            actual.append(literal if literal is not None else ('{' + field + '}' if field else '\n'))
        self.assertEqual(''.join(expected), ''.join(actual))

    def test_conditional_lines_match_reference(self):
        self.assertRegex(self.reference, r'if \(report\.implanted\)\s*\{\s*stream << "Implanted PE:')
        self.assertRegex(self.reference, r'if \(report\.errors\)\s*\{\s*stream << "\[!\] Errors:')
        self.assertRegex(self.formatter, r"if Summary\.Implanted <> 0 then\s*Result := Result \+\s*'Implanted PE:")
        self.assertRegex(self.formatter, r"if Summary\.Errors <> 0 then\s*Result := Result \+ '\[!\] Errors:")

    def test_no_scan_report_suppresses_both_summary_modes(self):
        main = (REFERENCE / 'main.cpp').read_text()
        self.assertLess(main.index('if (!report.scan_report) return;'), main.index('if (args.json_output)'))
        guard = 'if not Assigned(Report) or not Assigned(Report.ScanReport) then Exit;'
        self.assertLess(self.summary.index(guard), self.summary.index('if FOptions.JsonOutput then'))
        self.assertNotIn('ErrorReport.Message', self.summary)

    def test_cli_output_and_exitcode_regressions(self):
        self.assertNotIn('[TIME]', self.cli)
        self.assertNotIn('TStopwatch', self.cli)
        self.assertIn("Emit(nmScanResult, FormatScanSummary(Report.ScanReport.GenerateSummary) + '---' + sLineBreak);", self.summary)
        self.assertIn('if Kind = nmScanTiming then Exit;', self.cli)
        self.assertNotIn('DumpReport', self.summary)
        self.assertIn('Json := Report.ToJson(FOptions.ResultsFilter, FOptions.JsonLevel);', self.summary)
        self.assertIn('if Summary.Suspicious > 0 then Result := 2 else Result := 1;', self.tool)

    def test_baseline_comparison_and_encoding(self):
        baseline = ROOT / 'parity-work/baseline-20261016-output'
        patches = []
        for relative in ('src/Core/NativeMirror.Core.Text.pas', 'tools/NativeMirrorScan/NativeMirrorScan.dpr'):
            old = (baseline / relative).read_bytes()
            new = (ROOT / relative).read_bytes()
            self.assertEqual(old.startswith(b'\xef\xbb\xbf'), new.startswith(b'\xef\xbb\xbf'))
            self.assertEqual(b'\r\n' in old, b'\r\n' in new)
            old_lines = old.decode('utf-8').splitlines(keepends=True)
            new_lines = new.decode('utf-8').splitlines(keepends=True)
            patches.extend(difflib.unified_diff(old_lines, new_lines, fromfile='before/' + relative, tofile='after/' + relative))
            added = [line[2:] for line in difflib.ndiff(old_lines, new_lines) if line.startswith('+ ')]
            for line in added:
                self.assertEqual(line.rstrip('\r\n'), line.rstrip())
        (ROOT / 'parity-work/output-changes.diff').write_text(''.join(patches), encoding='utf-8')


if __name__ == '__main__':
    unittest.main()
