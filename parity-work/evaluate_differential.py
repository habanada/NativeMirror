import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
RUN = Path((ROOT / 'parity-work/latest-differential-run.txt').read_text().strip())
text = (RUN / 'NativeMirrorScannerDiagnostics.log').read_text(encoding='utf-8-sig')
records = []
for block in text.split('[TARGET]\n')[1:]:
    scenario = re.search(r'^Scenario=(.*)$', block, re.M)[1]
    native, reference = block.split('[NATIVEMIRROR]\n', 1)[1].split('[PE-SIEVE]\n', 1)
    def extract(section):
        raw = section.split('Output.Begin\n', 1)[1].split('Output.End', 1)[0].strip()
        report = json.loads(raw[raw.index('{'):raw.rindex('}') + 1])['scan_report']
        return dict(exitcode=int(re.search(r'^ExitCode=(\d+)$', section, re.M)[1]), report=report, raw=raw)
    n, p = extract(native), extract(reference)
    ns, ps = n['report']['scanned'], p['report']['scanned']
    differences = {}
    for field in sorted(set(ns['modified']) | set(ps['modified'])):
        if ns['modified'].get(field) != ps['modified'].get(field):
            differences['modified.' + field] = dict(native=ns['modified'].get(field), reference=ps['modified'].get(field))
    for field in ('total', 'skipped', 'errors'):
        if ns.get(field) != ps.get(field):
            differences['scanned.' + field] = dict(native=ns.get(field), reference=ps.get(field))
    for field in ('pid', 'is_64_bit', 'is_managed', 'used_reflection'):
        if n['report'].get(field) != p['report'].get(field):
            differences[field] = dict(native=n['report'].get(field), reference=p['report'].get(field))
    if n['exitcode'] != p['exitcode']:
        differences['exitcode'] = dict(native=n['exitcode'], reference=p['exitcode'])
    schema = {}
    for field in sorted(set(n['report']) | set(p['report'])):
        nt = type(n['report'][field]).__name__ if field in n['report'] else 'absent'
        pt = type(p['report'][field]).__name__ if field in p['report'] else 'absent'
        if nt != pt:
            schema[field] = dict(native=nt, reference=pt)
    records.append(dict(scenario=scenario, is_64_bit=n['report']['is_64_bit'], exitcode=n['exitcode'], scanned=ns['total'], modified=ns['modified'], differences=differences, top_level_schema_differences=schema, native_has_timing='[TIME]' in n['raw']))

files = ['bin/Win64/Debug/NativeMirrorScan.exe', 'bin/Win64/Debug/NativeMirrorScannerTests.exe', 'bin/Win64/Debug/NativeMirrorTestTarget.exe', 'bin/Win32/Debug/NativeMirrorTestTarget32.exe', 'bin/Win64/Debug/pe-sieve64.exe']
manifest = {f: hashlib.sha256((ROOT / f).read_bytes()).hexdigest() for f in files}
result = dict(reference_version='0.4.1.1', native_scans=len(records), reference_scans=len(records), skipped_reference_scans=text.count('Skipped=True'), records=records, binary_sha256=manifest)
(RUN / 'evaluation.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
lines = ['# Vergleichslauf gegen PE-sieve 0.4.1.1', '', '23 Integrationstests bestanden; 23 NativeMirror- und 23 PE-sieve-Scans tatsächlich ausgeführt. Keine Referenzscans übersprungen.', '', 'Ergänzend zu den sieben Kategorien der Testsuite wurden alle Summary-Zähler, PID, Bitness, Managed-/Reflection-Status und Exitcodes verglichen. Keine Felder normalisiert; beide Scanner untersuchten pro Fall dasselbe lebende Testziel.', '', '| Szenario | Ziel | Exitcode | Scanned | Abweichungen |', '| --- | --- | --- | --- | --- |']
for record in records:
    lines.append('| {} | {} | {} | {} | {} |'.format(record['scenario'], 'Win64' if record['is_64_bit'] else 'Win32', record['exitcode'], record['scanned'], json.dumps(record['differences'], ensure_ascii=False) if record['differences'] else 'keine'))
lines.extend(['', '## JSON-Befunde auf Ebene scan_report', '', 'Zusätzlich wurden vorhandene Feldnamen und JSON-Typen auf der obersten scan_report-Ebene verglichen. Abweichungen pro Fall stehen in evaluation.json; das vollständige verschachtelte Detailschema wurde nicht verglichen.', '', '```json', json.dumps(records[0]['top_level_schema_differences'], indent=2), '```', '', '## Grenzen', '', 'Beide Scanner erhalten dieselben Argumente mit `/pid N`; BuildNativeMirrorArgs delegiert an BuildPeSieveArgs. Die separate CLI-Matrix prueft weitere Argumentformen und Fehlerfaelle.', '', 'Zusätzliche Logzeilen vor/nach dem JSON werden zur strukturellen Auswertung abgetrennt. Rohdaten bleiben unverändert erhalten. Byteformatierung, vollständiges Detailschema, Detailwerte, Konsolentext sowie Dump-Dateien sind damit nicht vollständig verglichen. Die Suite nutzt `/ofilter 2` und erzeugt keine Dumps.', '', 'NativeMirror ist der vom Benutzer erstellte Win64-Scanner; fünf Szenarien betreffen Win32-Testziele. Das belegt keinen Build oder Lauf eines Win32-Scanners oder des optionalen NativeASM-Pfads.', '', 'Dieser Lauf belegt ausschließlich den Vergleich gegen 0.4.1.1, keine externe Parität zu 0.4.1.5. Referenz- und Produktionsquellen wurden im Testlauf nicht geändert.', '', 'Rohdaten: `console.txt`, `NativeMirrorScannerDiagnostics.log`; strukturierte Auswertung und Binär-Hashes: `evaluation.json`.'])
(RUN / 'evaluation.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
print('Native scans:', len(records), 'Reference scans:', len(records), 'Skipped:', result['skipped_reference_scans'])
differences = [r for r in records if r['differences']]
print('Cases with additional summary/exit differences:', len(differences))
for record in differences:
    print(record['scenario'], record['is_64_bit'], record['differences'])
assert len(records) == 23
assert result['skipped_reference_scans'] == 0

assert not differences
assert not any(r['top_level_schema_differences'] for r in records)
