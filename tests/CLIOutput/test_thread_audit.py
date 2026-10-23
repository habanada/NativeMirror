import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ParityAudit'))
from thread_evidence import audit_reports


class ThreadAuditTests(unittest.TestCase):
    def setUp(self):
        self.evidence = dict(base=0x10000, size=4096, alloc_protection=4, curr_protection=0x20, bytes=(bytes(range(1, 39)) + bytes(4096 - 38)).hex())
        core = dict(status=1, thread_id=1, thread_info=dict(state='Waiting', callstack=dict(stack_ptr='20000', frames_count=2, frames=['1001f;', '30000;fixture.dll!Wait+0x2c'])), indicators=['SUS_START', 'SUS_CALLSTACK_SHC'])
        self.reference = dict(scanner_version='0.4.1.1', scans=[dict(thread_scan=copy.deepcopy(core))])
        self.reference['scans'][0]['thread_scan'].update(susp_addr='1001f', module='10000', module_size='1000', protection='4', stats=dict(area_start='0', area_size='4c', entropy=5.24793))
        core['thread_info']['callstack']['frames'][0] = '1001f'
        core['susp_areas'] = [dict(susp_addr=['10000', '1001f'], module='10000', module_size='1000', alloc_protection='4', curr_protection='20', is_code='0', stats=dict(area_start='0', area_size='26', entropy=5.24793))]
        self.native = dict(scanner_version='0.4.1.5', scans=[dict(thread_scan=core)])

    def test_only_source_validated_changes_pass(self):
        self.assertTrue(audit_reports(self.reference, self.native, self.evidence)['passed'])

    def test_uppercase_symbol_offset_fails(self):
        self.native['scans'][0]['thread_scan']['thread_info']['callstack']['frames'][1] = '30000;fixture.dll!Wait+0x2C'
        result = audit_reports(self.reference, self.native, self.evidence)
        self.assertFalse(result['passed'])
        self.assertEqual(result['unexpected_differences'][0]['path'], '/scans/0/thread_scan/thread_info/callstack/frames/1')

    def test_extra_indicator_fails(self):
        self.native['scans'][0]['thread_scan']['indicators'].append('SUS_RET')
        self.assertFalse(audit_reports(self.reference, self.native, self.evidence)['passed'])

    def test_wrong_area_value_fails(self):
        self.native['scans'][0]['thread_scan']['susp_areas'][0]['stats']['area_size'] = '4c'
        self.assertFalse(audit_reports(self.reference, self.native, self.evidence)['passed'])

    def test_unknown_nested_field_fails(self):
        self.native['scans'][0]['thread_scan']['thread_info']['unknown'] = 1
        self.assertFalse(audit_reports(self.reference, self.native, self.evidence)['passed'])

    def test_changed_legacy_value_fails(self):
        self.reference['scans'][0]['thread_scan']['stats']['area_size'] = '1'
        self.assertFalse(audit_reports(self.reference, self.native, self.evidence)['passed'])


if __name__ == '__main__':
    unittest.main()
