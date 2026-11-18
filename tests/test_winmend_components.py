"""Component diagnosis must separate device errors from physical failures."""
import unittest
from unittest.mock import patch

from winmend_components import build_component_report
from winmend_diagnostics import DeepProbe, describe_whea, render_case_report_html
from test_winmend_hardware import deep_build


class ComponentTests(unittest.TestCase):
    def test_completion_marker_survives_real_row_splitter(self):
        probe = DeepProbe()
        def shell(script, **kwargs):
            self.assertIn("COMPONENTS_OK|1", script)
            return 0, 'P|Chipset|System|PCI\\TEST|0|OK|Vendor\nCOMPONENTS_OK|1\n', ''
        probe._ps = shell
        result = probe.component_devices()
        self.assertTrue(result['available'])
        self.assertEqual(result['count'], 1)

    def parse(self, rows, rc=0):
        probe = DeepProbe()
        probe._ps_rows = lambda *a, **k: (rc, rows, "")
        return probe.component_devices()

    def test_failed_or_incomplete_queries_never_report_healthy(self):
        for rows, rc in (([], 0), ([["COMPONENTS_OK"]], 1)):
            self.assertFalse(self.parse(rows, rc)["available"])

    def test_disconnected_devices_are_excluded_and_missing_codes_stay_unknown(self):
        result = self.parse([["P", "Old USB", "USB", "old", "45", "", ""],
                             ["P", "Controller", "System", "pci", "", "", ""],
                             ["COMPONENTS_OK"]])
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["unknown"], 1)
        self.assertEqual(result["problems"], [])

    def test_every_device_class_has_a_home_and_specific_repair(self):
        rows = [["P", "Chipset", "System", "a", "28", "Error", "Vendor"],
                ["P", "USB", "USB", "b", "43", "Error", "Vendor"],
                ["P", "Camera", "Camera", "c", "22", "Error", "Vendor"],
                ["COMPONENTS_OK"]]
        result = self.parse(rows)
        self.assertEqual([d['component'] for d in result['devices']], ['motherboard', 'usb', 'other'])
        case = deep_build({'component_devices': result})
        components = {c['id']: c for c in case['components']}
        self.assertEqual(components['motherboard']['status'], 'attention')
        self.assertIn('driver is missing', ' '.join(components['motherboard']['next_steps']))
        self.assertIn('intentionally disabled', ' '.join(components['other']['next_steps']))
        self.assertIn('component_device_status', [h['id'] for h in case['hypotheses']])
        self.assertFalse(any(s.get('action') == 'enable_device' for s in case['plan']))

    def test_unavailable_collectors_never_get_a_clean_bill_of_health(self):
        self.assertTrue(all(c['status'] == 'unavailable' for c in build_component_report({}, [])))

    def test_missing_sensor_access_remains_visible(self):
        rows = build_component_report({'sensor_readings': {'available': True, 'exposes_nothing': True}}, [])
        cooling = next(c for c in rows if c['id'] == 'cooling')
        self.assertEqual(cooling['status'], 'unavailable')
        self.assertIn('no supported sensors', ' '.join(cooling['missing']))

    def test_incomplete_memory_pass_is_limited(self):
        rows = build_component_report({'memory_pattern_test': {'available': True, 'completed': False}}, [])
        memory = next(c for c in rows if c['id'] == 'memory')
        self.assertEqual(memory['status'], 'limited')
        self.assertIn('did not complete', ' '.join(memory['missing']))

    def test_firmware_fault_produces_vendor_follow_up_not_board_replacement(self):
        case = deep_build({'firmware_errors': {'available': True, 'acpi_errors': 2, 'days': 45}})
        hypothesis = next(h for h in case['hypotheses'] if h['id'] == 'motherboard_firmware_errors')
        self.assertIn('do not prove', hypothesis['explanation'])
        self.assertIn('BitLocker recovery key', hypothesis['advice'])

    def test_firmware_events_use_numeric_severity_in_non_english_windows(self):
        probe = DeepProbe()
        probe._ps_events = lambda *a, **k: (True, [['F', 'ACPI', '13', '2', '2026-09-01', 'error']], '')
        self.assertEqual(probe.firmware_errors()['acpi_errors'], 1)

    def test_corrected_whea_events_are_not_counted_as_fatal(self):
        probe = DeepProbe()
        probe._ps_events = lambda *a, **k: (True, [
            ['WHEA', str(i), 'Warning', '2026-09-01', 'Processor Cache Hierarchy Error']
            for i in (17, 19, 47, 999)], '')
        result = probe.whea_errors()
        self.assertEqual(result['uncorrected'], 0)
        self.assertEqual(result['corrected'], 3)
        self.assertEqual(result['unknown_severity'], 1)
        self.assertEqual(describe_whea(19, 'Processor Cache Hierarchy Error')[0], 'processor')

    def test_unknown_whea_codes_do_not_become_a_corrected_error_diagnosis(self):
        case = deep_build({'whea_errors': {'available': True, 'count': 20, 'uncorrected': 0,
                                          'corrected': 0, 'unknown_severity': 20, 'areas': {}}})
        self.assertNotIn('hardware_error', [h['id'] for h in case['hypotheses']])

    def test_report_carries_manual_repairs_and_escapes_device_text(self):
        case = deep_build({'component_devices': self.parse([
            ['P', '<script>alert(1)</script>', 'System', 'pci', '28', '', ''], ['COMPONENTS_OK']])})
        report = render_case_report_html(case)
        self.assertIn('Hardware coverage', report)
        self.assertIn('driver is missing', report)
        self.assertNotIn('<script>alert(1)</script>', report)


# Test the real Qt surface with synthetic evidence, never launch a repair tool.
from test_winmend_guided_page import PageHarness, HAVE_QT


@unittest.skipUnless(HAVE_QT, 'Qt unavailable')
class ComponentPageTests(PageHarness, unittest.TestCase):
    def test_repair_button_opens_plan_before_it_can_run(self):
        page = self._page()
        page._show_case(deep_build())
        with patch.object(page.win, '_start_case', create=True) as launch:
            page._run_plan()
            self.assertEqual(page.tabs.currentIndex(), 4)
            launch.assert_not_called()

    def test_hardware_case_selects_component_workspace_and_keeps_export_visible(self):
        page = self._page()
        page._show_case(deep_build())
        self.assertEqual(page.tabs.currentIndex(), 3)
        self.assertEqual(page.components.topLevelItemCount(), 12)
        self.assertTrue(page.report_btn.isVisibleTo(page))
        self.assertTrue(page.report_btn.isEnabled())
        self.assertIn('Motherboard', page.component_detail.toPlainText())

    def test_component_tool_uses_only_fixed_commands(self):
        page = self._page()
        page._show_case(deep_build())
        with patch('WinMend.subprocess.Popen') as launch:
            page._open_component_tool()
            self.assertTrue(launch.call_args.args[0][0].endswith('msinfo32.exe'))
            page._busy = True
            page._open_component_tool()
            self.assertEqual(launch.call_count, 1)

    def test_new_non_hardware_case_removes_stale_components(self):
        page = self._page()
        page._show_case(deep_build())
        page._show_case({'findings': [], 'hypotheses': [], 'plan': [], 'profile': 'general'})
        self.assertFalse(page.tabs.isTabVisible(3))
        self.assertEqual(page.components.topLevelItemCount(), 0)

    def test_cancel_restores_hardware_rescan(self):
        page = self._page()
        page._busy = True
        page._update_run_button()
        self.assertFalse(page.hardware_rescan_btn.isEnabled())
        page._sweep_cancelled()
        self.assertTrue(page.hardware_rescan_btn.isEnabled())
