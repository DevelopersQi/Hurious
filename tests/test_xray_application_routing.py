# Copyright (C) 2024–present  Loren Eteval & contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Test persistent Xray application routing policy."""

from __future__ import annotations

from unittest import TestCase, mock
import json

from Furious.Backends.Xray import Routing


class XrayApplicationRoutingRulesTest(TestCase):
    def setUp(self):
        self.saved = '[]'

    def settings(self):
        return mock.patch.object(
            Routing.AppSettings,
            'get',
            side_effect=lambda key: self.saved,
        ), mock.patch.object(
            Routing.AppSettings,
            'set',
            side_effect=self._save,
        )

    def _save(self, key, value):
        self.saved = value

    def test_save_normalizes_paths_and_sorts_by_priority(self):
        get_patch, set_patch = self.settings()
        with get_patch, set_patch:
            result = Routing.saveApplicationRoutingRules([
                {
                    'id': 'browser',
                    'name': 'Browser',
                    'process': r'C:\Apps\Browser\browser.exe',
                    'outboundTag': 'direct',
                    'priority': 20,
                },
                {
                    'id': 'game',
                    'name': 'Game',
                    'process': 'game.exe',
                    'outboundTag': 'proxy',
                    'priority': 10,
                },
            ])

            self.assertEqual(result[0]['process'], 'game.exe')
            self.assertEqual(result[0]['outboundTag'], 'proxy')
            self.assertEqual(
                result[1]['process'],
                'C:/Apps/Browser/browser.exe',
            )

    def test_disabled_rules_are_not_emitted(self):
        self.saved = json.dumps([
            {
                'process': 'disabled.exe',
                'outboundTag': 'proxy',
                'enabled': False,
            },
            {
                'process': 'enabled.exe',
                'outboundTag': 'direct',
                'enabled': True,
            },
        ])

        get_patch, _set_patch = self.settings()
        with get_patch:
            self.assertEqual(
                Routing.applicationRoutingRulesObject(),
                [{
                    'type': 'field',
                    'process': ['enabled.exe'],
                    'outboundTag': 'direct',
                }],
            )

    def test_duplicate_processes_are_rejected_case_insensitively(self):
        get_patch, set_patch = self.settings()
        with get_patch, set_patch:
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                Routing.saveApplicationRoutingRules([
                    {'process': 'Browser.exe', 'outboundTag': 'proxy'},
                    {'process': 'browser.EXE', 'outboundTag': 'direct'},
                ])

    def test_invalid_outbound_is_rejected(self):
        get_patch, set_patch = self.settings()
        with get_patch, set_patch:
            with self.assertRaisesRegex(ValueError, 'proxy or direct'):
                Routing.saveApplicationRoutingRules([
                    {'process': 'app.exe', 'outboundTag': 'block'},
                ])


    def test_proxy_core_processes_are_rejected(self):
        get_patch, set_patch = self.settings()
        with get_patch, set_patch:
            with self.assertRaisesRegex(ValueError, 'valid EXE path'):
                Routing.saveApplicationRoutingRules([
                    {'process': r'C:\\Tools\\xray.exe', 'outboundTag': 'direct'},
                ])


    def test_wfp_policy_uses_only_absolute_executable_paths(self):
        self.saved = json.dumps([
            {
                'name': 'Browser',
                'process': r'C:\Apps\Browser\browser.exe',
                'outboundTag': 'proxy',
                'priority': 20,
                'enabled': True,
            },
            {
                'name': 'Legacy name-only rule',
                'process': 'legacy.exe',
                'outboundTag': 'direct',
                'priority': 10,
                'enabled': True,
            },
            {
                'name': 'Disabled application',
                'process': r'C:\Apps\Disabled.exe',
                'outboundTag': 'direct',
                'priority': 30,
                'enabled': False,
            },
        ])
        get_patch, _set_patch = self.settings()
        with get_patch:
            self.assertEqual(
                Routing.getWfpApplicationRoutingRules(),
                [{
                    'image_path': r'C:\Apps\Browser\browser.exe',
                    'action': 'proxy',
                    'priority': 20,
                    'enabled': True,
                }],
            )

    def test_xray_core_bypass_rule_is_first_class_direct_policy(self):
        self.assertEqual(
            Routing.xrayCoreBypassRoutingRule(),
            {
                'type': 'field',
                'process': ['self/'],
                'outboundTag': 'direct',
                'ruleTag': 'Furious-Xray-Core-Bypass',
            },
        )

    def test_newline_and_wildcard_process_selectors_are_rejected(self):
        get_patch, set_patch = self.settings()
        with get_patch, set_patch:
            for process in ('browser\n.exe', 'browser*.exe', 'browser?.exe'):
                with self.subTest(process=process):
                    with self.assertRaisesRegex(ValueError, 'valid EXE path'):
                        Routing.saveApplicationRoutingRules([
                            {'process': process, 'outboundTag': 'proxy'},
                        ])

    def test_application_routing_table_sizes_rows_for_embedded_controls(self):
        from pathlib import Path

        source = Path('Furious/Backends/Xray/RoutingWindow.py').read_text(encoding='utf-8')
        self.assertIn('def _fitRowToCellWidgets(self, row):', source)
        self.assertIn('self.table.setRowHeight(row, max(34, max(heights) + 6))', source)
        self.assertEqual(source.count('self._fitRowToCellWidgets(row)'), 2)

    def test_invalid_persisted_json_falls_back_to_empty_policy(self):
        self.saved = '{invalid'
        get_patch, _set_patch = self.settings()
        with get_patch:
            self.assertEqual(Routing.getApplicationRoutingRules(), [])


if __name__ == '__main__':
    import unittest
    unittest.main()
