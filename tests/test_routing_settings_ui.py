# Copyright (C) 2024–present  Loren Eteval & contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep application-routing settings entry points clear and independent."""

from __future__ import annotations

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read_source(relative_path: str) -> str:
    """Read one repository source file as UTF-8."""
    return (ROOT / relative_path).read_text(encoding='utf-8')


def translation_catalogue() -> dict:
    """Load the literal translation mapping without importing application code."""
    tree = ast.parse(read_source('Furious/Externals/GenTranslation.py'))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == 'TRANSLATION'
            for target in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError('TRANSLATION mapping was not found')


class RoutingSettingsUITest(unittest.TestCase):
    """Expose route-profile and application policies as separate settings actions."""

    def test_settings_show_two_independent_configuration_entries(self):
        source = read_source('Furious/Window/SettingsPage.py')
        self.assertIn(
            "_SettingsSection(_('Application & Routing Rules'))",
            source,
        )
        self.assertIn("_('Routing Rules Configuration')", source)
        self.assertIn("_('Application Rules Configuration')", source)
        self.assertIn('self._openRoutingEditor', source)
        self.assertIn('self._openApplicationRoutingEditor', source)
        self.assertIn(
            'self.routingSection.addCard(self.customRoutingCard)',
            source,
        )
        self.assertIn(
            'self.routingSection.addCard(self.applicationRoutingCard)',
            source,
        )
        self.assertNotIn('choose Application Rules to configure', source)

    def test_application_rules_open_directly_from_their_own_entry(self):
        source = read_source('Furious/Window/MainWindow.py')
        self.assertIn('openApplicationRoutingEditor=', source)
        self.assertIn(
            'from Furious.Backends.Xray.RoutingWindow import ApplicationRoutingDialog',
            source,
        )
        self.assertIn('ApplicationRoutingDialog(parent=self).open()', source)

    def test_route_profile_editor_does_not_embed_application_rules_action(self):
        source = read_source('Furious/Backends/Xray/RoutingWindow.py')
        self.assertNotIn('applicationRulesButton', source)
        self.assertNotIn('def openApplicationRules(', source)

    def test_new_settings_labels_and_descriptions_have_chinese_translations(self):
        catalogue = translation_catalogue()
        expected = {
            'Application & Routing Rules': '应用和路由规则',
            'Routing Rules Configuration': '路由规则配置',
            'Application Rules Configuration': '应用规则配置',
            (
                'Configure custom Xray routing profiles and define domain, IP, port, '
                'protocol, and process matching rules. Select a profile in the routing selector to apply it.'
            ): (
                '创建和编辑自定义 Xray 路由配置，可按域名、IP、端口、协议和进程匹配流量。'
                '保存后，在主界面的路由选择器中选择配置即可应用。'
            ),
            (
                'Configure per-application proxy or direct rules on Windows. Add running applications or browse to an EXE, then set rule order; current mode and protocol limitations are shown in the editor.'
            ): (
                '为 Windows 配置应用级代理或直连规则。可添加正在运行的应用或浏览选择 EXE，'
                '并设置规则顺序；当前模式和协议限制会在编辑窗口中说明。'
            ),
        }
        for key, translated in expected.items():
            with self.subTest(key=key):
                self.assertEqual(catalogue[key].get('ZH'), translated)


if __name__ == '__main__':
    unittest.main()
