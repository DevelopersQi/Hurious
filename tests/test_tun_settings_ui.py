# Copyright (C) 2024–present  Loren Eteval & contributors
#
# This file is part of Furious and is distributed under the GNU General Public
# License, version 3 or (at your option) any later version.

"""Regression tests for translated and responsive TUN settings forms."""

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
    source = read_source('Furious/Externals/GenTranslation.py')
    tree = ast.parse(source)

    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == 'TRANSLATION'
            for target in node.targets
        ):
            return ast.literal_eval(node.value)

    raise AssertionError('TRANSLATION mapping was not found')


class TUNSettingsUITest(unittest.TestCase):
    """Keep native and Tun2socks settings layouts consistent and translatable."""

    def test_editor_dialogs_allow_vertical_scrolling_for_long_forms(self):
        source = read_source('Furious/Qt/EditorWidgets.py')
        self.assertIn('self.tabScrollArea = QScrollArea(self.tabWidget)', source)
        self.assertIn('self.tabScrollArea.setWidgetResizable(True)', source)
        self.assertIn('self.tabScrollArea.setWidget(self.tabCentralWidget)', source)

    def test_native_tun_groups_use_one_responsive_form_layout(self):
        for relative_path, class_names in (
            (
                'Furious/Backends/Xray/TunSettingsDialog.py',
                (
                    'GuiXrayTUNSettingsGroupBoxInterface',
                    'GuiXrayTUNSettingsGroupBoxNetwork',
                ),
            ),
            (
                'Furious/Backends/Hysteria2/TunSettingsDialog.py',
                (
                    'GuiHysteria2TUNSettingsGroupBoxInterface',
                    'GuiHysteria2TUNSettingsGroupBoxNetwork',
                ),
            ),
        ):
            tree = ast.parse(read_source(relative_path))
            classes = {
                node.name: node
                for node in ast.walk(tree)
                if isinstance(node, ast.ClassDef)
            }

            for class_name in class_names:
                with self.subTest(path=relative_path, group=class_name):
                    methods = [
                        node
                        for node in classes[class_name].body
                        if isinstance(node, ast.FunctionDef)
                        and node.name == 'setupPageLayout'
                    ]
                    self.assertEqual(len(methods), 1)

                    method_source = ast.get_source_segment(
                        read_source(relative_path), methods[0]
                    )
                    self.assertIn('_singleColumnFormLayout', method_source)

    def test_native_tun_forms_do_not_disable_label_translation(self):
        hysteria = read_source('Furious/Backends/Hysteria2/TunSettingsDialog.py')
        self.assertNotIn('translatable=False', hysteria)

        xray = read_source('Furious/Backends/Xray/TunSettingsDialog.py')
        self.assertNotIn('maximumWidth=360', xray)

    def test_tun_backend_card_retranslates_from_original_keys(self):
        source = read_source('Furious/Window/SettingsPage.py')
        self.assertIn('self._titleKey = title', source)
        self.assertIn('self._descriptionKey = description', source)
        self.assertIn('self.titleLabel.setText(_(self._titleKey))', source)
        self.assertIn(
            'self.descriptionLabel.setText(_(self._descriptionKey))',
            source,
        )
        self.assertIn("            'TUN Backend',", source)

    def test_tun2socks_basic_form_wraps_labels_and_expands_inputs(self):
        source = read_source('Furious/Window/TunSettingsDialog.py')
        self.assertIn('QFormLayout.RowWrapPolicy.WrapAllRows', source)
        self.assertIn('QSizePolicy.Policy.Expanding', source)
        self.assertIn('inputWidget.setMinimumWidth(0)', source)

    def test_native_tun_labels_and_help_text_have_chinese_translations(self):
        catalogue = translation_catalogue()
        required = (
            'Interface',
            'Network',
            'Interface Name',
            'Interface Description',
            'User Level',
            'Automatic Outbound Interface',
            'MTU',
            'Timeout',
            'IPv4 TUN Address',
            'IPv6 TUN Address',
            'IPv4 Routes',
            'IPv6 Routes',
            'IPv4 Excluded Routes',
            'IPv6 Excluded Routes',
            'Gateway (separated by commas)',
            'DNS (separated by commas)',
            'AutoSystemRoutingTable (separated by commas)',
            'Xray gateway configures the virtual TUN interface, not the physical system gateway.',
            'Hysteria2 address.ipv4/ipv6 are virtual TUN addresses, not the physical adapter IP.',
            'Detected System Network',
            'Not detected',
            'Adapter: {name}    IPv4: {address}    Default gateway: {gateway}',
        )

        for key in required:
            with self.subTest(key=key):
                self.assertIn(key, catalogue)
                self.assertTrue(catalogue[key].get('ZH'))

    def test_system_network_widget_retranslates_its_visible_strings(self):
        source = read_source('Furious/Qt/SystemNetworkInfo.py')
        self.assertIn('class SystemNetworkInfoWidget(AppQGroupBox):', source)
        self.assertIn('def retranslate(self):', source)
        self.assertIn('self.refreshButton.setText(_(self._refreshKey))', source)
        self.assertIn('self._updateInfoLabel()', source)

    def test_detected_system_network_strings_are_registered(self):
        catalogue = translation_catalogue()
        for key in (
            'Detected System Network',
            'Not detected',
            'Adapter: {name}    IPv4: {address}    Default gateway: {gateway}',
        ):
            with self.subTest(key=key):
                self.assertIn(
                    'Furious.Qt.SystemNetworkInfo',
                    catalogue[key].get('source', []),
                )

    def test_new_native_tun_labels_are_registered_for_both_backends(self):
        catalogue = translation_catalogue()
        for key in (
            'Interface Name',
            'MTU',
            'IPv4 TUN Address',
            'IPv6 TUN Address',
            'IPv4 Routes',
            'IPv6 Routes',
        ):
            with self.subTest(key=key):
                sources = catalogue[key].get('source', [])
                self.assertIn('Furious.Backends.Xray.TunSettingsDialog', sources)
                self.assertIn('Furious.Backends.Hysteria2.TunSettingsDialog', sources)


if __name__ == '__main__':
    unittest.main()
