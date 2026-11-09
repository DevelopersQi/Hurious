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

    def test_tun2socks_basic_and_memory_groups_share_wrapped_layout(self):
        source = read_source('Furious/Window/TunSettingsDialog.py')
        tree = ast.parse(source)
        classes = {
            node.name: node
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef)
        }

        for class_name in (
            'GuiTUNSettingsGroupBoxBasic',
            'GuiTUNSettingsGroupBoxMemory',
        ):
            with self.subTest(group=class_name):
                methods = [
                    node
                    for node in classes[class_name].body
                    if isinstance(node, ast.FunctionDef)
                    and node.name == 'setupPageLayout'
                ]
                self.assertEqual(len(methods), 1)
                method_source = ast.get_source_segment(source, methods[0])
                self.assertIn('QFormLayout.RowWrapPolicy.WrapAllRows', method_source)

        self.assertIn('if isinstance(inputWidget, QLineEdit)', source)

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
            'Basic Configuration',
            'Memory Optimization',
            'Primary Adapter Interface Name',
            'Primary Adapter Interface IP',
            'Default Primary Gateway IP',
            'Tun2socks Adapter Interface DNS',
            'Bypass Tun2socks Adapter Interface IP (separated by commas)',
            'Disable Primary Adapter Interface DNS (Mitigating DNS leaks on Windows)',
            'Automatically Detect Primary Adapter Network Settings',
            'TCP Send Buffer Size (MiB)',
            'TCP Receive Buffer Size (MiB)',
            'TCP Receive Buffer Auto-tuning',
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
            'TUN Backend',
            'Choose how system traffic is routed. Automatic selects the native backend when supported and otherwise uses Tun2socks.',
            'Auto (Recommended)',
            'Use native TUN when supported; otherwise use Tun2socks.',
            'Tun2socks',
            'Compatibility mode using the Tun2socks adapter.',
            'Xray-core Native TUN',
            'Use Xray-core built-in TUN.',
            'Hysteria 2 Native TUN',
            'Use Hysteria 2 built-in TUN.',
            'Actual TUN backend: connecting…',
            'Actual TUN backend: not connected',
            'Actual TUN backend: {backend}',
            'TUN is not active',
            'Gateway (separated by commas)',
            'DNS (separated by commas)',
            'AutoSystemRoutingTable (separated by commas)',
            'Xray gateway configures the virtual TUN interface, not the physical system gateway.',
            'Hysteria2 address.ipv4/ipv6 are virtual TUN addresses, not the physical adapter IP.',
            'Detected System Network',
            'Not detected',
            'Adapter: {name}    IPv4: {address}    Default gateway: {gateway}',
                        'Application & Routing Rules',
            'Routing Rules Configuration',
            'Application Rules Configuration',
            'Configure custom Xray routing profiles and define domain, IP, port, protocol, and process matching rules. Select a profile in the routing selector to apply it.',
            'Configure per-application proxy or direct rules on Windows. Add running applications or browse to an EXE, then set rule order; current mode and protocol limitations are shown in the editor.',
            'Hysteria 2 Native TUN is not supported by the selected Xray-core configuration. Open Settings > TUN Backend and select Auto or Xray-core Native TUN.',
            'Xray-core Native TUN is not supported by the selected Hysteria 2 configuration. Open Settings > TUN Backend and select Auto or Hysteria 2 Native TUN.',
        )

        for key in required:
            with self.subTest(key=key):
                self.assertIn(key, catalogue)
                self.assertTrue(catalogue[key].get('ZH'))

    def test_automatic_tun_backend_matches_the_active_core(self):
        settings = read_source('Furious/Controllers/SettingsController.py')
        self.assertIn("default='auto'", settings)
        self.assertIn("validRange=[value for _label, value in TUN_BACKEND_OPTIONS]", settings)

        page = read_source('Furious/Window/SettingsPage.py')
        self.assertIn("selectedBackend = 'auto'", page)

        source = read_source('Furious/Service/ConnectionManager.py')
        self.assertIn("'official.xray': 'xray'", source)
        self.assertIn("'official.hysteria2': 'hysteria2'", source)
        self.assertIn(
            "if tunBackend == 'auto' and automaticBackend:",
            source,
        )
        self.assertIn(
            'pluginTUN = registry.prepareTUN(config, automaticBackend)',
            source,
        )

    def test_settings_categories_separate_tun_dns_from_system_proxy(self):
        source = read_source('Furious/Window/SettingsPage.py')
        self.assertIn("self.tunSection = _SettingsSection(_('TUN & DNS'))", source)
        self.assertIn("self.tunSection.addCard(self.tunSettingsCard)", source)
        self.assertIn("self.tunSection.addCard(self.tunModeCard)", source)
        self.assertIn("self.tunSection.addCard(self.tunBackendCard)", source)
        self.assertIn("self.connectionSection.addCard(self.systemProxyCard)", source)
        self.assertIn("('TUN & DNS', (self.tunSection,))", source)
        self.assertIn('self.categoryList.currentRowChanged.connect(', source)
        self.assertIn('self.categoryStack.setCurrentIndex', source)

    def test_settings_category_names_have_chinese_translations(self):
        catalogue = translation_catalogue()
        self.assertEqual(catalogue['TUN & DNS'].get('ZH'), 'TUN 与 DNS 设置')
        for key in (
            'General',
            'Connection',
            'TUN & DNS',
            'Application & Routing Rules',
            'Network',
            'Privacy and Statistics',
            'Advanced',
            'Application',
            'Plugins',
        ):
            with self.subTest(key=key):
                self.assertIn(key, catalogue)
                self.assertTrue(catalogue[key].get('ZH'))

    def test_manual_tun_backend_overrides_are_kept_out_of_general_settings(self):
        source = read_source('Furious/Window/SettingsPage.py')
        self.assertNotIn(
            'self.generalSection.addCard(self.tunBackendCard)',
            source,
        )
        self.assertIn(
            'self.tunSection.addCard(self.tunBackendCard)',
            source,
        )

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


    def test_tun_backend_selection_uses_consistent_radio_indicators(self):
        source = read_source('Furious/Window/SettingsPage.py')
        self.assertIn(
            'QRadioButton#TUNBackendOptionRadio::indicator',
            source,
        )
        self.assertIn(
            'QRadioButton#TUNBackendOptionRadio::indicator:checked',
            source,
        )
        self.assertIn('border-radius: 8px;', source)
        self.assertIn("AppStyleSheet.paletteForTheme(theme)", source)
        self.assertIn("background-color: {palette['accent']};", source)
        self.assertIn("background-color: {palette['panel']};", source)
        self.assertNotIn(
            'QCheckBox#TUNBackendOptionRadio::indicator',
            source,
        )


    def test_normal_launch_resets_tun_and_only_runas_admin_launch_enables_it(self):
        source = read_source('Furious/Application/DesktopApplication.py')
        self.assertIn(
            'AppBuiltinCommand.RunAs.value in sys.argv[1:]',
            source,
        )
        self.assertIn(
            'and SystemRuntime.isAdmin()',
            source,
        )
        self.assertIn("AppSettings.turnON_('VPNMode')", source)
        self.assertIn("AppSettings.turnOFF('VPNMode')", source)
        self.assertIn(
            'reset persisted TUN mode for a normal application launch',
            source,
        )

    def test_home_tun_title_is_stable_and_switch_owns_the_actual_state(self):
        source = read_source('Furious/Window/TunSettingsDialog.py')
        tree = ast.parse(source)
        function = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == 'tunModeTitle'
        )
        function_source = ast.get_source_segment(source, function)

        self.assertIn("return _('TUN Mode')", function_source)
        self.assertNotIn('SystemRuntime.isAdmin()', function_source)
        self.assertNotIn('TUN Mode Disabled', function_source)

        home = read_source('Furious/Window/HomePage.py')
        self.assertIn("self.tunModeSwitch.toggled.connect(self.handleTUNModeChanged)", home)
        self.assertIn('AppSettingsController().setTUNMode(enabled)', home)

    def test_home_and_settings_tun_switches_share_the_elevation_handoff(self):
        home = read_source('Furious/Window/HomePage.py')
        settings = read_source('Furious/Window/SettingsPage.py')
        self.assertIn('self.tunModeSwitch.toggled.connect(self.handleTUNModeChanged)', home)
        self.assertIn('self.tunModeSwitch.syncChecked(False)', home)
        self.assertIn('self.restartAsAdmin()', home)
        self.assertIn('self._restartAsAdmin()', settings)
        self.assertIn('return False', settings)
        self.assertIn(
            'self.tunModeCard.checkBox.syncCheckedAnimated',
            settings,
        )


    def test_settings_show_two_independent_configuration_entries(self):
        source = read_source('Furious/Window/SettingsPage.py')
        self.assertIn(
            "_SettingsSection(_('Application & Routing Rules'))",
            source,
        )
        self.assertIn("_('Routing Rules Configuration')", source)
        self.assertIn("_('Application Rules Configuration')", source)
        application_index = source.index("self.applicationRoutingCard = None")
        routing_index = source.index("self.customRoutingCard = None")
        self.assertLess(application_index, routing_index)
        self.assertIn('first matching rule wins', source)
        self.assertIn('Priority against routing rules depends on the selected backend.', source)
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
        routingEntry = source[
            source.index('self.customRoutingCard = None'):
            source.index('self.connectionSection.addCard(self.proxyBypassCard)')
        ]
        self.assertNotIn('choose Application Rules to configure', routingEntry)

    def test_application_rules_open_directly_from_their_own_entry(self):
        source = read_source('Furious/Window/MainWindow.py')
        self.assertIn('openApplicationRoutingEditor=', source)
        self.assertIn(
            'from Furious.Backends.Xray.RoutingWindow import ApplicationRoutingDialog',
            source,
        )
        self.assertIn('self._applicationRoutingDialog = dialog', source)
        self.assertIn('dialog.finished.connect(self._applicationRoutingDialogFinished)', source)
        self.assertIn('self._applicationRoutingDialog.raise_()', source)

    def test_route_profile_editor_does_not_embed_application_rules_action(self):
        source = read_source('Furious/Backends/Xray/RoutingWindow.py')
        self.assertNotIn('applicationRulesButton', source)
        self.assertNotIn('def openApplicationRules(', source)

    def test_routing_settings_descriptions_have_chinese_translations(self):
        catalogue = translation_catalogue()
        expected = {
            'Application & Routing Rules': '应用和路由规则',
            'Routing Rules Configuration': '路由规则配置',
            'Application Rules Configuration': '应用规则配置',
            (
                'Set proxy or direct actions for individual Windows applications. Within this list, rules are checked from top to bottom and the first matching rule wins. Priority against routing rules depends on the selected backend.'
            ): (
                '为指定 Windows 应用设置代理或直连。本列表按从上到下的顺序匹配，'
                '命中第一条规则后即采用该策略；与路由规则之间的优先级由当前后端决定。'
            ),
            (
                'Configure Xray routing by domain, IP, port, protocol, or process. Rules follow their configured order within the selected routing profile. Priority against application rules depends on the selected backend.'
            ): (
                '按域名、IP、端口、协议或进程配置 Xray 路由。规则在所选路由配置中按设定顺序匹配；'
                '与应用规则之间的优先级由当前后端决定。'
            ),
        }
        for key, translated in expected.items():
            with self.subTest(key=key):
                self.assertEqual(catalogue[key].get('ZH'), translated)



if __name__ == '__main__':
    unittest.main()
