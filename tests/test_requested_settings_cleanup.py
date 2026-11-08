# Copyright (C) 2024–present  Furious contributors
#
# This file is part of Furious and is distributed under the GNU General Public
# License, version 3 or (at your option) any later version.

"""Regression coverage for the requested settings and popup cleanup."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def source(path):
    return (ROOT / path).read_text(encoding='utf-8')


class RequestedSettingsCleanupTest(unittest.TestCase):
    def test_tun_is_disabled_by_default_and_backend_defaults_to_auto(self):
        settings = source('Furious/Controllers/SettingsController.py')

        self.assertIn(
            "'VPNMode',\n    isBinary=True,\n    default=AppBinarySettings.OFF,",
            settings,
        )
        self.assertIn(
            "'TUNBackend',\n    validRange=[value for _label, value in TUN_BACKEND_OPTIONS],\n    default='auto',",
            settings,
        )

    def test_hysteria2_settings_do_not_duplicate_tun_or_expose_unused_stats(self):
        plugin = source('Furious/Backends/Hysteria2/Plugin.py')
        settings = source('Furious/Window/SettingsPage.py')

        self.assertNotIn('Hysteria2SettingsProvider', plugin)
        self.assertNotIn('Hysteria2ActionProvider', plugin)
        self.assertNotIn('Hysteria2StatsProvider', plugin)
        self.assertNotIn('configuredHysteria2StatsTarget', plugin)
        self.assertIn('Hysteria2CoreRuntimeFactory()', plugin)

        # The only Hysteria2 TUN editor entry is the shared TUN & DNS section.
        self.assertIn('self.hysteria2TunSettingsCard = _ActionSettingsCard(', settings)
        self.assertIn('self.tunSection.addCard(self.hysteria2TunSettingsCard)', settings)

    def test_open_application_folder_uses_a_local_file_url(self):
        home = source('Furious/Window/HomePage.py')

        self.assertIn('QtCore.QUrl.fromLocalFile(appFolder)', home)
        self.assertNotIn('QtCore.QUrl(appFolder)', home)

    def test_popup_surfaces_suppress_native_opaque_backgrounds(self):
        widgets = source('Furious/Qt/QtWidgets.py')

        self.assertGreaterEqual(
            widgets.count('QtCore.Qt.WidgetAttribute.WA_NoSystemBackground'),
            2,
        )
        self.assertIn('popupPalette.setColor(', widgets)
        self.assertIn('menuPalette.setColor(', widgets)
        self.assertIn('QColor(QtCore.Qt.GlobalColor.transparent)', widgets)


if __name__ == '__main__':
    unittest.main()
