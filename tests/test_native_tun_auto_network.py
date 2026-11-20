# Copyright (C) 2024–present  Loren Eteval & contributors <loren.eteval@proton.me>
#
# This file is part of Furious.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Verify automatic physical-network projection into native TUN settings."""

from __future__ import annotations

import copy
import unittest

from Furious.Backends.Xray.TUN import DEFAULT_XRAY_TUN_SETTINGS, applyXrayTUNAutoNetworkSettings
from Furious.Backends.Hysteria2.TUN import DEFAULT_HYSTERIA2_TUN_SETTINGS, applyHysteria2TUNAutoNetworkSettings


class XrayTUNAutoNetworkSettingsTest(unittest.TestCase):
    def testDetectedAdapterSelectsOutboundInterfaceWithoutMutatingSource(self):
        settings = copy.deepcopy(DEFAULT_XRAY_TUN_SETTINGS)
        original = copy.deepcopy(settings)
        result = applyXrayTUNAutoNetworkSettings(
            settings, {'name': 'Ethernet 2', 'ip': '192.168.1.20', 'gateway': '192.168.1.1'}
        )
        self.assertEqual(result['autoOutboundsInterface'], 'Ethernet 2')
        self.assertEqual(result['gateway'], DEFAULT_XRAY_TUN_SETTINGS['gateway'])
        self.assertEqual(result['dns'], ['1.1.1.1', '8.8.8.8'])
        self.assertEqual(settings, original)

    def testExplicitOutboundInterfaceIsPreserved(self):
        settings = copy.deepcopy(DEFAULT_XRAY_TUN_SETTINGS)
        settings['autoOutboundsInterface'] = 'Wi-Fi'
        result = applyXrayTUNAutoNetworkSettings(settings, {'name': 'Ethernet'})
        self.assertEqual(result['autoOutboundsInterface'], 'Wi-Fi')

    def testMissingDetectedAdapterLeavesAutomaticModeUnchanged(self):
        result = applyXrayTUNAutoNetworkSettings(DEFAULT_XRAY_TUN_SETTINGS, {'name': ''})
        self.assertEqual(result['autoOutboundsInterface'], 'auto')


class Hysteria2TUNAutoNetworkSettingsTest(unittest.TestCase):
    def testHostAndGatewayAreIdempotentIPv4Exclusions(self):
        settings = copy.deepcopy(DEFAULT_HYSTERIA2_TUN_SETTINGS)
        settings['route']['ipv4Exclude'] = ['10.0.0.0/8']
        original = copy.deepcopy(settings)
        info = {'ip': '192.168.1.20', 'gateway': '192.168.1.1'}
        result = applyHysteria2TUNAutoNetworkSettings(settings, info)
        self.assertEqual(result['route']['ipv4Exclude'], [
            '10.0.0.0/8', '192.168.1.20/32', '192.168.1.1/32'
        ])
        self.assertEqual(result['address'], DEFAULT_HYSTERIA2_TUN_SETTINGS['address'])
        self.assertEqual(settings, original)
        self.assertEqual(applyHysteria2TUNAutoNetworkSettings(result, info), result)

    def testInvalidAndNonIPv4ValuesAreIgnored(self):
        result = applyHysteria2TUNAutoNetworkSettings(
            DEFAULT_HYSTERIA2_TUN_SETTINGS,
            {'ip': 'not-an-ip', 'gateway': '2001:db8::1'},
        )
        self.assertEqual(result['route']['ipv4Exclude'], [])


if __name__ == '__main__':
    unittest.main()
