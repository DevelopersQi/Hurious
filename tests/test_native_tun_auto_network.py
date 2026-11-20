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

from Furious.Backends.Xray.TUN import (
    DEFAULT_XRAY_TUN_SETTINGS,
    applyXrayTUNAutoNetworkSettings,
    buildXrayTUNInbound,
)
from Furious.Backends.Hysteria2.TUN import (
    DEFAULT_HYSTERIA2_TUN_SETTINGS,
    applyHysteria2TUNAutoNetworkSettings,
    buildHysteria2TUNConfig,
)


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

    def testInboundResolvesAutomaticInterfaceFromCurrentNetwork(self):
        from unittest import mock

        with mock.patch(
            'Furious.Backends.Xray.TUN.getPrimaryAdapterInfo',
            return_value={'name': 'Wi-Fi', 'ip': '192.168.1.20', 'gateway': '192.168.1.1'},
        ):
            inbound = buildXrayTUNInbound({'autoOutboundsInterface': 'auto'})

        self.assertEqual(inbound['settings']['autoOutboundsInterface'], 'Wi-Fi')

    def testInboundPreservesExplicitOutboundInterface(self):
        from unittest import mock

        with mock.patch(
            'Furious.Backends.Xray.TUN.getPrimaryAdapterInfo',
            return_value={'name': 'Wi-Fi'},
        ):
            inbound = buildXrayTUNInbound({'autoOutboundsInterface': 'Ethernet 2'})

        self.assertEqual(inbound['settings']['autoOutboundsInterface'], 'Ethernet 2')


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

    def testAutomaticallyDetectedRoutesAreReplacedAfterNetworkChange(self):
        first = applyHysteria2TUNAutoNetworkSettings(
            DEFAULT_HYSTERIA2_TUN_SETTINGS,
            {'ip': '192.168.1.20', 'gateway': '192.168.1.1'},
        )
        second = applyHysteria2TUNAutoNetworkSettings(
            first,
            {'ip': '10.0.0.20', 'gateway': '10.0.0.1'},
        )
        self.assertEqual(second['route']['ipv4Exclude'], [
            '10.0.0.20/32', '10.0.0.1/32'
        ])

    def testUserDefinedExclusionsSurviveAutomaticNetworkRefresh(self):
        settings = copy.deepcopy(DEFAULT_HYSTERIA2_TUN_SETTINGS)
        settings['route']['ipv4Exclude'] = ['172.16.0.0/12']
        first = applyHysteria2TUNAutoNetworkSettings(
            settings,
            {'ip': '192.168.1.20', 'gateway': '192.168.1.1'},
        )
        second = applyHysteria2TUNAutoNetworkSettings(
            first,
            {'ip': '10.0.0.20', 'gateway': '10.0.0.1'},
        )
        self.assertEqual(second['route']['ipv4Exclude'], [
            '172.16.0.0/12', '10.0.0.20/32', '10.0.0.1/32'
        ])

    def testRuntimeConfigUsesCurrentNetworkInsteadOfSavedDetectedRoutes(self):
        from unittest import mock

        stale = copy.deepcopy(DEFAULT_HYSTERIA2_TUN_SETTINGS)
        stale['route']['ipv4Exclude'] = ['192.168.1.20/32', '192.168.1.1/32']
        stale['_autoDetectedIPv4Exclude'] = [
            '192.168.1.20/32', '192.168.1.1/32'
        ]
        with mock.patch(
            'Furious.Backends.Hysteria2.TUN.getPrimaryAdapterInfo',
            return_value={'ip': '10.0.0.20', 'gateway': '10.0.0.1'},
        ):
            config = buildHysteria2TUNConfig(stale)

        self.assertEqual(config['route']['ipv4Exclude'], [
            '10.0.0.20/32', '10.0.0.1/32'
        ])


if __name__ == '__main__':
    unittest.main()
