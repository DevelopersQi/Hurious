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

"""Protect native-TUN ownership for normal and proxy-only operations."""

from __future__ import annotations

from unittest import mock

import copy
import unittest

from Furious.Backends.Configuration import ConfigHysteria2, ConfigXray
from Furious.Backends.Hysteria2 import Plugin as Hysteria2PluginModule
from Furious.Backends.Hysteria2.Plugin import Hysteria2CoreRuntimeFactory
from Furious.Backends.Xray import Plugin as XrayPluginModule
from Furious.Backends.Xray.Plugin import XrayCoreRuntimeFactory
from Furious.Plugins.API import TUNPreparationError
from Furious.Plugins.Registry import PluginRegistry
from Furious.Service.ConnectionManager import ConnectionManager


class _RecordingConnectionManager(ConnectionManager):
    """Capture the runtime document without starting a core process."""

    def _startCoreRuntime(self, config, *_args, **_kwargs):
        """Record the prepared runtime configuration as a successful launch."""
        self.runtimeConfiguration = config

        return None, True


class XrayNativeTUNTest(unittest.TestCase):
    """Verify Xray runtime copies preserve or replace native TUN intentionally."""

    customTUN = {
        'tag': 'user-tun',
        'protocol': 'tun',
        'settings': {'gateway': ['192.0.2.1/24']},
    }
    generatedTUN = {
        'tag': 'tun',
        'protocol': 'tun',
        'settings': {'gateway': ['10.0.0.1/16']},
    }
    httpInbound = {'tag': 'http', 'protocol': 'http'}

    def setUp(self):
        """Create one stateless Xray core-runtime capability."""
        self.factory = XrayCoreRuntimeFactory()

    def configuration(self, *, nativeTUN: bool) -> ConfigXray:
        """Return one minimal Xray document with optional custom native TUN."""
        inbounds = [copy.deepcopy(self.httpInbound)]

        if nativeTUN:
            inbounds.append(copy.deepcopy(self.customTUN))

        return ConfigXray({'inbounds': inbounds, 'outbounds': []})

    def prepare(self, original, enabled):
        """Prepare an independent runtime copy under one toggle state."""
        runtime = original.deepcopy()

        with (
            mock.patch.object(XrayPluginModule, 'PLATFORM', 'Windows'),
            mock.patch.object(
                XrayPluginModule,
                'isXrayTUNEnabled',
                return_value=enabled,
            ),
            mock.patch.object(
                XrayPluginModule,
                'buildXrayTUNInbound',
                return_value=copy.deepcopy(self.generatedTUN),
            ),
        ):
            handled = self.factory.prepareTUN(runtime)

        return runtime, handled

    def testExistingTUNIsReplacedWhenManagedTUNIsEnabled(self):
        """Replace every runtime TUN inbound without changing persisted JSON."""
        original = self.configuration(nativeTUN=True)
        snapshot = copy.deepcopy(original)

        runtime, handled = self.prepare(original, True)

        self.assertTrue(handled)
        self.assertEqual(original, snapshot)
        self.assertEqual(runtime['inbounds'], [self.httpInbound, self.generatedTUN])
        self.assertFalse(self.factory.usesApplicationTun2socks(runtime))

    def testExistingTUNIsPreservedWhenManagedTUNIsDisabled(self):
        """Treat a user TUN inbound as authoritative for normal connection."""
        original = self.configuration(nativeTUN=True)
        snapshot = copy.deepcopy(original)

        runtime, handled = self.prepare(original, False)

        self.assertTrue(handled)
        self.assertEqual(runtime, original)
        self.assertEqual(original, snapshot)
        self.assertFalse(self.factory.usesApplicationTun2socks(runtime))

    def testGeneratedTUNIsInjectedWhenEnabledAndMissing(self):
        """Inject Furious-managed Xray TUN into only the runtime copy."""
        original = self.configuration(nativeTUN=False)
        snapshot = copy.deepcopy(original)

        runtime, handled = self.prepare(original, True)

        self.assertTrue(handled)
        self.assertEqual(original, snapshot)
        self.assertEqual(runtime['inbounds'], [self.httpInbound, self.generatedTUN])
        self.assertFalse(self.factory.usesApplicationTun2socks(runtime))

    def testMissingTUNLeavesApplicationFallbackAvailableWhenDisabled(self):
        """Report no native owner so global TUN may use application tun2socks."""
        original = self.configuration(nativeTUN=False)

        runtime, handled = self.prepare(original, False)

        self.assertFalse(handled)
        self.assertEqual(runtime, original)
        self.assertTrue(self.factory.usesApplicationTun2socks(runtime))

    def testExplicitXrayBackendGeneratesNativeTUNWhenMissing(self):
        """Generate the selected native Xray inbound on the runtime copy."""
        runtime = self.configuration(nativeTUN=False)

        with mock.patch.object(
            XrayPluginModule,
            'buildXrayTUNInbound',
            return_value=copy.deepcopy(self.generatedTUN),
        ):
            handled = self.factory.prepareTUNForBackend(runtime, 'xray')

        self.assertTrue(handled)
        self.assertEqual(runtime['inbounds'], [self.httpInbound, self.generatedTUN])

    def testExplicitXrayBackendRejectsMalformedInboundCollection(self):
        """Do not discard malformed user configuration to force a TUN inbound."""
        runtime = ConfigXray({'inbounds': 'invalid', 'outbounds': []})

        with self.assertRaisesRegex(TUNPreparationError, 'inbounds field'):
            self.factory.prepareTUNForBackend(runtime, 'xray')

    def testExplicitXrayBackendOverridesLegacyToggleAndPreservesCustomTUN(self):
        """Force native Xray without replacing an explicit user inbound."""
        original = self.configuration(nativeTUN=True)
        runtime = original.deepcopy()

        with mock.patch.object(XrayPluginModule, 'isXrayTUNEnabled', return_value=False):
            handled = self.factory.prepareTUNForBackend(runtime, 'xray')

        self.assertTrue(handled)
        self.assertEqual(runtime, original)

    def testExplicitTun2socksRejectsAnAuthoritativeCustomTUN(self):
        """Never pair a user-defined native TUN with application tun2socks."""
        runtime = self.configuration(nativeTUN=True)

        with self.assertRaisesRegex(TUNPreparationError, 'already defines'):
            self.factory.prepareTUNForBackend(runtime, 'tun2socks')

    def testExplicitTun2socksIsSelectedWhenNoNativeTUNExists(self):
        """Allow host tun2socks when the selected core has no native TUN."""
        runtime = self.configuration(nativeTUN=False)

        self.assertFalse(self.factory.prepareTUNForBackend(runtime, 'tun2socks'))
        self.assertTrue(self.factory.usesApplicationTun2socks(runtime))

    def testWrongNativeBackendIsRejected(self):
        """Do not silently substitute Hysteria 2 for a requested Xray TUN."""
        runtime = self.configuration(nativeTUN=False)

        with self.assertRaisesRegex(
            TUNPreparationError,
            'Hysteria 2 Native TUN is not supported by the selected Xray-core configuration',
        ):
            self.factory.prepareTUNForBackend(runtime, 'hysteria2')

    def testDownloadTestExplicitlyStripsNativeTUN(self):
        """Keep normal custom TUN while deriving a TUN-free speed-test copy."""
        original = self.configuration(nativeTUN=True)
        snapshot = copy.deepcopy(original)

        runtime, handled = self.prepare(original, False)
        speedTest = self.factory.prepareDownloadTest(original, 18080)

        self.assertTrue(handled)
        self.assertEqual(runtime, original)
        self.assertEqual(original, snapshot)
        self.assertFalse(
            any(inbound.get('protocol') == 'tun' for inbound in speedTest['inbounds'])
        )

    def testConnectionManagerDoesNotPairCustomTUNWithTun2socks(self):
        """Stop host tun2socks selection once Xray reports custom native TUN."""
        original = self.configuration(nativeTUN=True)
        registry = mock.Mock()
        registry.prepareTUN.side_effect = self.factory.prepareTUN
        registry.usesApplicationTun2socks.side_effect = (
            self.factory.usesApplicationTun2socks
        )
        manager = _RecordingConnectionManager()

        with (
            mock.patch.object(
                XrayPluginModule,
                'isXrayTUNEnabled',
                return_value=False,
            ),
            mock.patch(
                'Furious.Service.ConnectionManager.SystemRuntime.isTUNMode',
                return_value=True,
            ),
            mock.patch(
                'Furious.Service.ConnectionManager.getPluginRegistry',
                return_value=registry,
            ),
            mock.patch('Furious.Service.ConnectionManager.Tun2socks') as tun2socks,
        ):
            self.assertTrue(manager.start(original, 'Global'))

        registry.usesApplicationTun2socks.assert_not_called()
        tun2socks.assert_not_called()

        self.assertEqual(manager.runtimeConfiguration, original)

        manager.cleanup()

    def testConnectionManagerPassesExplicitBackendToRegistry(self):
        """Route a persisted backend preference into the plugin preparation path."""
        original = self.configuration(nativeTUN=False)
        registry = mock.Mock()
        registry.prepareTUN.return_value = True
        registry.factoryForConfig.return_value.factoryId = 'official.xray'
        manager = _RecordingConnectionManager()

        with (
            mock.patch(
                'Furious.Service.ConnectionManager.SystemRuntime.isTUNMode',
                return_value=True,
            ),
            mock.patch(
                'Furious.Service.ConnectionManager.AppSettings.get',
                return_value='xray',
            ),
            mock.patch(
                'Furious.Service.ConnectionManager.getPluginRegistry',
                return_value=registry,
            ),
        ):
            self.assertTrue(manager.start(original, 'Global'))

        registry.prepareTUN.assert_called_once()
        self.assertEqual(registry.prepareTUN.call_args.args[1], 'xray')
        self.assertEqual(manager.activeTUNBackend, 'xray')
        registry.usesApplicationTun2socks.assert_not_called()

        manager.cleanup()

    def testAutomaticBackendSelectsXrayNativeTUN(self):
        """Select Xray native TUN automatically, regardless of legacy toggle."""
        registry = mock.Mock()
        registry.factoryForConfig.return_value.factoryId = 'official.xray'
        registry.prepareTUN.return_value = True
        manager = _RecordingConnectionManager()

        with (
            mock.patch(
                'Furious.Service.ConnectionManager.SystemRuntime.isTUNMode',
                return_value=True,
            ),
            mock.patch(
                'Furious.Service.ConnectionManager.AppSettings.get',
                return_value='auto',
            ),
            mock.patch(
                'Furious.Service.ConnectionManager.getPluginRegistry',
                return_value=registry,
            ),
        ):
            nativeTUN, applicationTun2socks = manager._prepareTUNPolicy(
                self.configuration(nativeTUN=False), False
            )

        self.assertTrue(nativeTUN)
        self.assertFalse(applicationTun2socks)
        registry.prepareTUN.assert_called_once()
        self.assertEqual(registry.prepareTUN.call_args.args[1], 'xray')
        self.assertEqual(manager.activeTUNBackend, 'xray')
        registry.usesApplicationTun2socks.assert_not_called()


    def testManagedTUNPreparationFailureDoesNotFallBackToTun2socks(self):
        """Fail an unavailable managed TUN instead of changing networking mode."""
        original = self.configuration(nativeTUN=True)
        registry = mock.Mock()
        registry.prepareTUN.side_effect = TUNPreparationError('managed TUN failed')
        manager = _RecordingConnectionManager()

        with (
            mock.patch(
                'Furious.Service.ConnectionManager.SystemRuntime.isTUNMode',
                return_value=True,
            ),
            mock.patch(
                'Furious.Service.ConnectionManager.getPluginRegistry',
                return_value=registry,
            ),
            mock.patch('Furious.Service.ConnectionManager.Tun2socks') as tun2socks,
        ):
            self.assertFalse(manager.start(original, 'Global'))

        self.assertEqual(manager.lastStartError, 'managed TUN failed')

        registry.usesApplicationTun2socks.assert_not_called()
        tun2socks.assert_not_called()

        self.assertFalse(hasattr(manager, 'runtimeConfiguration'))

    def testRegistryPropagatesIntentionalTUNPreparationFailure(self):
        """Keep the explicit failure distinct from an unsupported capability."""
        registry = PluginRegistry()

        factory = mock.Mock(factoryId='managed-tun-factory')
        factory.prepareTUNForBackend.side_effect = TUNPreparationError(
            'managed TUN failed'
        )

        registry.factoryForConfig = mock.Mock(return_value=factory)

        with self.assertRaisesRegex(TUNPreparationError, 'managed TUN failed'):
            registry.prepareTUN(self.configuration(nativeTUN=False))


class Hysteria2NativeTUNTest(unittest.TestCase):
    """Verify Hysteria 2 runtime copies preserve or replace native TUN."""

    customTUN = {
        'name': 'user-tun',
        'address': {'ipv4': '192.0.2.1/30'},
    }
    generatedTUN = {
        'name': 'hytun',
        'address': {'ipv4': '100.100.100.101/30'},
    }

    def setUp(self):
        """Create one stateless Hysteria 2 core-runtime capability."""
        self.factory = Hysteria2CoreRuntimeFactory()

    def configuration(self, *, nativeTUN: bool) -> ConfigHysteria2:
        """Return one minimal Hysteria 2 document with optional custom TUN."""
        config = ConfigHysteria2(
            {
                'server': '203.0.113.10:443',
                'http': {'listen': '127.0.0.1:10809'},
            }
        )

        if nativeTUN:
            config['tun'] = copy.deepcopy(self.customTUN)

        return config

    def prepare(self, original, enabled):
        """Prepare an independent runtime copy under one toggle state."""
        runtime = original.deepcopy()

        with (
            mock.patch.object(
                Hysteria2PluginModule,
                'isHysteria2TUNEnabled',
                return_value=enabled,
            ),
            mock.patch.object(Hysteria2PluginModule, 'PLATFORM', 'Windows'),
            mock.patch.object(
                Hysteria2PluginModule,
                'getHysteria2TUNSettings',
                return_value={},
            ),
            mock.patch.object(
                Hysteria2PluginModule,
                'resolveHysteria2ServerAddresses',
                return_value=['203.0.113.10'],
            ),
            mock.patch.object(
                Hysteria2PluginModule,
                'buildHysteria2TUNConfig',
                return_value=copy.deepcopy(self.generatedTUN),
            ),
        ):
            handled = self.factory.prepareTUN(runtime)

        return runtime, handled

    def testExistingTUNIsReplacedWhenManagedTUNIsEnabled(self):
        """Replace the runtime block without changing the persisted document."""
        original = self.configuration(nativeTUN=True)
        snapshot = copy.deepcopy(original)

        runtime, handled = self.prepare(original, True)

        self.assertTrue(handled)
        self.assertEqual(runtime['tun'], self.generatedTUN)
        self.assertEqual(original, snapshot)
        self.assertFalse(self.factory.usesApplicationTun2socks(runtime))

    def testExistingTUNIsPreservedWhenManagedTUNIsDisabled(self):
        """Treat a user TUN block as authoritative for normal connection."""
        original = self.configuration(nativeTUN=True)
        snapshot = copy.deepcopy(original)

        runtime, handled = self.prepare(original, False)

        self.assertTrue(handled)
        self.assertEqual(runtime, original)
        self.assertEqual(original, snapshot)
        self.assertFalse(self.factory.usesApplicationTun2socks(runtime))

    def testMalformedExplicitTUNStillPreventsSilentFallback(self):
        """Leave validation of an explicit malformed block to Hysteria 2."""
        original = self.configuration(nativeTUN=False)
        original['tun'] = 'malformed-user-value'

        runtime, handled = self.prepare(original, False)

        self.assertTrue(handled)
        self.assertEqual(runtime['tun'], 'malformed-user-value')
        self.assertFalse(self.factory.usesApplicationTun2socks(runtime))

    def testGeneratedTUNIsInjectedWhenEnabledAndMissing(self):
        """Inject Furious-managed Hysteria 2 TUN into only the runtime copy."""
        original = self.configuration(nativeTUN=False)
        snapshot = copy.deepcopy(original)

        runtime, handled = self.prepare(original, True)

        self.assertTrue(handled)
        self.assertEqual(runtime['tun'], self.generatedTUN)
        self.assertEqual(original, snapshot)
        self.assertFalse(self.factory.usesApplicationTun2socks(runtime))

    def testMissingTUNLeavesApplicationFallbackAvailableWhenDisabled(self):
        """Report no native owner so global TUN may use application tun2socks."""
        original = self.configuration(nativeTUN=False)

        runtime, handled = self.prepare(original, False)

        self.assertFalse(handled)
        self.assertEqual(runtime, original)
        self.assertTrue(self.factory.usesApplicationTun2socks(runtime))

    def testUnavailableManagedTUNFailsWithoutRemovingUserTUN(self):
        """Do not replace a requested native TUN with application tun2socks."""
        original = self.configuration(nativeTUN=True)
        runtime = original.deepcopy()

        with (
            mock.patch.object(
                Hysteria2PluginModule,
                'isHysteria2TUNEnabled',
                return_value=True,
            ),
            mock.patch.object(Hysteria2PluginModule, 'PLATFORM', 'Linux'),
            mock.patch.object(
                Hysteria2PluginModule.SystemRuntime,
                'isAdmin',
                return_value=False,
            ),
        ):
            with self.assertRaisesRegex(TUNPreparationError, 'superuser privileges'):
                self.factory.prepareTUN(runtime)

        self.assertEqual(runtime, original)

    def testExplicitHysteria2BackendPreservesCustomTUN(self):
        """Keep the user's Hysteria 2 TUN block unchanged when selected."""
        runtime = self.configuration(nativeTUN=True)
        snapshot = copy.deepcopy(runtime)

        self.assertTrue(self.factory.prepareTUNForBackend(runtime, 'hysteria2'))
        self.assertEqual(runtime, snapshot)

    def testExplicitHysteria2BackendOverridesLegacyToggle(self):
        """Prepare native Hysteria 2 when explicitly selected."""
        runtime = self.configuration(nativeTUN=False)

        with (
            mock.patch.object(Hysteria2PluginModule, 'isHysteria2TUNEnabled', return_value=False),
            mock.patch.object(Hysteria2PluginModule, 'PLATFORM', 'Windows'),
            mock.patch.object(Hysteria2PluginModule, 'getHysteria2TUNSettings', return_value={}),
            mock.patch.object(
                Hysteria2PluginModule,
                'resolveHysteria2ServerAddresses',
                return_value=['203.0.113.10'],
            ),
            mock.patch.object(
                Hysteria2PluginModule,
                'buildHysteria2TUNConfig',
                return_value=copy.deepcopy(self.generatedTUN),
            ),
        ):
            handled = self.factory.prepareTUNForBackend(runtime, 'hysteria2')

        self.assertTrue(handled)
        self.assertEqual(runtime['tun'], self.generatedTUN)

    def testExplicitTun2socksPreservesNoCustomTUNAndRejectsCustomTUN(self):
        """Enforce exactly one TUN owner for Hysteria 2 configurations."""
        plain = self.configuration(nativeTUN=False)
        self.assertFalse(self.factory.prepareTUNForBackend(plain, 'tun2socks'))

        custom = self.configuration(nativeTUN=True)
        snapshot = copy.deepcopy(custom)

        with self.assertRaisesRegex(TUNPreparationError, 'already defines'):
            self.factory.prepareTUNForBackend(custom, 'tun2socks')

        self.assertEqual(custom, snapshot)

    def testWrongNativeBackendIsRejected(self):
        """Do not silently substitute Xray for a requested Hysteria 2 TUN."""
        runtime = self.configuration(nativeTUN=False)

        with self.assertRaisesRegex(
            TUNPreparationError,
            'Xray-core Native TUN is not supported by the selected Hysteria 2 configuration',
        ):
            self.factory.prepareTUNForBackend(runtime, 'xray')

    def testDownloadTestExplicitlyStripsNativeTUN(self):
        """Keep normal custom TUN while deriving a TUN-free speed-test copy."""
        original = self.configuration(nativeTUN=True)
        snapshot = copy.deepcopy(original)

        runtime, handled = self.prepare(original, False)
        speedTest = self.factory.prepareDownloadTest(original, 18080)

        self.assertTrue(handled)
        self.assertEqual(runtime, original)
        self.assertEqual(original, snapshot)
        self.assertNotIn('tun', speedTest)

    def testAutomaticBackendSelectsHysteria2NativeTUN(self):
        """Select Hysteria 2 native TUN automatically for Hysteria 2 profiles."""
        registry = mock.Mock()
        registry.factoryForConfig.return_value.factoryId = 'official.hysteria2'
        registry.prepareTUN.return_value = True
        manager = _RecordingConnectionManager()

        with (
            mock.patch(
                'Furious.Service.ConnectionManager.SystemRuntime.isTUNMode',
                return_value=True,
            ),
            mock.patch(
                'Furious.Service.ConnectionManager.AppSettings.get',
                return_value='auto',
            ),
            mock.patch(
                'Furious.Service.ConnectionManager.getPluginRegistry',
                return_value=registry,
            ),
        ):
            nativeTUN, applicationTun2socks = manager._prepareTUNPolicy(
                self.configuration(nativeTUN=False), False
            )

        self.assertTrue(nativeTUN)
        self.assertFalse(applicationTun2socks)
        registry.prepareTUN.assert_called_once()
        self.assertEqual(registry.prepareTUN.call_args.args[1], 'hysteria2')
        self.assertEqual(manager.activeTUNBackend, 'hysteria2')
        registry.usesApplicationTun2socks.assert_not_called()

    def testConnectionManagerDoesNotPairCustomTUNWithTun2socks(self):
        """Stop host tun2socks selection once Hysteria 2 owns native TUN."""
        original = self.configuration(nativeTUN=True)
        registry = mock.Mock()
        registry.prepareTUN.side_effect = self.factory.prepareTUN
        registry.usesApplicationTun2socks.side_effect = (
            self.factory.usesApplicationTun2socks
        )
        manager = _RecordingConnectionManager()

        with (
            mock.patch.object(
                Hysteria2PluginModule,
                'isHysteria2TUNEnabled',
                return_value=False,
            ),
            mock.patch(
                'Furious.Service.ConnectionManager.SystemRuntime.isTUNMode',
                return_value=True,
            ),
            mock.patch(
                'Furious.Service.ConnectionManager.getPluginRegistry',
                return_value=registry,
            ),
            mock.patch('Furious.Service.ConnectionManager.Tun2socks') as tun2socks,
        ):
            self.assertTrue(manager.start(original, 'Global'))

        registry.usesApplicationTun2socks.assert_not_called()
        tun2socks.assert_not_called()

        self.assertEqual(manager.runtimeConfiguration, original)

        manager.cleanup()


if __name__ == '__main__':
    unittest.main()
