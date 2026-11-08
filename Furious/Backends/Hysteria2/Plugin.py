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

"""Integrate Hysteria 2 configuration, editor, and process startup."""

from __future__ import annotations

from Furious.Frozenlib import *
from Furious.Qt.DynamicTranslate import gettext as _
from Furious.Plugins.API import *
from Furious.Plugins.Runtime import serializeRuntimeConfiguration
from Furious.Backends.Configuration import *

from .Process import Hysteria2
from .Stats import Hysteria2StatsProvider
from .ProtocolEditors import HYSTERIA2_PROTOCOL_EDITORS
from .Protocols import HYSTERIA2_PROTOCOL_HANDLERS
from .TUN import *

import logging

__all__ = ['Hysteria2Plugin']

logger = logging.getLogger(__name__)


def _placeholder(x):
    return x


_ = _placeholder

class Hysteria2CoreRuntimeFactory(CoreRuntimeFactory):
    """Construct Hysteria 2 core runtimes independently of protocol handling."""

    factoryId = 'official.hysteria2'
    configurationTypes = (ConfigHysteria2,)
    runtimeTypes = (Hysteria2,)

    def prepareTUN(self, config) -> bool:
        """Apply the legacy Auto preference while preserving custom TUN data."""
        # The per-core switch is hidden from the UI; retain its persisted
        # value as the Auto default so existing user configurations behave
        # consistently after upgrading.
        if not isHysteria2TUNEnabled():
            return hasHysteria2TUNConfig(config)

        # Linux native TUN requires elevation. Auto remains Tun2socks when
        # the legacy preference is off; an enabled preference must fail
        # clearly rather than silently changing the requested backend.
        if PLATFORM == 'Linux' and not SystemRuntime.isAdmin():
            raise TUNPreparationError(
                'Hysteria 2 native TUN requires Linux superuser privileges'
            )

        settings = getHysteria2TUNSettings()
        serverAddresses = resolveHysteria2ServerAddresses(config)
        route = settings.get('route', {})
        hasManualExclusions = bool(route.get('ipv4Exclude') or route.get('ipv6Exclude'))

        if not serverAddresses and not hasManualExclusions:
            raise TUNPreparationError(
                'Hysteria 2 native TUN cannot start because '
                'the server address could not be resolved and no manual route '
                'exclusion is configured'
            )

        config['tun'] = buildHysteria2TUNConfig(settings, serverAddresses)

        return True

    def prepareTUNForBackend(self, config, backend: str) -> bool:
        """Honor explicit Hysteria 2 TUN selection without overwriting user data."""
        backend = str(backend or 'auto').strip().casefold()

        if backend == 'auto':
            return self.prepareTUN(config)

        if backend == 'xray':
            raise TUNPreparationError(
                _(
                    'Xray-core Native TUN is not supported by the selected '
                    'Hysteria 2 configuration. Select Auto or Hysteria 2 Native TUN.'
                )
            )

        if backend != 'hysteria2':
            return super().prepareTUNForBackend(config, backend)

        if hasHysteria2TUNConfig(config):
            return True

        if PLATFORM == 'Linux' and not SystemRuntime.isAdmin():
            raise TUNPreparationError(
                'Hysteria 2 native TUN requires Linux superuser privileges'
            )

        settings = getHysteria2TUNSettings()
        serverAddresses = resolveHysteria2ServerAddresses(config)
        route = settings.get('route', {})
        hasManualExclusions = bool(route.get('ipv4Exclude') or route.get('ipv6Exclude'))

        if not serverAddresses and not hasManualExclusions:
            raise TUNPreparationError(
                'Hysteria 2 native TUN cannot start because '
                'the server address could not be resolved and no manual route '
                'exclusion is configured'
            )

        config['tun'] = buildHysteria2TUNConfig(settings, serverAddresses)

        return True

    def usesApplicationTun2socks(self, config) -> bool:
        """Use host tun2socks only when the runtime has no native TUN block."""
        return not hasHysteria2TUNConfig(config)

    def create(self, request: CoreRuntimeRequest):
        """Create a prepared Hysteria 2 core-runtime launch."""
        if request.log:
            logger.info(f'core {Hysteria2.name()} configured')

        runtime = Hysteria2(
            serializeRuntimeConfiguration(request.configuration, Hysteria2.name()),
            enableTrafficStats=not request.proxyModeOnly,
            exitCallback=request.exitCallback,
            msgCallback=request.messageCallback,
        )

        return PreparedRuntime(
            runtime,
            readiness=CoreRuntimeStartup(endpoint=request.configuration.httpProxy()),
        )

    def prepareDownloadTest(self, config, port: int):
        """Create a Hysteria 2 configuration with one local HTTP proxy."""
        configcopy = config.deepcopy()
        configcopy['http'] = {
            'listen': f'127.0.0.1:{port}',
            'timeout': 300,
            'disable_udp': False,
        }
        configcopy.pop('socks5', '')
        configcopy.pop('tun', None)

        return configcopy

    def coreVersions(self):
        """Return the bundled Hysteria 2 version."""
        return (Hysteria2.version(),)

    def logTimestampPatterns(self):
        """Return the timestamp format emitted by Hysteria 2."""
        return (r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})',)


def _placeholder(x):
    return x


_ = _placeholder

_TRANSLATABLE = [
    _('Official Hysteria 2 protocol, editor, and runtime support.'),
]


class Hysteria2Plugin(FuriousPlugin):
    """Bundle official Hysteria 2 protocol and runtime capabilities."""

    metadata = PluginMetadata(
        'official.hysteria2',
        'Hysteria2',
        description='Official Hysteria 2 protocol, editor, and runtime support.',
        provider='Furious',
    )

    def __init__(self):
        """Create an isolated Hysteria 2 runtime factory."""
        self.capabilities = (
            *HYSTERIA2_PROTOCOL_HANDLERS,
            *HYSTERIA2_PROTOCOL_EDITORS,
            Hysteria2CoreRuntimeFactory(),
            Hysteria2StatsProvider(),
        )
