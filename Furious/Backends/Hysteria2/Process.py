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

"""Wrap the embedded Hysteria 2 core process."""

from __future__ import annotations

from Furious.Frozenlib import *
from Furious.Core import *

from enum import Enum
from typing import Union

import time
import logging
import functools
import multiprocessing
import json
import os
import tempfile

logger = logging.getLogger(__name__)

__all__ = ['Hysteria2']


def startHysteria2(jsonString: str, msgQueue: multiprocessing.Queue):
    """Start hysteria2."""
    try:
        import hysteria2
    except ImportError as ex:
        # Never pretend that a missing core is running.  The previous
        # placeholder loop kept the child process alive forever, causing the
        # GUI readiness probe to report only a generic startup timeout.
        message = (
            'Hysteria 2 core module is unavailable. '
            'Please verify the application package and its bundled dependencies.'
        )
        msgQueue.putMessage(message)
        raise RuntimeError(message) from ex

    entrypoint = getattr(hysteria2, 'startFromJSON', None)
    if not callable(entrypoint):
        message = (
            'The installed Hysteria 2 binding does not provide startFromJSON. '
            'Please rebuild the application with a compatible Hysteria 2 binding.'
        )
        msgQueue.putMessage(message)
        raise RuntimeError(message)

    try:
        redirect = (
            versionToValue(hysteria2.__version__)
            > versionToValue('2.0.0.1')
        )
    except (AttributeError, TypeError, ValueError):
        # A missing or malformed version must not prevent the core from
        # starting; use the safe, non-redirected output path.
        redirect = False

    ProcessOutputRedirector.launch(
        msgQueue,
        functools.partial(entrypoint, jsonString),
        redirect,
    )


class Hysteria2(MultiprocessingRuntime):
    """Manage the embedded Hysteria 2 core subprocess."""

    class ExitCode(Enum):
        """Enumerate process exit codes."""

        ConfigurationError = 23
        # Windows: 4294967295. Darwin, Linux: 255 (-1)
        ServerStartFailure = 4294967295 if PLATFORM == 'Windows' else 255
        # Windows shutting down
        SystemShuttingDown = 0x40010004

    def __init__(self, configuration: str, *, enableTrafficStats=True, **kwargs):
        """Initialize a runtime with a private local traffic-counter channel."""
        self.hysteria2StatsFile = ''
        statsPath = ''

        if enableTrafficStats:
            try:
                descriptor, statsPath = tempfile.mkstemp(
                    prefix='furious-hysteria2-traffic-',
                    suffix='.json',
                )
                os.close(descriptor)
                payload = json.loads(configuration)
                if not isinstance(payload, dict):
                    raise ValueError('runtime configuration must be a JSON object')
                payload['furiousStatsFile'] = statsPath
                configuration = json.dumps(
                    payload,
                    ensure_ascii=False,
                    separators=(',', ':'),
                )
                self.hysteria2StatsFile = statsPath
            except (OSError, TypeError, ValueError):
                if statsPath:
                    try:
                        os.remove(statsPath)
                    except OSError:
                        pass
                logger.warning('Hysteria 2 local traffic statistics are unavailable')

        super().__init__(
            lambda output: ProcessLaunchSpec(
                target=startHysteria2,
                args=(configuration, output),
                processOptions=kwargs.pop('processOptions', {}),
            ),
            **kwargs,
        )

    def start(self):
        """Start the core and clean up the stats channel on startup failure."""
        try:
            super().start()
        except Exception:
            self._removeTrafficStatsFile()
            raise

    def _removeTrafficStatsFile(self):
        """Remove this runtime's private counter snapshot."""
        path = self.hysteria2StatsFile
        if not path:
            return
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError:
            logger.debug('failed to remove Hysteria 2 traffic snapshot')

    def _consumeExit(self):
        """Clean up local statistics after the child process has exited."""
        event = super()._consumeExit()
        self._removeTrafficStatsFile()
        return event

    def stop(self):
        """Stop the core and release its local statistics snapshot."""
        super().stop()
        self._removeTrafficStatsFile()

    def dispose(self):
        """Dispose the runtime and always release its private stats file."""
        try:
            # MultiprocessingRuntime.dispose() calls its internal _stopLocked()
            # directly, so the public stop() override is not dispatched here.
            super().dispose()
        finally:
            self._removeTrafficStatsFile()

    @staticmethod
    def name() -> str:
        """Return the process implementation name."""
        return 'Hysteria2'

    @staticmethod
    def version() -> str:
        """Return the bundled core version."""
        try:
            import hysteria2

            return hysteria2.__version__
        except Exception:
            # Any non-exit exceptions

            return '0.0.0'
