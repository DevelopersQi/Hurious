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

"""Define the execution-only contract shared by managed core runtimes."""

from __future__ import annotations

from Furious.Frozenlib.Constants import PLATFORM

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Union

__all__ = [
    'CoreRuntime',
    'RuntimeExit',
    'RuntimeExitReason',
    'RuntimeStartError',
    'RuntimeState',
]


class RuntimeState(str, Enum):
    """Describe execution-resource state without implying connection readiness."""

    Created = 'created'
    Starting = 'starting'
    Alive = 'alive'
    Stopping = 'stopping'
    Exited = 'exited'
    Failed = 'failed'
    Disposed = 'disposed'


class RuntimeExitReason(str, Enum):
    """Classify the small set of exit meanings shared by runtime consumers."""

    Stopped = 'stopped'
    InvalidConfiguration = 'invalid-configuration'
    StartFailure = 'start-failure'
    ConnectionLost = 'connection-lost'
    SystemShuttingDown = 'system-shutting-down'
    Unexpected = 'unexpected'


_EXIT_MESSAGES = {
    RuntimeExitReason.Stopped: '',
    RuntimeExitReason.InvalidConfiguration: 'Invalid server configuration',
    RuntimeExitReason.StartFailure: 'Failed to start core',
    RuntimeExitReason.ConnectionLost: 'Connection to server has been lost',
    RuntimeExitReason.SystemShuttingDown: '',
    RuntimeExitReason.Unexpected: 'Core terminated unexpectedly',
}


@dataclass(frozen=True)
class RuntimeExit:
    """Publish one interpreted runtime termination with its raw diagnostic code."""

    code: Union[int, None]
    reason: RuntimeExitReason
    message: str = ''
    details: str = ''

    def __post_init__(self):
        """Fill the stable default message for one semantic reason."""
        if not self.message:
            object.__setattr__(self, 'message', _EXIT_MESSAGES[self.reason])

    @property
    def unexpected(self) -> bool:
        """Return whether the owner should treat this exit as a failure."""
        return self.reason not in (
            RuntimeExitReason.Stopped,
            RuntimeExitReason.SystemShuttingDown,
        )


class RuntimeStartError(RuntimeError):
    """Report one expected failure to acquire a live runtime execution resource."""

    def __init__(
        self,
        message: str,
        *,
        reason: RuntimeExitReason = RuntimeExitReason.StartFailure,
        details: str = '',
        code: Union[int, None] = None,
    ):
        """Initialize a structured startup failure."""
        super().__init__(str(message or _EXIT_MESSAGES[reason]))

        self.reason = reason
        self.message = str(message or _EXIT_MESSAGES[reason])
        self.details = str(details or '')
        self.code = code

    @classmethod
    def fromExit(cls, event: RuntimeExit, *, details: str = ''):
        """Build a startup failure from a termination observed during spawn."""
        return cls(
            event.message,
            reason=event.reason,
            details=details or event.details,
            code=event.code,
        )


class CoreRuntime(ABC):
    """Own one core's execution resources and publish typed exit events.

    Runtime state describes only execution. Endpoint/TUN readiness, startup
    timeouts, transaction sequencing, and commit belong to service owners.

    ``exitCallback`` is bound once before start and remains stable until final
    disposal. It receives ``(runtime, RuntimeExit)`` and may be called from an
    implementation worker thread; the supplied owner must provide its own
    thread-safe handoff.
    """

    class ExitCode(Enum):
        """Define raw process-exit values shared by runtime implementations."""

        ConfigurationError = 23
        ServerStartFailure = 4294967295 if PLATFORM == 'Windows' else 255
        SystemShuttingDown = 0x40010004

    def __init__(
        self,
        exitCallback: Union[Callable[[CoreRuntime, RuntimeExit], None], None] = None,
    ):
        """Initialize a created runtime with one optional stable event sink."""
        super().__init__()

        self._exitCallback = exitCallback
        self._state = RuntimeState.Created
        self._disposed = False
        self._lastExit = None

    @property
    def state(self) -> RuntimeState:
        """Return execution state, never connection readiness."""
        return self._state

    @property
    def lastExit(self) -> Union[RuntimeExit, None]:
        """Return the first typed terminal event, even before queued delivery."""
        return self._lastExit

    def setState(self, state: RuntimeState):
        """Move to one explicit execution-resource state."""
        self._state = RuntimeState(state)

    def bindExitCallback(self, callback):
        """Bind the runtime's event sink exactly once before execution starts."""
        if not callable(callback):
            raise TypeError('runtime exit callback must be callable')

        if self._exitCallback is not None and self._exitCallback is not callback:
            raise RuntimeError('runtime exit callback is already bound')

        if self.state is not RuntimeState.Created:
            raise RuntimeError('runtime exit callback must be bound before start')

        self._exitCallback = callback

    def interpretExit(self, exitcode: int, *, requested: bool = False) -> RuntimeExit:
        """Interpret one raw code once at the runtime boundary."""
        if requested:
            reason = RuntimeExitReason.Stopped
        elif exitcode == self.ExitCode.ConfigurationError.value:
            reason = RuntimeExitReason.InvalidConfiguration
        elif exitcode == self.ExitCode.ServerStartFailure.value:
            reason = RuntimeExitReason.StartFailure
        elif exitcode == self.ExitCode.SystemShuttingDown.value:
            reason = RuntimeExitReason.SystemShuttingDown
        else:
            reason = RuntimeExitReason.Unexpected

        return RuntimeExit(exitcode, reason)

    def publishExit(self, event: RuntimeExit):
        """Record and publish one interpreted exit through the stable event sink."""
        if not isinstance(event, RuntimeExit):
            raise TypeError('runtime exits must be RuntimeExit values')

        # Store before handing off: the owner may observe the stopped runtime
        # before its queued Qt callback is delivered.
        if self._lastExit is None:
            self._lastExit = event

        if callable(self._exitCallback):
            self._exitCallback(self, event)

    def isRunning(self) -> bool:
        """Passively report execution liveness without consuming an exit."""
        return self.state is RuntimeState.Alive

    @staticmethod
    @abstractmethod
    def name() -> str:
        """Return the runtime implementation's user-visible name."""
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def version() -> str:
        """Return the bundled implementation version, if one exists."""
        raise NotImplementedError

    @abstractmethod
    def start(self):
        """Acquire execution resources or raise RuntimeStartError."""
        raise NotImplementedError

    @abstractmethod
    def stop(self):
        """Stop execution while leaving this runtime safe to dispose."""
        raise NotImplementedError

    def dispose(self):
        """Idempotently release final callbacks and execution resources."""
        if self._disposed:
            return

        if self.state in (
            RuntimeState.Starting,
            RuntimeState.Alive,
            RuntimeState.Stopping,
        ):
            self.stop()

        self._exitCallback = None
        self._disposed = True
        self.setState(RuntimeState.Disposed)
