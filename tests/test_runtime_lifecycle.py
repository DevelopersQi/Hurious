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

"""Verify typed runtime lifecycle, ownership transfer, and Qt-thread handoff."""

from Furious.Core import MultiprocessingRuntime, ProcessLaunchSpec
from Furious.Core.Tun2socks import Tun2socks
from Furious.Core.ProcessOutput import ProcessOutputRedirector
from Furious.Interface import (
    CoreRuntime,
    RuntimeExitReason,
    RuntimeStartError,
    RuntimeState,
)
from Furious.Service.RuntimeLease import RuntimeEventRouter, RuntimeLease

from PySide6 import QtCore

from tests.support import application, collectAtBoundary, processQtEvents, waitFor

from unittest import TestCase, mock

import threading
import weakref
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event


class _Runtime(CoreRuntime):
    """Provide an execution-free runtime for lease tests."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.stopCount = 0

    @staticmethod
    def name():
        return 'Lease fixture'

    @staticmethod
    def version():
        return '1'

    def start(self):
        self.setState(RuntimeState.Alive)

    def stop(self):
        self.stopCount += 1
        self.setState(RuntimeState.Exited)

    def publishCode(self, exitcode):
        """Interpret and publish one fixture process-exit code."""
        self.publishExit(self.interpretExit(exitcode))


class _ProcessRuntime(MultiprocessingRuntime):
    """Provide names around the reusable multiprocessing implementation."""

    def __init__(self, **kwargs):
        super().__init__(
            lambda _output: ProcessLaunchSpec(lambda: None),
            **kwargs,
        )

    @staticmethod
    def name():
        return 'Process fixture'

    @staticmethod
    def version():
        return '1'


class _AttemptOwner(QtCore.QObject):
    """Record runtime exits and the Qt thread that consumed them."""

    def __init__(self):
        super().__init__()
        self.events = []

    def runtimeExited(self, runtime, event):
        self.events.append((runtime, event, QtCore.QThread.currentThread()))


class RuntimeLifecycleTest(TestCase):
    """Exercise semantic exits independently from connection readiness."""

    @classmethod
    def setUpClass(cls):
        cls.app = application()

    def testProducerFlushesFinalCoreOutputAfterWriterCloses(self):
        """Forward final stderr lines even when the core exits between polls."""
        with TemporaryDirectory() as directory:
            temporaryFile = Path(directory) / 'core-output.log'
            temporaryFile.write_bytes(
                b'tun2socks: initializing Wintun adapter\n'
                b'tun2socks: failed to create Wintun adapter\n'
            )
            finished = Event()
            finished.set()
            msgQueue = mock.Mock()

            ProcessOutputRedirector._produceMessages(
                msgQueue,
                str(temporaryFile),
                finished,
            )

        self.assertEqual(
            [call.args[0] for call in msgQueue.putMessage.call_args_list],
            [
                'tun2socks: initializing Wintun adapter\n',
                'tun2socks: failed to create Wintun adapter\n',
            ],
        )

    def testWatcherThreadExitIsConsumedOnRouterQtThread(self):
        """Queue a worker-thread publication onto the Qt owner's thread."""
        owner = _AttemptOwner()
        router = RuntimeEventRouter()
        runtime = _Runtime(exitCallback=router.publish)
        router.attach(runtime, owner)
        lease = RuntimeLease(runtime, router)

        thread = threading.Thread(target=runtime.publishCode, args=(9,))

        thread.start()
        thread.join()

        self.assertTrue(waitFor(lambda: bool(owner.events)))
        self.assertIs(owner.events[0][2], self.app.thread())
        self.assertEqual(owner.events[0][1].code, 9)

        lease.release()

    def testRouterRejectsAnUntypedRuntimeExit(self):
        """Require interpretation at the concrete runtime boundary."""
        router = RuntimeEventRouter()
        runtime = _Runtime()

        with self.assertRaisesRegex(TypeError, 'requires a RuntimeExit'):
            router.publish(runtime, 23)

        router.deleteLater()

    def testRepeatedRoutersAvoidPackagedBoundMethodRetention(self):
        """Keep released queued routers out of Nuitka-like callback protection."""
        originalConnect = QtCore.SignalInstance.connect
        protectedCallbacks = []
        references = []

        def protectingConnect(signal, callback, *args, **kwargs):
            if getattr(callback, '__self__', None) is not None:
                protectedCallbacks.append(callback)

            return originalConnect(signal, callback, *args, **kwargs)

        with mock.patch.object(
            QtCore.SignalInstance,
            'connect',
            protectingConnect,
        ):
            for _index in range(32):
                router = RuntimeEventRouter()
                references.append(weakref.ref(router))

                router.finishRelease()
                router.deleteLater()

        del router
        collectAtBoundary()

        self.assertEqual(protectedCallbacks, [])
        self.assertTrue(all(reference() is None for reference in references))

    def testCommitNearQueuedExitUsesOneStableRoute(self):
        """Deliver an already queued exit exactly once to the committed owner."""
        owner = _AttemptOwner()
        committed = []
        router = RuntimeEventRouter()
        runtime = _Runtime(exitCallback=router.publish)
        router.attach(runtime, owner)
        lease = RuntimeLease(runtime, router)

        runtime.publishCode(11)
        lease.commit(lambda current, event: committed.append((current, event)))

        processQtEvents()

        self.assertEqual(owner.events, [])
        self.assertEqual(len(committed), 1)
        self.assertIs(committed[0][0], runtime)
        self.assertEqual(committed[0][1].code, 11)

        lease.release()

    def testPostCommitDuplicateExitIsDeliveredOnce(self):
        """Keep one terminal authority after ownership has transferred."""
        owner = _AttemptOwner()
        committed = []
        router = RuntimeEventRouter()
        runtime = _Runtime(exitCallback=router.publish)
        router.attach(runtime, owner)
        lease = RuntimeLease(runtime, router)
        lease.commit(lambda current, event: committed.append((current, event)))

        runtime.publishCode(12)
        runtime.publishCode(13)

        processQtEvents()

        self.assertEqual(owner.events, [])
        self.assertEqual(len(committed), 1)
        self.assertEqual(committed[0][1].code, 12)

        lease.release()

    def testReleaseSuppressesLateQueuedExitAndIsIdempotent(self):
        """Ignore late notifications and clean the exact runtime only once."""
        owner = _AttemptOwner()
        router = RuntimeEventRouter()
        runtime = _Runtime(exitCallback=router.publish)
        router.attach(runtime, owner)
        lease = RuntimeLease(runtime, router)

        runtime.publishCode(13)

        lease.release()
        lease.release()

        processQtEvents()

        self.assertEqual(owner.events, [])
        self.assertEqual(runtime.stopCount, 1)
        self.assertIs(runtime.state, RuntimeState.Disposed)

    def testTun2socksUsesSharedExitCodeContract(self):
        """Keep inherited exit interpretation valid for every TUN child exit."""
        self.assertIs(Tun2socks.ExitCode, CoreRuntime.ExitCode)

        runtime = mock.Mock()
        runtime.ExitCode = Tun2socks.ExitCode

        event = CoreRuntime.interpretExit(runtime, 61)

        self.assertIs(event.reason, RuntimeExitReason.Unexpected)
        self.assertEqual(event.code, 61)

    def testMultiprocessingRuntimePublishesOneInterpretedExit(self):
        """Detect, reap, and publish one raw child transition internally."""
        process = mock.Mock()
        process.is_alive.side_effect = (True, True, False)
        process.exitcode = CoreRuntime.ExitCode.ConfigurationError.value
        events = []

        with mock.patch(
            'Furious.Core.MultiprocessingRuntime.multiprocessing.Process',
            return_value=process,
        ):
            runtime = _ProcessRuntime(
                exitCallback=lambda current, event: events.append((current, event))
            )

            runtime.start()

            self.assertIs(runtime.state, RuntimeState.Alive)
            self.assertTrue(runtime.isRunning())
            runtime._output.putMessage('tun2socks: failed to create Wintun adapter')
            # multiprocessing.Queue uses an asynchronous feeder thread; wait
            # until the parent-side pipe has the message before simulating the
            # child exit, otherwise this fixture races the queue transport.
            self.assertTrue(waitFor(lambda: runtime._output._reader.poll()))

            runtime._pollProcess()
            runtime._pollProcess()

        self.assertEqual(len(events), 1)
        self.assertIs(events[0][1].reason, RuntimeExitReason.InvalidConfiguration)
        self.assertEqual(events[0][1].code, 23)
        self.assertIn('failed to create Wintun adapter', events[0][1].details)
        process.close.assert_called_once_with()

        runtime.dispose()

        self.assertIsNone(runtime._monitorConnection)
        self.assertIsNone(runtime._output._timerConnection)

        runtime.dispose()

    def testMultiprocessingRuntimeExposesOnlyLiveChildPid(self):
        """Expose a child PID only while the owned process is still alive."""
        process = mock.Mock()
        process.pid = 4321
        process.is_alive.return_value = True

        with mock.patch(
            'Furious.Core.MultiprocessingRuntime.multiprocessing.Process',
            return_value=process,
        ):
            runtime = _ProcessRuntime()
            runtime.start()

            self.assertEqual(runtime.processId, 4321)

            process.is_alive.return_value = False
            process.exitcode = 0
            runtime._pollProcess()

            self.assertIsNone(runtime.processId)
            self.assertIsNone(runtime.process)

        runtime.dispose()

    def testMultiprocessingSpawnFailureRaisesStructuredError(self):
        """Represent expected acquisition failure without mutable side state."""
        process = mock.Mock()
        process.start.side_effect = OSError('fixture spawn failure')

        with mock.patch(
            'Furious.Core.MultiprocessingRuntime.multiprocessing.Process',
            return_value=process,
        ):
            runtime = _ProcessRuntime()

            with self.assertRaises(RuntimeStartError) as raised:
                runtime.start()

        self.assertIs(raised.exception.reason, RuntimeExitReason.StartFailure)
        self.assertIn('fixture spawn failure', raised.exception.details)

        runtime.dispose()

        self.assertIsNone(runtime._monitorConnection)
        self.assertIsNone(runtime._output._timerConnection)


    def testImmediateChildExitRaisesWithCapturedDiagnostics(self):
        """Preserve stderr when a child exits before the first monitor tick."""
        process = mock.Mock()
        process.is_alive.return_value = False
        process.exitcode = 1
        events = []

        with mock.patch(
            'Furious.Core.MultiprocessingRuntime.multiprocessing.Process',
            return_value=process,
        ):
            runtime = _ProcessRuntime(
                exitCallback=lambda current, event: events.append(event)
            )
            runtime._output.drainPendingMessages = mock.Mock(
                return_value='hysteria2: invalid client configuration'
            )

            with self.assertRaises(RuntimeStartError) as raised:
                runtime.start()

        self.assertEqual(raised.exception.code, 1)
        self.assertIn('invalid client configuration', raised.exception.details)
        self.assertIsNone(runtime.process)
        self.assertFalse(events)

        runtime.dispose()

    def testUnexpectedExitCanBeFollowedByRepeatedReconnects(self):
        """Reap each failed child before constructing the next connection."""
        processes = []
        for code in (1, 1, 0):
            process = mock.Mock()
            process.pid = 7000 + len(processes)
            process.exitcode = code
            process.is_alive.side_effect = [True, False, True, False, True]
            processes.append(process)

        events = []
        with mock.patch(
            'Furious.Core.MultiprocessingRuntime.multiprocessing.Process',
            side_effect=processes,
        ) as processFactory:
            runtime = _ProcessRuntime(
                exitCallback=lambda current, event: events.append(event)
            )

            for index in range(3):
                runtime.start()
                runtime._pollProcess()
                if index < 2:
                    self.assertIsNone(runtime.process)

            self.assertEqual(processFactory.call_count, 3)

        self.assertEqual(len(events), 3)
        self.assertEqual([event.code for event in events], [1, 1, 0])
        for process in processes:
            process.close.assert_called_once_with()

        runtime.dispose()

    def testConcurrentStartsCreateOnlyOneChildProcess(self):
        """Serialize concurrent callers so one runtime cannot own two children."""
        enteredStart = Event()
        releaseStart = Event()
        process = mock.Mock()
        process.is_alive.return_value = True
        process.terminate.side_effect = lambda: setattr(
            process.is_alive, 'return_value', False
        )
        process.start.side_effect = lambda: (
            enteredStart.set(),
            releaseStart.wait(2),
        )
        errors = []

        with mock.patch(
            'Furious.Core.MultiprocessingRuntime.multiprocessing.Process',
            return_value=process,
        ) as processFactory:
            runtime = _ProcessRuntime()
            runtime._output.startTimer = mock.Mock()
            runtime._monitor.start = mock.Mock()

            def startRuntime():
                try:
                    runtime.start()
                except RuntimeStartError as error:
                    errors.append(error)

            first = threading.Thread(target=startRuntime)
            second = threading.Thread(target=startRuntime)

            first.start()
            self.assertTrue(enteredStart.wait(2))
            second.start()
            releaseStart.set()

            first.join(2)
            second.join(2)

            self.assertFalse(first.is_alive())
            self.assertFalse(second.is_alive())
            self.assertEqual(processFactory.call_count, 1)
            self.assertEqual(len(errors), 1)
            self.assertIn('already running', str(errors[0]))

            runtime.stop()
            runtime.dispose()


if __name__ == '__main__':
    import unittest

    unittest.main()
