"""Tests for the serialized WFP IPC worker."""

from __future__ import annotations

from threading import Event, Lock, get_ident
import unittest

from Furious.Service.WfpIpcController import _WfpIpcWorker


class _FakeClient:
    def __init__(self, calls, lock, fail=False):
        self.calls = calls
        self.lock = lock
        self.fail = fail

    def status(self):
        return self._record("status")

    def clearEndpointConfig(self):
        return self._record("clear-endpoint")

    def startBroker(self, host, port, listen_ipv4=True, listen_ipv6=True):
        return self._record("start-broker", host, port, listen_ipv4, listen_ipv6)

    def stopBroker(self):
        return self._record("stop-broker")

    def setEndpointConfig(self, payload):
        return self._record("set-endpoint", bytes(payload))

    def _record(self, command, *arguments):
        with self.lock:
            self.calls.append((command, get_ident(), arguments))

        if self.fail:
            raise RuntimeError("service unavailable")

        return command + "-ok"


class WfpIpcWorkerTest(unittest.TestCase):
    def test_serializes_commands_on_one_background_thread(self):
        calls = []
        lock = Lock()
        completed = []
        done = Event()
        main_thread = get_ident()

        def on_complete(request_id, command, result, error):
            completed.append((request_id, command, result, error))
            if len(completed) == 2:
                done.set()

        worker = _WfpIpcWorker(
            lambda: _FakeClient(calls, lock),
            on_complete,
        )
        try:
            self.assertTrue(worker.submit(1, "status"))
            self.assertTrue(worker.submit(2, "clear-endpoint"))
            self.assertTrue(done.wait(2))
        finally:
            worker.close()

        self.assertEqual([entry[0] for entry in calls], ["status", "clear-endpoint"])
        self.assertTrue(all(entry[1] != main_thread for entry in calls))
        self.assertEqual(
            completed,
            [
                (1, "status", "status-ok", ""),
                (2, "clear-endpoint", "clear-endpoint-ok", ""),
            ],
        )

    def test_reports_transport_errors_without_killing_worker(self):
        calls = []
        lock = Lock()
        completed = []
        done = Event()

        def on_complete(request_id, command, result, error):
            completed.append((request_id, command, result, error))
            if len(completed) == 2:
                done.set()

        worker = _WfpIpcWorker(
            lambda: _FakeClient(calls, lock, fail=True),
            on_complete,
        )
        try:
            worker.submit(1, "status")
            worker.submit(2, "clear-endpoint")
            self.assertTrue(done.wait(2))
        finally:
            worker.close()

        self.assertEqual(len(completed), 2)
        self.assertTrue(all(result is None for _, _, result, _ in completed))
        self.assertTrue(all(error == "service unavailable" for _, _, _, error in completed))

    def test_forwards_broker_and_endpoint_arguments_in_queue_order(self):
        calls = []
        lock = Lock()
        completed = []
        done = Event()

        def on_complete(request_id, command, result, error):
            completed.append((request_id, command, result, error))
            if len(completed) == 3:
                done.set()

        worker = _WfpIpcWorker(lambda: _FakeClient(calls, lock), on_complete)
        try:
            worker.submit(1, "start-broker", ("127.0.0.1", 10808, True, False))
            worker.submit(2, "set-endpoint", (b"endpoint-abi",))
            worker.submit(3, "stop-broker")
            self.assertTrue(done.wait(2))
        finally:
            worker.close()

        self.assertEqual(
            [entry[0] for entry in calls],
            ["start-broker", "set-endpoint", "stop-broker"],
        )
        self.assertEqual(
            [entry[2] for entry in calls],
            [
                ("127.0.0.1", 10808, True, False),
                (b"endpoint-abi",),
                (),
            ],
        )
        self.assertEqual(
            [entry[2] for entry in completed],
            ["start-broker-ok", "set-endpoint-ok", "stop-broker-ok"],
        )

    def test_close_drains_accepted_requests_before_worker_exit(self):
        started = Event()
        release = Event()
        completed = []

        class BlockingClient:
            def status(self):
                started.set()
                self.assert_released()
                return "status-ok"

            def assert_released(self):
                if not release.wait(2):
                    raise RuntimeError("test did not release the worker")

        done = Event()

        def on_complete(request_id, command, result, error):
            completed.append((request_id, command, result, error))
            done.set()

        worker = _WfpIpcWorker(BlockingClient, on_complete)
        self.assertTrue(worker.submit(1, "status"))
        self.assertTrue(started.wait(2))
        worker.close()
        self.assertFalse(worker.submit(2, "status"))
        release.set()

        self.assertTrue(done.wait(2))
        self.assertEqual(completed, [(1, "status", "status-ok", "")])

    def test_rejects_new_commands_after_close(self):
        worker = _WfpIpcWorker(lambda: None, lambda *args: None)
        worker.close()

        self.assertFalse(worker.submit(1, "status"))


if __name__ == "__main__":
    unittest.main()
