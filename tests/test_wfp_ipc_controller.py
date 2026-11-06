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

    def _record(self, command):
        with self.lock:
            self.calls.append((command, get_ident()))

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
        self.assertTrue(all(thread_id != main_thread for _, thread_id in calls))
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

    def test_rejects_new_commands_after_close(self):
        worker = _WfpIpcWorker(lambda: None, lambda *args: None)
        worker.close()

        self.assertFalse(worker.submit(1, "status"))


if __name__ == "__main__":
    unittest.main()
