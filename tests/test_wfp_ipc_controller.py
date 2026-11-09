import threading
import time
import unittest

from Furious.Service.WfpIpcController import (
    MAX_PENDING_WFP_COMMANDS,
    _WfpIpcWorker,
)


class _Client:
    def __init__(self, fail=False, entered=None, release=None):
        self.fail = fail
        self.entered = entered
        self.release = release

    def status(self):
        if self.entered is not None:
            self.entered.set()
        if self.release is not None:
            self.release.wait(2.0)
        if self.fail:
            raise RuntimeError("simulated service restart")
        return "ok"


class WfpIpcControllerTests(unittest.TestCase):
    def test_queue_is_bounded_and_rejects_overload_without_blocking(self):
        entered = threading.Event()
        release = threading.Event()
        completed = []
        worker = _WfpIpcWorker(
            lambda: _Client(entered=entered, release=release),
            lambda *args: completed.append(args),
        )
        try:
            self.assertTrue(worker.submit(1, "status"))
            self.assertTrue(entered.wait(1.0))
            for request_id in range(2, MAX_PENDING_WFP_COMMANDS + 2):
                self.assertTrue(worker.submit(request_id, "status"))

            started = time.monotonic()
            self.assertFalse(
                worker.submit(MAX_PENDING_WFP_COMMANDS + 2, "status")
            )
            self.assertLess(time.monotonic() - started, 0.1)
        finally:
            release.set()
            worker.close()

        self.assertEqual(len(completed), MAX_PENDING_WFP_COMMANDS + 1)

    def test_failed_request_recreates_client_for_service_recovery(self):
        completed = []
        factory_calls = []
        first_done = threading.Event()
        second_done = threading.Event()

        def factory():
            factory_calls.append(len(factory_calls) + 1)
            return _Client(fail=len(factory_calls) == 1)

        def callback(request_id, command, result, error):
            completed.append((request_id, result, error))
            (first_done if request_id == 1 else second_done).set()

        worker = _WfpIpcWorker(factory, callback)
        try:
            self.assertTrue(worker.submit(1, "status"))
            self.assertTrue(first_done.wait(1.0))
            self.assertTrue(worker.submit(2, "status"))
            self.assertTrue(second_done.wait(1.0))
        finally:
            worker.close()

        self.assertEqual(factory_calls, [1, 2])
        self.assertIn("simulated service restart", completed[0][2])
        self.assertEqual(completed[1][1:], ("ok", ""))


if __name__ == "__main__":
    unittest.main()
