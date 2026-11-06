"""Behavioral tests for the built-in Windows session listener."""

from __future__ import annotations

import ctypes
import importlib.util
import pathlib
import sys
import threading
import unittest


@unittest.skipUnless(sys.platform == "win32", "Windows-only native API test")
class Win32SessionNativeTests(unittest.TestCase):
    def setUp(self):
        module_path = (
            pathlib.Path(__file__).resolve().parents[1]
            / "Furious"
            / "Frozenlib"
            / "Win32SessionNative.py"
        )
        spec = importlib.util.spec_from_file_location(
            "_furious_win32session_native_test", module_path
        )
        self.assertIsNotNone(spec)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def test_shutdown_messages_invoke_callback_and_listener_stops(self):
        callback_count = 0
        callback_lock = threading.Lock()
        callback_called = threading.Event()

        def callback():
            nonlocal callback_count
            with callback_lock:
                callback_count += 1
            callback_called.set()

        self.assertTrue(self.module.set(callback))
        listener = threading.Thread(target=self.module.run, daemon=True)
        listener.start()

        try:
            self.assertTrue(self.module._ready.wait(5.0))
            hwnd = self.module._hwnd
            self.assertTrue(hwnd)

            send_message = self.module._user32.SendMessageW
            send_message.argtypes = [
                self.module._HWND,
                ctypes.c_uint,
                self.module._WPARAM,
                self.module._LPARAM,
            ]
            send_message.restype = self.module._LRESULT

            # Windows must be allowed to continue logoff/shutdown.
            self.assertEqual(
                send_message(hwnd, self.module._WM_QUERYENDSESSION, 0, 0), 1
            )

            # A cancelled end-session notification must not invoke cleanup.
            send_message(hwnd, self.module._WM_ENDSESSION, 0, 0)
            self.assertFalse(callback_called.is_set())

            # Only a confirmed end-session notification invokes the callback.
            send_message(hwnd, self.module._WM_ENDSESSION, 1, 0)
            self.assertTrue(callback_called.wait(5.0))

            with callback_lock:
                self.assertEqual(callback_count, 1)
        finally:
            self.assertTrue(self.module.off())
            listener.join(5.0)

        self.assertFalse(listener.is_alive())


if __name__ == "__main__":
    unittest.main()
