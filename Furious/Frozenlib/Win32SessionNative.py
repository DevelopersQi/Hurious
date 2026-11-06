# Copyright (C) 2024–present  Loren Eteval & contributors
#
# This file is part of Furious.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Native Windows session shutdown notifications without a binary extension.

The listener owns a hidden top-level window on a dedicated thread. Windows
broadcasts WM_QUERYENDSESSION before logoff/shutdown and WM_ENDSESSION after
the request has been accepted. The callback is invoked only for a confirmed
end session, and the query is always accepted so Furious never blocks shutdown.
"""

from __future__ import annotations

import ctypes
import logging
import os
import threading
from ctypes import wintypes
from typing import Callable

logger = logging.getLogger(__name__)

if os.name != "nt":
    raise ImportError("Win32SessionNative is available only on Windows")

_user32 = ctypes.WinDLL("user32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_HWND = ctypes.c_void_p
_HINSTANCE = ctypes.c_void_p
_HMENU = ctypes.c_void_p
_HICON = ctypes.c_void_p
_HCURSOR = ctypes.c_void_p
_HBRUSH = ctypes.c_void_p
_LRESULT = ctypes.c_ssize_t
_WPARAM = ctypes.c_size_t
_LPARAM = ctypes.c_ssize_t

_WM_CLOSE = 0x0010
_WM_DESTROY = 0x0002
_WM_QUERYENDSESSION = 0x0011
_WM_ENDSESSION = 0x0016
_WS_EX_TOOLWINDOW = 0x00000080
_WS_EX_NOACTIVATE = 0x08000000
_WS_POPUP = 0x80000000
_ERROR_CLASS_ALREADY_EXISTS = 1410

_WNDPROC = ctypes.WINFUNCTYPE(
    _LRESULT, _HWND, wintypes.UINT, _WPARAM, _LPARAM
)


class _WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style", wintypes.UINT),
        ("lpfnWndProc", _WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", _HINSTANCE),
        ("hIcon", _HICON),
        ("hCursor", _HCURSOR),
        ("hbrBackground", _HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    ]


_user32.DefWindowProcW.argtypes = [_HWND, wintypes.UINT, _WPARAM, _LPARAM]
_user32.DefWindowProcW.restype = _LRESULT
_user32.RegisterClassW.argtypes = [ctypes.POINTER(_WNDCLASSW)]
_user32.RegisterClassW.restype = wintypes.ATOM
_user32.CreateWindowExW.argtypes = [
    wintypes.DWORD,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.DWORD,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    _HWND,
    _HMENU,
    _HINSTANCE,
    ctypes.c_void_p,
]
_user32.CreateWindowExW.restype = _HWND
_user32.DestroyWindow.argtypes = [_HWND]
_user32.DestroyWindow.restype = wintypes.BOOL
_user32.PostMessageW.argtypes = [_HWND, wintypes.UINT, _WPARAM, _LPARAM]
_user32.PostMessageW.restype = wintypes.BOOL
_user32.GetMessageW.argtypes = [
    ctypes.POINTER(wintypes.MSG),
    _HWND,
    wintypes.UINT,
    wintypes.UINT,
]
_user32.GetMessageW.restype = ctypes.c_int
_user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
_user32.TranslateMessage.restype = wintypes.BOOL
_user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
_user32.DispatchMessageW.restype = _LRESULT
_kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
_kernel32.GetModuleHandleW.restype = _HINSTANCE
_kernel32.GetCurrentProcessId.restype = wintypes.DWORD

_lock = threading.RLock()
_ready = threading.Event()
_callback: Callable[[], None] | None = None
_hwnd: _HWND | None = None
_running = False
_callback_invoked = False
_class_name = f"Furious.Win32Session.{_kernel32.GetCurrentProcessId()}"


def _window_proc(hwnd, message, wparam, lparam):
    global _callback_invoked

    try:
        if message == _WM_QUERYENDSESSION:
            # Do not veto Windows logoff or shutdown.
            return 1

        if message == _WM_ENDSESSION:
            if wparam:
                with _lock:
                    callback = None if _callback_invoked else _callback
                    _callback_invoked = True

                if callback is not None:
                    try:
                        callback()
                    except Exception:
                        logger.exception("Windows session shutdown callback failed")

            return 0

        if message == _WM_CLOSE:
            _user32.DestroyWindow(hwnd)
            return 0

        if message == _WM_DESTROY:
            _user32.PostQuitMessage(0)
            return 0
    except Exception:
        # Exceptions must never cross the native window-procedure boundary.
        logger.exception("Windows session window procedure failed")

    return _user32.DefWindowProcW(hwnd, message, wparam, lparam)


_window_proc_callback = _WNDPROC(_window_proc)


def set(callback: Callable[[], None]) -> bool:
    """Register the callback invoked after Windows confirms logoff/shutdown."""
    global _callback, _callback_invoked

    if not callable(callback):
        raise TypeError("callback must be callable")

    with _lock:
        if _running:
            return False
        _callback = callback
        _callback_invoked = False

    return True


def run() -> bool:
    """Create the hidden notification window and run its message loop."""
    global _hwnd, _running, _callback

    with _lock:
        if _running:
            return False
        if _callback is None:
            logger.error("Windows session callback has not been configured")
            return False
        _running = True
        _ready.clear()

    window = None
    try:
        instance = _kernel32.GetModuleHandleW(None)
        window_class = _WNDCLASSW()
        window_class.lpfnWndProc = _window_proc_callback
        window_class.hInstance = instance
        window_class.lpszClassName = _class_name

        ctypes.set_last_error(0)
        atom = _user32.RegisterClassW(ctypes.byref(window_class))
        if not atom and ctypes.get_last_error() != _ERROR_CLASS_ALREADY_EXISTS:
            raise ctypes.WinError(ctypes.get_last_error())

        window = _user32.CreateWindowExW(
            _WS_EX_TOOLWINDOW | _WS_EX_NOACTIVATE,
            _class_name,
            _class_name,
            _WS_POPUP,
            0,
            0,
            0,
            0,
            None,
            None,
            instance,
            None,
        )
        if not window:
            raise ctypes.WinError(ctypes.get_last_error())

        with _lock:
            _hwnd = window
        _ready.set()

        message = wintypes.MSG()
        while True:
            result = _user32.GetMessageW(ctypes.byref(message), None, 0, 0)
            if result == -1:
                raise ctypes.WinError(ctypes.get_last_error())
            if result == 0:
                break
            _user32.TranslateMessage(ctypes.byref(message))
            _user32.DispatchMessageW(ctypes.byref(message))

        return True
    except Exception:
        logger.exception("Windows session notification listener failed")
        return False
    finally:
        if window:
            try:
                _user32.DestroyWindow(window)
            except Exception:
                logger.exception("Unable to destroy Windows session notification window")

        with _lock:
            _hwnd = None
            _running = False
            _callback = None
        _ready.set()


def off() -> bool:
    """Stop the listener and release its callback."""
    global _callback

    with _lock:
        if not _running:
            _callback = None
            return True

    if not _ready.wait(5.0):
        logger.error("Windows session listener did not become ready")
        return False

    with _lock:
        window = _hwnd

    if not window:
        return False

    if not _user32.PostMessageW(window, _WM_CLOSE, 0, 0):
        logger.error(
            "Unable to stop Windows session listener: %s",
            ctypes.WinError(ctypes.get_last_error()),
        )
        return False

    return True
