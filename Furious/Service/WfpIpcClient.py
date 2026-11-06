# Copyright (C) 2024–present  Loren Eteval & contributors <loren.eteval@proton.me>
#
# This file is part of Furious and is licensed under GPL-3.0-or-later.

"""Strict client implementation for the elevated Windows WFP control pipe."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import count
from threading import Lock
import struct
import sys
import time


PIPE_NAME = r"\\.\pipe\FuriousWfpService.v1"
IPC_MAGIC = 0x46575043
IPC_VERSION = 1
MAX_MESSAGE_SIZE = 64 * 1024

COMMAND_STATUS = 1
COMMAND_SET_POLICY = 2
COMMAND_CLEAR_POLICY = 3
COMMAND_DRIVER_STATUS = 4
COMMAND_SET_ENDPOINT_CONFIG = 5
COMMAND_CLEAR_ENDPOINT_CONFIG = 6

REDIRECT_ABI_VERSION = 2
MAX_EXCLUDED_PROCESS_IDS = 8
REDIRECT_FLAG_IPV4 = 0x00000001
REDIRECT_FLAG_IPV6 = 0x00000002
REDIRECT_FLAG_TCP = 0x00000004
REDIRECT_FLAG_UDP = 0x00000008
REDIRECT_KNOWN_FLAGS = 0x0000000F

_HEADER = struct.Struct("<IHHIIQ")
_RESPONSE = struct.Struct("<IHHIIQII")
_ENDPOINT_CONFIG = struct.Struct("<IIIIIIQHHHHI8I")


class WfpIpcError(RuntimeError):
    """Base exception for WFP control-plane communication failures."""


class WfpIpcUnavailable(WfpIpcError):
    """The elevated WFP service cannot currently be reached."""


class WfpIpcProtocolError(WfpIpcError):
    """The peer returned a malformed or mismatched response."""


class WfpIpcRemoteError(WfpIpcError):
    """The service rejected a valid command with a Win32 status."""

    def __init__(self, status):
        self.status = int(status)
        super().__init__(f"WFP service command failed with Win32 status {self.status}")


@dataclass(frozen=True)
class WfpIpcResponse:
    command: int
    request_id: int
    win32_status: int
    service_state: int


_request_ids = count(1)
_request_ids_lock = Lock()


def _next_request_id():
    with _request_ids_lock:
        return next(_request_ids) & 0xFFFFFFFFFFFFFFFF


def build_request(command, payload=b"", request_id=None):
    """Encode one complete message-mode pipe request."""
    payload = bytes(payload)
    if request_id is None:
        request_id = _next_request_id()
    if not 0 <= int(command) <= 0xFFFFFFFF:
        raise ValueError("command must fit in uint32")
    if not 0 <= int(request_id) <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("request_id must fit in uint64")
    total_size = _HEADER.size + len(payload)
    if total_size > MAX_MESSAGE_SIZE:
        raise ValueError("WFP IPC request exceeds the protocol size limit")
    return _HEADER.pack(
        IPC_MAGIC, IPC_VERSION, _HEADER.size, total_size,
        int(command), int(request_id),
    ) + payload


def parse_response(data, command, request_id):
    """Validate the fixed-size response and bind it to its request."""
    data = bytes(data)
    if len(data) != _RESPONSE.size:
        raise WfpIpcProtocolError("WFP service returned an invalid response size")

    magic, version, header_size, total_size, response_command, response_id, status, state = (
        _RESPONSE.unpack(data)
    )
    if (
        magic != IPC_MAGIC
        or version != IPC_VERSION
        or header_size != _HEADER.size
        or total_size != _RESPONSE.size
        or response_command != int(command)
        or response_id != int(request_id)
    ):
        raise WfpIpcProtocolError("WFP service response does not match the request")

    return WfpIpcResponse(response_command, response_id, status, state)


def pack_endpoint_config(
    *,
    backend,
    flags,
    proxy_process_id,
    policy_generation,
    tcp_port_v4=0,
    udp_port_v4=0,
    tcp_port_v6=0,
    udp_port_v6=0,
    excluded_process_ids=(),
):
    """Serialize the packed 76-byte FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG ABI."""
    excluded = tuple(int(pid) for pid in excluded_process_ids)
    values = (
        int(backend), int(flags), int(proxy_process_id), int(policy_generation),
        int(tcp_port_v4), int(udp_port_v4), int(tcp_port_v6), int(udp_port_v6),
    )
    backend, flags, proxy_pid, generation, tcp4, udp4, tcp6, udp6 = values

    if not 1 <= backend <= 3:
        raise ValueError("backend must be in the supported range 1..3")
    if not 0 < proxy_pid <= 0xFFFFFFFF:
        raise ValueError("proxy_process_id must be a non-zero uint32")
    if not 0 < generation <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("policy_generation must be a non-zero uint64")
    if flags & ~REDIRECT_KNOWN_FLAGS:
        raise ValueError("flags contain unsupported bits")
    if not flags & (REDIRECT_FLAG_IPV4 | REDIRECT_FLAG_IPV6):
        raise ValueError("at least one address family must be enabled")
    if not flags & (REDIRECT_FLAG_TCP | REDIRECT_FLAG_UDP):
        raise ValueError("at least one transport protocol must be enabled")
    if len(excluded) > MAX_EXCLUDED_PROCESS_IDS:
        raise ValueError("too many excluded process IDs")
    if any(pid <= 0 or pid > 0xFFFFFFFF for pid in excluded):
        raise ValueError("excluded process IDs must be non-zero uint32 values")
    if proxy_pid in excluded or len(set(excluded)) != len(excluded):
        raise ValueError("excluded process IDs must be unique and differ from proxy PID")

    for port in (tcp4, udp4, tcp6, udp6):
        if not 0 <= port <= 0xFFFF:
            raise ValueError("redirect ports must fit in uint16")

    v4 = bool(flags & REDIRECT_FLAG_IPV4)
    v6 = bool(flags & REDIRECT_FLAG_IPV6)
    tcp = bool(flags & REDIRECT_FLAG_TCP)
    udp = bool(flags & REDIRECT_FLAG_UDP)
    if (
        (v4 and tcp) != bool(tcp4)
        or (v4 and udp) != bool(udp4)
        or (v6 and tcp) != bool(tcp6)
        or (v6 and udp) != bool(udp6)
        or (not v4 and (tcp4 or udp4))
        or (not v6 and (tcp6 or udp6))
        or (not tcp and (tcp4 or tcp6))
        or (not udp and (udp4 or udp6))
    ):
        raise ValueError("redirect ports do not match the enabled flags")

    padded_pids = excluded + (0,) * (MAX_EXCLUDED_PROCESS_IDS - len(excluded))
    return _ENDPOINT_CONFIG.pack(
        _ENDPOINT_CONFIG.size,
        REDIRECT_ABI_VERSION,
        backend,
        flags,
        proxy_pid,
        0,
        generation,
        tcp4,
        udp4,
        tcp6,
        udp6,
        len(excluded),
        *padded_pids,
    )


class WindowsNamedPipeTransport:
    """Open one local message-mode pipe connection per request."""

    def __init__(self, pipe_name=PIPE_NAME, timeout_ms=500):
        self.pipe_name = str(pipe_name)
        self.timeout_ms = max(int(timeout_ms), 1)

    def exchange(self, request):
        if sys.platform != "win32":
            raise WfpIpcUnavailable("WFP named-pipe IPC is available only on Windows")

        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = (
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        )
        create_file.restype = wintypes.HANDLE
        wait_pipe = kernel32.WaitNamedPipeW
        wait_pipe.argtypes = (wintypes.LPCWSTR, wintypes.DWORD)
        wait_pipe.restype = wintypes.BOOL
        write_file = kernel32.WriteFile
        write_file.argtypes = (
            wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
        )
        write_file.restype = wintypes.BOOL
        read_file = kernel32.ReadFile
        read_file.argtypes = (
            wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
        )
        read_file.restype = wintypes.BOOL
        set_pipe_state = kernel32.SetNamedPipeHandleState
        set_pipe_state.argtypes = (
            wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        )
        set_pipe_state.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL

        invalid_handle = ctypes.c_void_p(-1).value
        handle = create_file(
            self.pipe_name, 0xC0000000, 0, None, 3, 0, None
        )
        if handle == invalid_handle:
            error = ctypes.get_last_error()
            if error == 231:  # ERROR_PIPE_BUSY
                if wait_pipe(self.pipe_name, self.timeout_ms):
                    handle = create_file(
                        self.pipe_name, 0xC0000000, 0, None, 3, 0, None
                    )
                    if handle != invalid_handle:
                        error = 0
                    else:
                        error = ctypes.get_last_error()
            if handle == invalid_handle:
                raise WfpIpcUnavailable(
                    f"cannot connect to WFP service pipe (Win32 error {error})"
                )

        try:
            # Use message-mode, nonblocking reads so a stalled service cannot
            # indefinitely hang the caller.
            mode = wintypes.DWORD(0x00000002 | 0x00000001)  # MESSAGE | NOWAIT
            if not set_pipe_state(handle, ctypes.byref(mode), None, None):
                raise WfpIpcUnavailable(
                    f"cannot configure WFP service pipe (Win32 error {ctypes.get_last_error()})"
                )

            deadline = time.monotonic() + self.timeout_ms / 1000.0
            request_buffer = ctypes.create_string_buffer(request)
            written = wintypes.DWORD()
            while not write_file(
                handle, request_buffer, len(request), ctypes.byref(written), None
            ):
                error = ctypes.get_last_error()
                if error != 232 or time.monotonic() >= deadline:  # ERROR_NO_DATA
                    raise WfpIpcUnavailable(
                        f"cannot write WFP service request (Win32 error {error})"
                    )
                kernel32.Sleep(5)
            if written.value != len(request):
                raise WfpIpcProtocolError("WFP service request was only partially written")

            response_buffer = ctypes.create_string_buffer(_RESPONSE.size)
            received = wintypes.DWORD()
            while not read_file(
                handle, response_buffer, _RESPONSE.size,
                ctypes.byref(received), None,
            ):
                error = ctypes.get_last_error()
                if error != 232 or time.monotonic() >= deadline:  # ERROR_NO_DATA
                    raise WfpIpcUnavailable(
                        f"cannot read WFP service response (Win32 error {error})"
                    )
                kernel32.Sleep(5)

            if received.value != _RESPONSE.size:
                raise WfpIpcProtocolError("WFP service returned a truncated response")
            return response_buffer.raw[:received.value]
        finally:
            close_handle(handle)


class WfpIpcClient:
    """Synchronous, bounded request client; callers must keep it off the UI thread."""

    def __init__(self, transport=None):
        self._transport = transport or WindowsNamedPipeTransport()

    def request(self, command, payload=b""):
        request_id = _next_request_id()
        request = build_request(command, payload, request_id)
        raw_response = self._transport.exchange(request)
        response = parse_response(raw_response, command, request_id)
        if response.win32_status:
            raise WfpIpcRemoteError(response.win32_status)
        return response

    def status(self):
        return self.request(COMMAND_STATUS)

    def driverStatus(self):
        return self.request(COMMAND_DRIVER_STATUS)

    def setEndpointConfig(self, payload):
        if len(payload) != _ENDPOINT_CONFIG.size:
            raise ValueError("endpoint config payload must be exactly 76 bytes")
        return self.request(COMMAND_SET_ENDPOINT_CONFIG, payload)

    def clearEndpointConfig(self):
        return self.request(COMMAND_CLEAR_ENDPOINT_CONFIG)
