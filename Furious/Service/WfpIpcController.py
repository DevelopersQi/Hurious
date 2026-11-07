# Copyright (C) 2024–present  Loren Eteval & contributors
#
# This file is part of Furious and is distributed under the GNU General Public
# License, version 3 or (at your option) any later version.

"""Serialize bounded WFP IPC requests away from the Qt GUI thread."""

from __future__ import annotations

from queue import Queue
from threading import Lock, Thread, current_thread
from itertools import count

from PySide6 import QtCore

from Furious.Service.WfpIpcClient import WfpIpcClient


class _WfpIpcWorker:
    """Own one IPC client and process commands sequentially on a daemon thread."""

    _STOP = object()

    def __init__(self, client_factory, completed):
        self._client_factory = client_factory
        self._completed = completed
        self._queue = Queue()
        self._stateLock = Lock()
        self._closed = False
        self._thread = Thread(
            target=self._run,
            name="Furious-WfpIpc",
            daemon=True,
        )
        self._thread.start()

    def submit(self, request_id, command, arguments=()):
        with self._stateLock:
            if self._closed:
                return False

            self._queue.put((int(request_id), str(command), tuple(arguments)))
            return True

    def close(self):
        with self._stateLock:
            if not self._closed:
                self._closed = True
                self._queue.put(self._STOP)

        # IPC requests are bounded; wait briefly so queued endpoint-clear and
        # broker-stop operations can finish before the application exits.
        if current_thread() is not self._thread:
            self._thread.join(timeout=3.0)

    def _run(self):
        client = None

        while True:
            item = self._queue.get()
            try:
                if item is self._STOP:
                    return

                request_id, command, arguments = item
                try:
                    if client is None:
                        client = self._client_factory()

                    if command == "status":
                        result = client.status()
                    elif command == "clear-endpoint":
                        result = client.clearEndpointConfig()
                    elif command == "start-broker":
                        result = client.startBroker(*arguments)
                    elif command == "stop-broker":
                        result = client.stopBroker()
                    elif command == "set-endpoint":
                        result = client.setEndpointConfig(arguments[0])
                    elif command == "set-policy":
                        result = client.setPolicy(*arguments)
                    elif command == "clear-policy":
                        result = client.clearPolicy()
                    else:
                        raise ValueError("unsupported WFP IPC operation")

                    self._completed(request_id, command, result, "")
                except Exception as error:
                    self._completed(request_id, command, None, str(error))
            finally:
                self._queue.task_done()


class WfpIpcController(QtCore.QObject):
    """Queue WFP control operations without blocking the application thread.

    ConnectionManager coordinates endpoint activation after broker startup.
    This controller only serializes asynchronous service commands.
    """

    requestFinished = QtCore.Signal(int, str, object, str)

    def __init__(self, client_factory=None, parent=None):
        super().__init__(parent)

        self._clientFactory = client_factory or WfpIpcClient
        self._requestIds = count(1)
        self._closed = False
        self._worker = _WfpIpcWorker(
            self._clientFactory,
            self._publishResult,
        )

    def _publishResult(self, request_id, command, result, error):
        self.requestFinished.emit(
            int(request_id),
            str(command),
            result,
            str(error),
        )

    def _submit(self, command, *arguments):
        if self._closed:
            return None

        request_id = next(self._requestIds)
        if not self._worker.submit(request_id, command, arguments):
            return None

        return request_id

    def queryStatus(self):
        """Request service status asynchronously."""
        return self._submit("status")

    def clearEndpointConfig(self):
        """Clear a previously installed endpoint configuration asynchronously."""
        return self._submit("clear-endpoint")

    def startBroker(self, socksHost, socksPort, listenIpv4=True, listenIpv6=True):
        """Start the service-hosted TCP broker asynchronously."""
        return self._submit(
            "start-broker", socksHost, socksPort, listenIpv4, listenIpv6
        )

    def stopBroker(self):
        """Stop the service-hosted TCP broker asynchronously."""
        return self._submit("stop-broker")

    def setEndpointConfig(self, payload):
        """Submit a native endpoint configuration asynchronously."""
        return self._submit("set-endpoint", bytes(payload))

    def setPolicy(self, rules, backend, policyGeneration):
        """Replace application routing policy asynchronously."""
        snapshot = tuple(dict(rule) for rule in rules)
        return self._submit("set-policy", snapshot, backend, policyGeneration)

    def clearPolicy(self):
        """Remove all application-scoped WFP routing filters asynchronously."""
        return self._submit("clear-policy")

    def close(self):
        """Stop accepting commands and let the worker drain queued requests."""
        if self._closed:
            return

        self._closed = True
        self._worker.close()
