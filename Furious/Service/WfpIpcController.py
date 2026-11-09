# Copyright (C) 2024–present  Loren Eteval & contributors
#
# This file is part of Furious and is distributed under the GNU General Public
# License, version 3 or (at your option) any later version.

"""Serialize bounded WFP IPC requests away from the Qt GUI thread."""

from __future__ import annotations

from queue import Empty, Full, Queue
from threading import Lock, Thread, current_thread
from itertools import count

from PySide6 import QtCore

from Furious.Service.WfpIpcClient import WfpIpcClient


MAX_PENDING_WFP_COMMANDS = 128
WFP_WORKER_POLL_INTERVAL_SECONDS = 0.1


class _WfpIpcWorker:
    """Own one IPC client and process bounded commands on a daemon thread.

    A failed request invalidates the client instance. The next queued command
    creates a fresh client, allowing recovery after a named-pipe/service restart.
    """

    def __init__(self, client_factory, completed):
        self._client_factory = client_factory
        self._completed = completed
        self._queue = Queue(maxsize=MAX_PENDING_WFP_COMMANDS)
        self._stateLock = Lock()
        self._closed = False
        self._thread = Thread(
            target=self._run,
            name="Furious-WfpIpc",
            daemon=True,
        )
        self._thread.start()

    def submit(self, request_id, command, arguments=()):
        """Queue a command without blocking the caller or growing without bound."""
        item = (int(request_id), str(command), tuple(arguments))
        with self._stateLock:
            if self._closed:
                return False
            try:
                self._queue.put_nowait(item)
            except Full:
                return False
            return True

    def close(self):
        """Stop accepting work, drain accepted commands, then exit the worker."""
        with self._stateLock:
            self._closed = True

        # No sentinel is required: the worker drains accepted work and observes
        # _closed after the queue becomes empty. This cannot block the GUI thread
        # even when the bounded queue is full.
        if current_thread() is not self._thread:
            self._thread.join(timeout=3.0)

    def _run(self):
        client = None

        while True:
            try:
                item = self._queue.get(
                    timeout=WFP_WORKER_POLL_INTERVAL_SECONDS
                )
            except Empty:
                with self._stateLock:
                    if self._closed:
                        return
                continue

            try:
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
                    elif command == "start-udp-broker":
                        result = client.startUdpBroker(*arguments)
                    elif command == "stop-udp-broker":
                        result = client.stopUdpBroker()
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
                    # A broken pipe or service restart must not poison all
                    # subsequent commands with a stale client object.
                    client = None
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

    def startUdpBroker(self, socksHost, socksPort, listenIpv4=True, listenIpv6=True):
        """Start the service-hosted UDP broker asynchronously."""
        return self._submit(
            "start-udp-broker", socksHost, socksPort, listenIpv4, listenIpv6
        )

    def stopUdpBroker(self):
        """Stop the service-hosted UDP broker asynchronously."""
        return self._submit("stop-udp-broker")

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
        """Stop accepting commands and drain accepted work."""
        if self._closed:
            return

        self._closed = True
        self._worker.close()
