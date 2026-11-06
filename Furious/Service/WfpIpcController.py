# Copyright (C) 2024–present  Loren Eteval & contributors
#
# This file is part of Furious and is distributed under the GNU General Public
# License, version 3 or (at your option) any later version.

"""Serialize bounded WFP IPC requests away from the Qt GUI thread."""

from __future__ import annotations

from queue import Queue
from threading import Thread
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
        self._closed = False
        self._thread = Thread(
            target=self._run,
            name="Furious-WfpIpc",
            daemon=True,
        )
        self._thread.start()

    def submit(self, request_id, command):
        if self._closed:
            return False

        self._queue.put((int(request_id), str(command)))
        return True

    def close(self):
        if self._closed:
            return

        self._closed = True
        self._queue.put(self._STOP)

    def _run(self):
        client = None

        while True:
            item = self._queue.get()
            try:
                if item is self._STOP:
                    return

                request_id, command = item
                try:
                    if client is None:
                        client = self._client_factory()

                    if command == "status":
                        result = client.status()
                    elif command == "clear-endpoint":
                        result = client.clearEndpointConfig()
                    else:
                        raise ValueError("unsupported WFP IPC operation")

                    self._completed(request_id, command, result, "")
                except Exception as error:
                    self._completed(request_id, command, None, str(error))
            finally:
                self._queue.task_done()


class WfpIpcController(QtCore.QObject):
    """Queue WFP control operations without blocking the application thread.

    Endpoint activation is intentionally not exposed here. The TCP broker must
    provide real listener ports and its process ID before SET_ENDPOINT_CONFIG
    can safely be issued.
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

    def _submit(self, command):
        if self._closed:
            return None

        request_id = next(self._requestIds)
        if not self._worker.submit(request_id, command):
            return None

        return request_id

    def queryStatus(self):
        """Request service status asynchronously."""
        return self._submit("status")

    def clearEndpointConfig(self):
        """Clear a previously installed endpoint configuration asynchronously."""
        return self._submit("clear-endpoint")

    def close(self):
        """Stop accepting commands and let the worker drain queued requests."""
        if self._closed:
            return

        self._closed = True
        self._worker.close()
