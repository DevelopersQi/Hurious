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

"""Protect Xray asset downloads from malformed or mismatched content."""

from Furious.Backends.Xray.AssetDownloadManager import (
    XrayAssetAssetsDownloadManager,
    XrayAssetDownloadManager,
    XrayAssetSHA256DownloadManager,
)

from PySide6 import QtCore, QtNetwork

from shiboken6 import isValid

from unittest import TestCase, mock

import os
import hashlib
import unittest
import tempfile
import threading
import weakref

from tests.support import application, processQtEvents, waitFor


class _Reply:
    """Expose the byte-array portion of QNetworkReply used by the managers."""

    def __init__(self, data: bytes):
        self._data = QtCore.QByteArray(data)

    def readAll(self):
        return self._data


class _PendingReply(QtNetwork.QNetworkReply):
    """Exercise real reply signals without opening a network connection."""

    def __init__(self, parent):
        super().__init__(parent)
        self.abortCount = 0

    def abort(self):
        self.abortCount += 1
        self.setError(self.NetworkError.OperationCanceledError, 'cancelled by test')
        self.setFinished(True)

        self.finished.emit()


class XrayAssetDownloadTest(TestCase):
    """Verify checksum metadata and downloaded bytes before replacement."""

    @classmethod
    def setUpClass(cls):
        application()

    def tearDown(self):
        processQtEvents()

    def testPluginShutdownReleasesAssetClientsAndPendingHashes(self):
        """Plugin shutdown must reach the clients acquired after connection."""
        from Furious.Backends.Xray.Plugin import XrayPlugin, XrayCoreRuntimeFactory

        plugin = XrayPlugin()
        factory = next(
            item
            for item in plugin.capabilities
            if isinstance(item, XrayCoreRuntimeFactory)
        )
        manager = XrayAssetDownloadManager()
        factory._assetDownloadManager = manager

        clients = [
            client
            for helper in (manager.downloadHelperGeosite, manager.downloadHelperGeoip)
            for client in (helper.sha256Downloader, helper.assetsDownloader)
        ]
        download = mock.Mock()
        pool = mock.Mock()

        with mock.patch(
            'Furious.Backends.Xray.AssetDownloadManager.AppThreadPool',
            return_value=pool,
        ):
            clients[0].successCallback(
                _Reply(hashlib.sha256(b'new asset').hexdigest().encode()),
                filepath='missing-asset.dat',
                downloadCallback=download,
            )

        replies = []

        for client in clients:
            reply = _PendingReply(client)
            replies.append(reply)

            with mock.patch.object(client, 'get', return_value=reply):
                client.webGET('https://example.invalid/asset', logActionMessage=False)

        worker = pool.start.call_args.args[0]

        try:
            plugin.shutdown()
            plugin.shutdown()

            worker.run()
            processQtEvents()

            download.assert_not_called()
            self.assertTrue(all(not isValid(client) for client in clients))
            self.assertEqual([reply.abortCount for reply in replies], [1] * 4)
            self.assertTrue(all(not isValid(reply) for reply in replies))
        finally:
            for client in clients:
                if isValid(client):
                    client.deleteLater()

            processQtEvents()

    def testPoolHashResultsReturnToOwnerThreadAndReleaseJobs(self):
        """Real pool execution crosses back to Qt before invoking callbacks."""
        manager = XrayAssetSHA256DownloadManager()
        pool = QtCore.QThreadPool()
        deliveries = []
        expected = hashlib.sha256(b'new asset').hexdigest()

        try:
            with mock.patch(
                'Furious.Backends.Xray.AssetDownloadManager.AppThreadPool',
                return_value=pool,
            ):
                for _ in range(30):
                    manager.successCallback(
                        _Reply(expected.encode()),
                        filepath='missing-asset.dat',
                        downloadCallback=lambda digest: deliveries.append(
                            (digest, QtCore.QThread.currentThread())
                        ),
                    )

            self.assertTrue(waitFor(lambda: len(deliveries) == 30))
            self.assertEqual(deliveries, [(expected, manager.thread())] * 30)
            self.assertEqual(manager._hashJobs, {})
        finally:
            self.assertTrue(pool.waitForDone(3000))
            manager.deleteLater()
            pool.deleteLater()
            processQtEvents()

    def testRunningHashDoesNotRetainCallbackAfterOwnerDestruction(self):
        """A blocked real worker owns bytes, not a destroyed owner's callback."""
        manager = XrayAssetSHA256DownloadManager()
        pool = QtCore.QThreadPool()
        entered = threading.Event()
        release = threading.Event()
        digestFunction = hashlib.sha256
        download = mock.Mock()
        callbackReference = weakref.ref(download)
        expected = digestFunction(b'new asset').hexdigest()

        def compute(data):
            entered.set()

            if not release.wait(3):
                raise RuntimeError('test hash was not released')

            return digestFunction(data)

        try:
            with (
                mock.patch(
                    'Furious.Backends.Xray.AssetDownloadManager.AppThreadPool',
                    return_value=pool,
                ),
                mock.patch(
                    'Furious.Backends.Xray.AssetDownloadManager.hashlib.sha256',
                    side_effect=compute,
                ),
            ):
                manager.successCallback(
                    _Reply(expected.encode()),
                    filepath='missing-asset.dat',
                    downloadCallback=download,
                )
                del download

                self.assertTrue(entered.wait(3))

                manager.deleteLater()
                processQtEvents()

                self.assertIsNone(callbackReference())

                release.set()
                self.assertTrue(pool.waitForDone(3000))
                processQtEvents()
        finally:
            release.set()
            self.assertTrue(pool.waitForDone(3000))

            if isValid(manager):
                manager.deleteLater()
            pool.deleteLater()
            processQtEvents()

    def testHashCompletionCannotOutliveDownloadManager(self):
        """A queued hash must not start downloads after its Qt owner dies."""
        manager = XrayAssetSHA256DownloadManager()
        download = mock.Mock()
        pool = mock.Mock()

        with mock.patch(
            'Furious.Backends.Xray.AssetDownloadManager.AppThreadPool',
            return_value=pool,
        ):
            manager.successCallback(
                _Reply(hashlib.sha256(b'new asset').hexdigest().encode()),
                filepath='missing-asset.dat',
                downloadCallback=download,
            )

        worker = pool.start.call_args.args[0]

        manager.deleteLater()
        processQtEvents()

        worker.run()
        processQtEvents()
        manager.shutdown()

        download.assert_not_called()

    def testMalformedChecksumDoesNotStartHashOrAssetDownload(self):
        manager = XrayAssetSHA256DownloadManager()
        download = mock.Mock()

        with (
            mock.patch(
                'Furious.Backends.Xray.AssetDownloadManager.AppThreadPool'
            ) as threadPool,
            self.assertLogs(
                'Furious.Backends.Xray.AssetDownloadManager', level='ERROR'
            ) as logs,
        ):
            manager.successCallback(
                _Reply(b'not-a-sha256 asset.dat'),
                filepath='asset.dat',
                downloadCallback=download,
            )

        threadPool.assert_not_called()
        download.assert_not_called()
        self.assertIn('asset update skipped', '\n'.join(logs.output))
        manager.deleteLater()

    def testChangedLocalAssetForwardsNormalizedExpectedDigest(self):
        manager = XrayAssetSHA256DownloadManager()
        download = mock.Mock()
        expectedDigest = hashlib.sha256(b'new asset').hexdigest()
        pool = mock.Mock()
        pool.start.side_effect = lambda worker: worker.run()

        with (
            tempfile.NamedTemporaryFile() as existing,
            mock.patch(
                'Furious.Backends.Xray.AssetDownloadManager.AppThreadPool',
                return_value=pool,
            ),
        ):
            existing.write(b'old asset')
            existing.flush()
            manager.successCallback(
                _Reply(f'{expectedDigest.upper()}  asset.dat\n'.encode()),
                filepath=existing.name,
                downloadCallback=download,
            )

        processQtEvents()

        download.assert_called_once_with(expectedDigest)
        manager.deleteLater()

    def testMismatchedDownloadPreservesExistingAsset(self):
        manager = XrayAssetAssetsDownloadManager()
        expectedDigest = hashlib.sha256(b'expected asset').hexdigest()

        with tempfile.NamedTemporaryFile(delete=False) as existing:
            existing.write(b'known-good asset')
            filepath = existing.name

        self.addCleanup(os.unlink, filepath)

        with self.assertLogs(
            'Furious.Backends.Xray.AssetDownloadManager', level='ERROR'
        ) as logs:
            manager.successCallback(
                _Reply(b'corrupt download'),
                filepath=filepath,
                expectedDigest=expectedDigest,
            )

        with open(filepath, 'rb') as existing:
            self.assertEqual(existing.read(), b'known-good asset')

        self.assertIn('existing file preserved', '\n'.join(logs.output))
        manager.deleteLater()

    def testMatchingDownloadAtomicallyReplacesExistingAsset(self):
        manager = XrayAssetAssetsDownloadManager()
        downloaded = b'verified new asset'
        expectedDigest = hashlib.sha256(downloaded).hexdigest()

        with tempfile.NamedTemporaryFile(delete=False) as existing:
            existing.write(b'old asset')
            filepath = existing.name

        self.addCleanup(os.unlink, filepath)

        manager.successCallback(
            _Reply(downloaded),
            filepath=filepath,
            expectedDigest=expectedDigest,
        )

        with open(filepath, 'rb') as existing:
            self.assertEqual(existing.read(), downloaded)

        manager.deleteLater()


if __name__ == '__main__':
    unittest.main()
