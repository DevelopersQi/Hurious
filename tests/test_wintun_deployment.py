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

"""Verify checksum-protected Wintun runtime preparation."""

from unittest import TestCase, mock

import hashlib
import io
import tempfile
import zipfile

import Deploy


class WintunDeploymentTest(TestCase):
    """Exercise Wintun archive verification without network access."""

    def makeArchive(self):
        """Build a minimal in-memory archive matching the official layout."""
        buffer = io.BytesIO()

        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('wintun/bin/amd64/wintun.dll', b'MZ' + b'fake-pe')
            archive.writestr(
                'wintun/LICENSE.txt', b'Wintun binary redistribution license'
            )

        return buffer.getvalue()

    def testVerifiedOfficialLayoutExtractsArchitectureAndLicense(self):
        archiveData = self.makeArchive()
        digest = hashlib.sha256(archiveData).hexdigest()

        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.object(Deploy, 'PLATFORM', 'Windows'),
                mock.patch.object(Deploy, 'PLATFORM_MACHINE_LOWER', 'amd64'),
                mock.patch.object(Deploy, 'WINTUN_SHA256', digest),
                mock.patch.object(
                    Deploy,
                    'WINTUN_BUILD_ASSET_DIR',
                    Deploy.pathlib.Path(directory),
                ),
                mock.patch.object(
                    Deploy.urllib.request,
                    'urlopen',
                    return_value=io.BytesIO(archiveData),
                ),
            ):
                self.assertTrue(Deploy.downloadWintunAsset())

            self.assertEqual(
                (Deploy.pathlib.Path(directory) / 'amd64' / 'wintun.dll').read_bytes(),
                b'MZfake-pe',
            )
            self.assertEqual(
                (Deploy.pathlib.Path(directory) / 'LICENSE.txt').read_bytes(),
                b'Wintun binary redistribution license',
            )

    def testChecksumMismatchDoesNotExtractUntrustedFiles(self):
        archiveData = self.makeArchive()

        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.object(Deploy, 'PLATFORM', 'Windows'),
                mock.patch.object(Deploy, 'PLATFORM_MACHINE_LOWER', 'amd64'),
                mock.patch.object(Deploy, 'WINTUN_SHA256', '0' * 64),
                mock.patch.object(
                    Deploy,
                    'WINTUN_BUILD_ASSET_DIR',
                    Deploy.pathlib.Path(directory),
                ),
                mock.patch.object(
                    Deploy.urllib.request,
                    'urlopen',
                    return_value=io.BytesIO(archiveData),
                ),
            ):
                self.assertFalse(Deploy.downloadWintunAsset())

            self.assertEqual(list(Deploy.pathlib.Path(directory).iterdir()), [])


if __name__ == '__main__':
    import unittest

    unittest.main()
