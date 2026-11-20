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

"""Present the automatically detected host network used by TUN settings."""

from __future__ import annotations

from Furious.Frozenlib.SystemNetwork import getPrimaryAdapterInfo
from Furious.Qt import gettext as _
from Furious.Qt.QtWidgets import AppQGroupBox

from PySide6 import QtCore
from PySide6.QtWidgets import QGroupBox, QHBoxLayout, QLabel, QPushButton

__all__ = ['SystemNetworkInfoWidget']


class SystemNetworkInfoWidget(AppQGroupBox):
    """Show the host's active adapter, local IPv4 address, and gateway."""

    networkInfoChanged = QtCore.Signal(dict)

    def __init__(self, parent=None):
        """Create a compact, refreshable host-network summary."""
        self._titleKey = 'Detected System Network'
        self._refreshKey = 'Refresh'
        super().__init__(_(self._titleKey), parent)

        self.infoLabel = QLabel(self)
        self.infoLabel.setWordWrap(True)
        self.infoLabel.setTextInteractionFlags(
            QtCore.Qt.TextInteractionFlag.TextSelectableByMouse
        )

        self.refreshButton = QPushButton(_(self._refreshKey), self)
        self.refreshButton.clicked.connect(self.refresh)

        layout = QHBoxLayout(self)
        layout.addWidget(self.infoLabel, 1)
        layout.addWidget(self.refreshButton)

        self._info = {}
        self.refresh()

    def info(self) -> dict[str, str]:
        """Return a copy of the latest detected host-network information."""
        return dict(self._info)

    def retranslate(self):
        """Refresh all visible strings using their original translation keys."""
        self.setTitle(_(self._titleKey))
        self.refreshButton.setText(_(self._refreshKey))
        self._updateInfoLabel()

    def _updateInfoLabel(self):
        """Render the latest host-network information in the active language."""
        name = self._info.get('name') or _('Unknown')
        address = self._info.get('ip') or _('Not detected')
        gateway = self._info.get('gateway') or _('Not detected')

        self.infoLabel.setText(
            _(
                'Adapter: {name}    IPv4: {address}    Default gateway: {gateway}'
            ).format(
                name=name,
                address=address,
                gateway=gateway,
            )
        )

    @QtCore.Slot()
    def refresh(self):
        """Refresh host-network information and notify the owning dialog."""
        self._info = getPrimaryAdapterInfo()
        self._updateInfoLabel()
        self.networkInfoChanged.emit(self.info())
