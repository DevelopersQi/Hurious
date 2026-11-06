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

"""Provide the editor for Hysteria 2 native TUN settings."""

from __future__ import annotations

from Furious.Frozenlib import *
from Furious.Qt import *
from Furious.Qt.Signals import connectWeakly
from Furious.Qt import gettext as _
from Furious.Qt.SystemNetworkInfo import SystemNetworkInfoWidget

from PySide6 import QtCore
from PySide6.QtGui import *
from PySide6.QtWidgets import *

from .Plugin import *
from .TUN import *

import copy
import logging

__all__ = ['Hysteria2TunSettingsDialog']

logger = logging.getLogger(__name__)


def _singleColumnFormLayout(containers):
    """Lay out native TUN fields vertically with expandable input controls."""
    layout = QFormLayout()
    layout.setFormAlignment(QtCore.Qt.AlignmentFlag.AlignLeft)
    layout.setFieldGrowthPolicy(
        QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow
    )
    layout.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
    layout.setHorizontalSpacing(12)
    layout.setVerticalSpacing(10)

    for container in containers:
        widgets = container.widgets()
        if len(widgets) == 2:
            label, editor = widgets
            if isinstance(editor, QLineEdit):
                editor.setMinimumWidth(0)
                editor.setSizePolicy(
                    QSizePolicy.Policy.Expanding,
                    QSizePolicy.Policy.Fixed,
                )
            else:
                editor.setSizePolicy(
                    QSizePolicy.Policy.Fixed,
                    QSizePolicy.Policy.Fixed,
                )
            layout.addRow(label, editor)
        elif len(widgets) == 1:
            layout.addRow(widgets[0])

    return layout


def _nestedValue(config: dict, path: tuple[str, ...], default):
    """Return a nested settings value or *default*."""
    value = config

    for key in path:
        if not isinstance(value, dict):
            return default

        value = value.get(key, default)

    return value


def _setNestedValue(config: dict, path: tuple[str, ...], value):
    """Set one nested settings value."""
    target = config

    for key in path[:-1]:
        child = target.get(key)

        if not isinstance(child, dict):
            child = {}
            target[key] = child

        target = child

    target[path[-1]] = value


class GuiHysteria2TUNItemText(GuiEditorItemTextInput):
    """Edit one string-valued Hysteria 2 TUN setting."""

    def __init__(self, *args, **kwargs):
        """Initialize a Hysteria 2 TUN string editor."""
        self.path = tuple(kwargs.pop('path'))

        maximumWidth = kwargs.pop('maximumWidth', None)

        super().__init__(*args, **kwargs)

        if maximumWidth is not None:
            self._input.setMaximumWidth(maximumWidth)

    def inputToFactory(self, config: dict) -> bool:
        """Store the current text in a Hysteria 2 TUN settings mapping."""
        value = self.text().strip()

        if _nestedValue(config, self.path, '') == value:
            return False

        _setNestedValue(config, self.path, value)

        return True

    def factoryToInput(self, config: dict):
        """Load one Hysteria 2 TUN string setting into the editor."""
        value = _nestedValue(config, self.path, '')

        self.setText(value if isinstance(value, str) else '')


class GuiHysteria2TUNItemList(GuiHysteria2TUNItemText):
    """Edit one list-valued TUN setting as comma-separated text."""

    def inputToFactory(self, config: dict) -> bool:
        """Store comma-separated values in the settings mapping."""
        value = [item.strip() for item in self.text().split(',') if item.strip()]

        if _nestedValue(config, self.path, []) == value:
            return False

        _setNestedValue(config, self.path, value)

        return True

    def factoryToInput(self, config: dict):
        """Load one list setting into the editor."""
        value = _nestedValue(config, self.path, [])

        self.setText(','.join(value) if isinstance(value, list) else '')


class GuiHysteria2TUNItemMTU(GuiEditorItemTextSpinBox):
    """Edit the native TUN MTU."""

    def __init__(self, *args, **kwargs):
        """Initialize the MTU editor."""
        super().__init__(*args, **kwargs)

        self.setRange(1, 65535)

    def inputToFactory(self, config: dict) -> bool:
        """Store the MTU in the settings mapping."""
        value = self.value()

        if config.get('mtu', 1500) == value:
            return False

        config['mtu'] = value

        return True

    def factoryToInput(self, config: dict):
        """Load the MTU into the editor."""
        value = config.get('mtu', 1500)

        self.setValue(value if isinstance(value, int) else 1500)


class GuiHysteria2TUNSettingsGroupBoxInterface(GuiEditorWidgetQGroupBox):
    """Edit Hysteria 2 TUN interface settings."""

    def __init__(self, **kwargs):
        """Initialize the interface settings group."""
        self._titleKey = 'Interface'
        super().__init__(_(self._titleKey), **kwargs)

    def retranslate(self):
        """Refresh the group title using its untranslated source key."""
        self.setTitle(_(self._titleKey))

    def setupPageLayout(self):
        """Use the same responsive single-column layout for native TUN fields."""
        return _singleColumnFormLayout(self._containers)

    def containerSequence(self):
        """Return interface-setting editors in display order."""
        return [
            GuiHysteria2TUNItemText(
                title='Interface Name',
                path=('name',),
            ),
            GuiHysteria2TUNItemMTU(title='MTU'),
            GuiHysteria2TUNItemText(
                title='Timeout',
                path=('timeout',),
            ),
        ]


class GuiHysteria2TUNSettingsGroupBoxNetwork(GuiEditorWidgetQGroupBox):
    """Edit Hysteria 2 TUN addresses and routes."""

    def __init__(self, **kwargs):
        """Initialize the network settings group."""
        self._titleKey = 'Network'
        super().__init__(_(self._titleKey), **kwargs)

    def setupPageLayout(self):
        """Use the same responsive single-column layout as other TUN pages."""
        return _singleColumnFormLayout(self._containers)

    def containerSequence(self):
        """Return address and route editors in display order."""
        return [
            GuiHysteria2TUNItemText(
                title='IPv4 TUN Address',
                path=('address', 'ipv4'),
            ),
            GuiHysteria2TUNItemText(
                title='IPv6 TUN Address',
                path=('address', 'ipv6'),
            ),
            GuiHysteria2TUNItemList(
                title='IPv4 Routes',
                path=('route', 'ipv4'),
            ),
            GuiHysteria2TUNItemList(
                title='IPv6 Routes',
                path=('route', 'ipv6'),
            ),
            GuiHysteria2TUNItemList(
                title='IPv4 Excluded Routes',
                path=('route', 'ipv4Exclude'),
            ),
            GuiHysteria2TUNItemList(
                title='IPv6 Excluded Routes',
                path=('route', 'ipv6Exclude'),
            ),
        ]

class Hysteria2TUNDocumentationURL(AppQLabel):
    """Link to the official Hysteria 2 TUN documentation."""

    URL = 'https://hysteria.network/docs/advanced/Full-Client-Config/#tun'

    def __init__(self, *args, **kwargs):
        """Initialize the Hysteria 2 TUN documentation link."""
        super().__init__(*args, **kwargs)

        self.setWebsiteURL()

        connectWeakly(self.linkActivated, self, 'handleLinkActivated')

    def setWebsiteURL(self):
        """Set the translated documentation hyperlink text."""
        self.setText(f'<a href="{self.URL}">' + _('TUN Documentation') + '</a>')

    @staticmethod
    def handleLinkActivated(link: str):
        """Open the Hysteria 2 TUN documentation in the default browser."""
        if QDesktopServices.openUrl(QtCore.QUrl(link)):
            logger.info(f'open link {link!r} success')
        else:
            logger.error(f'open link {link!r} failed')

    def retranslate(self):
        """Refresh the translated documentation hyperlink text."""
        self.setWebsiteURL()


class Hysteria2TunSettingsDialog(GuiEditorWidgetQDialog):
    """Edit and persist Hysteria 2 native TUN settings."""

    def __init__(self, *args, **kwargs):
        """Initialize the Hysteria 2 TUN settings dialog."""
        self._isConnectionActive = kwargs.pop('isConnectionActive', lambda: False)
        kwargs.setdefault('style', 'portrait')
        kwargs.setdefault('tabTranslatable', True)

        super().__init__(*args, **kwargs)

        self.setTabText(_('Customize Hysteria2 TUN Settings'))
        self.setFixedSize(int(650 * GOLDEN_RATIO), 770)

        self._settings = getHysteria2TUNSettings()

        self.networkInfoWidget = SystemNetworkInfoWidget(self)
        self.layout().insertRow(0, self.networkInfoWidget)
        networkNote = QLabel(
            _(
                'Hysteria2 address.ipv4/ipv6 are virtual TUN addresses, not the physical adapter IP.'
            )
        )
        networkNote.setWordWrap(True)
        self.layout().insertRow(1, networkNote)

        self.factoryToInput(self._settings)

        connectWeakly(self.accepted, self, 'handleAccepted')

        self.layout().takeRow(self.layout().rowCount() - 1)

        bottomLayout = QHBoxLayout()
        bottomLayout.addWidget(Hysteria2TUNDocumentationURL())
        bottomLayout.addStretch(1)
        bottomLayout.addWidget(self.dialogBtns)

        self.layout().addRow(bottomLayout)

    def handleAccepted(self):
        """Persist changed settings and offer to reconnect when connected."""
        oldSettings = copy.deepcopy(self._settings)

        self.inputToFactory(self._settings)

        if self._settings == oldSettings:
            return

        saveHysteria2TUNSettings(self._settings)

        if SystemRuntime.isTUNMode() and self._isConnectionActive():
            showMBoxNewChangesNextTime()

    def createGroupBoxSequence(self):
        """Create Hysteria 2 TUN setting groups in display order."""
        return [
            GuiHysteria2TUNSettingsGroupBoxInterface(),
            GuiHysteria2TUNSettingsGroupBoxNetwork(),
        ]
