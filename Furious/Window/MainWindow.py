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

"""Provide the page-based application main window."""

from __future__ import annotations

from Furious.Frozenlib import *
from Furious.Models import CoreConfiguration, ServerProfile
from Furious.Qt import *
from Furious.Qt import gettext as _
from Furious.Service import MetricsHistory, PluginNavigationManager, isCoreActive
from Furious.Widget.NavigationView import NavigationView
from Furious.Window.HomePage import HomePage
from Furious.Window.LogPage import LogPage
from Furious.Window.MetricsPage import MetricsPage
from Furious.Window.SettingsPage import SettingsPage
from Furious.Window.SubscriptionPage import SubscriptionPage

from PySide6 import QtCore

from typing import Union

import logging

__all__ = ['MainWindow']

logger = logging.getLogger(__name__)


def _xrayTunSettingsDialogFactory(**kwargs):
    """Create the Xray native-TUN editor without importing its UI at startup."""
    from Furious.Backends.Xray.Process import XrayCore
    from Furious.Backends.Xray.TunSettingsDialog import XrayTunSettingsDialog

    return XrayTunSettingsDialog(
        isConnectionActive=lambda: isCoreActive(XrayCore),
        **kwargs,
    )


def _hysteria2TunSettingsDialogFactory(**kwargs):
    """Create the Hysteria 2 native-TUN editor on demand."""
    from Furious.Backends.Hysteria2.Process import Hysteria2
    from Furious.Backends.Hysteria2.TunSettingsDialog import Hysteria2TunSettingsDialog

    return Hysteria2TunSettingsDialog(
        isConnectionActive=lambda: isCoreActive(Hysteria2),
        **kwargs,
    )


# Migrate legacy settings.
registerAppSettings('ServerWidgetWindowSize')
registerAppSettings('AppMainWindowGeometry')
registerAppSettings('AppMainWindowState')

_TRANSLATABLE_NAVIGATION_LABELS = (
    _('Home'),
    _('Log'),
    _('Subscription'),
    _('Metrics'),
    _('Settings'),
)


class MainWindow(AppQMainWindow):
    """Manage application pages, navigation, and global window state."""

    DEFAULT_WINDOW_SIZE_DARWIN = QtCore.QSize(1500, 780)
    DEFAULT_WINDOW_SIZE = (
        QtCore.QSize(1800, 960) if PLATFORM != 'Darwin' else DEFAULT_WINDOW_SIZE_DARWIN
    )

    QT_FALLBACK_WINDOW_SIZE = QtCore.QSize(640, 480)

    def __init__(self, *args, **kwargs):
        """Create and register the built-in application pages."""
        super().__init__(*args, **kwargs)

        self.setFocusPolicy(QtCore.Qt.FocusPolicy.StrongFocus)
        self.menuBar().hide()

        self.navigationView = NavigationView(parent=self)
        self.homePage = HomePage(parent=self.navigationView)
        self.subscriptionPage = SubscriptionPage(
            self.homePage.userServersQTableWidget,
            parent=self.navigationView,
        )
        self.metricsHistory = MetricsHistory(parent=self)
        self.homePage.trafficStatsManager.sampleChanged.connect(
            self.metricsHistory.recordTrafficSample
        )
        self.homePage.trafficStatsManager.usageHistoryReset.connect(
            self.metricsHistory.clearTrafficUsageHistory
        )
        self.metricsPage = MetricsPage(
            self.metricsHistory,
            parent=self.navigationView,
        )
        self.logPage = AppLogPage()
        self._routingEditor = None
        self._applicationRoutingDialog = None
        self.settingsPage = SettingsPage(
            tunSettingsDialogFactory=self.homePage.getGuiTUNSettings,
            xrayTunSettingsDialogFactory=_xrayTunSettingsDialogFactory,
            hysteria2TunSettingsDialogFactory=_hysteria2TunSettingsDialogFactory,
            proxyBypassDialog=self.homePage.customizeProxyBypassDialog,
            networkTestDialog=self.homePage.customizeNetworkTestDialog,
            checkForUpdates=self.homePage.checkForUpdates,
            openAboutPage=self.homePage.openAboutPage,
            restartAsAdmin=self.homePage.restartAsAdmin,
            openApplicationFolder=self.homePage.openApplicationFolder,
            openRoutingEditor=self.openRoutingEditor,
            openApplicationRoutingEditor=(
                self.openApplicationRoutingEditor if PLATFORM == 'Windows' else None
            ),
            parent=self.navigationView,
        )

        AppConnectionController().interactionEnabledChanged.connect(
            self.settingsPage.setConnectionControlsEnabled
        )

        AppConnectionController().errorOccurred.connect(
            self._handleConnectionError
        )

        self.settingsPage.setConnectionControlsEnabled(
            AppConnectionController().interactionEnabled
        )

        if not isinstance(self.logPage, LogPage):
            raise TypeError('application log page must be a LogPage')

        # NavigationView selects the first registered page.  Keep Home first
        # so every new window session starts from the canonical product page.
        self.navigationView.addPage(
            'home',
            self.homePage,
            'Home',
            'house-door.svg',
        )
        self.navigationView.addPage(
            'log',
            self.logPage,
            'Log',
            'journal-text.svg',
        )
        self.navigationView.addPage(
            'subscription',
            self.subscriptionPage,
            'Subscription',
            'star.svg',
        )
        self.pluginNavigationManager = PluginNavigationManager()
        self.pluginNavigationManager.registerPages(self.navigationView)
        self.navigationView.addPage(
            'metrics',
            self.metricsPage,
            'Metrics',
            'speedometer2.svg',
        )
        self.navigationView.addPage(
            'settings',
            self.settingsPage,
            'Settings',
            'gear-wide-connected.svg',
            placement='bottom',
        )
        self.setCentralWidget(self.navigationView)

        # Preserve the established application-facing server-management API.
        self.userServersQTableWidget = self.homePage.userServersQTableWidget
        self.userSubsWindow = self.subscriptionPage
        self.networkConnectivityManager = self.homePage.networkConnectivityManager
        self.networkState = self.homePage.networkState
        self.trafficStats = self.homePage.trafficStats
        self.trafficStatsManager = self.homePage.trafficStatsManager

        self.retranslate()

    def openRoutingEditor(self):
        """Open the reusable Xray custom-routing profile editor."""
        if self._routingEditor is None:
            # Import only when requested so startup does not eagerly load the
            # advanced Xray editor for users who never configure custom routes.
            from Furious.Backends.Xray.RoutingWindow import XrayRoutingWindow

            self._routingEditor = XrayRoutingWindow(parent=self)

        if self._routingEditor.isMinimized():
            self._routingEditor.showNormal()
        else:
            self._routingEditor.show()

        self._routingEditor.raise_()
        self._routingEditor.activateWindow()

    def openApplicationRoutingEditor(self):
        """Open the transient Windows per-application routing editor."""
        if PLATFORM != 'Windows':
            return

        if self._applicationRoutingDialog is not None:
            self._applicationRoutingDialog.raise_()
            self._applicationRoutingDialog.activateWindow()
            return

        from Furious.Backends.Xray.RoutingWindow import ApplicationRoutingDialog

        dialog = ApplicationRoutingDialog(parent=self)
        self._applicationRoutingDialog = dialog
        dialog.finished.connect(self._applicationRoutingDialogFinished)
        dialog.open()

    @QtCore.Slot(int)
    def _applicationRoutingDialogFinished(self, _result):
        """Release the transient application editor after it has closed."""
        self._applicationRoutingDialog = None

    @QtCore.Slot(object)
    def _handleConnectionError(self, error):
        """Offer direct navigation when the selected TUN backend is incompatible."""
        message = str(getattr(error, 'message', '') or error or '')
        isBackendMismatch = (
            ('不能选择' in message and '原生 TUN' in message)
            or 'Native TUN is not supported' in message
        )
        if not isBackendMismatch:
            return

        # Use the application's exported message-box wrapper.  QMessageBox is
        # intentionally not exported by Furious.Qt, while AppQMessageBox is
        # theme-aware, translated, and owns its transient Qt lifetime.
        try:
            isChinese = str(AppSettings.get('Language') or '').upper() == 'ZH'

            dialog = AppQMessageBox(parent=self)
            dialog.setIcon(AppQMessageBox.Icon.Warning)
            dialog.setWindowTitle(
                'TUN 后端不兼容' if isChinese else _('TUN backend mismatch')
            )
            dialog.setText(message)
            # The error message already explains the supported choices. Do
            # not repeat the same instruction in a second explanatory label.
            dialog.setStandardButtons(
                AppQMessageBox.StandardButton.Yes | AppQMessageBox.StandardButton.No
            )
            yesButton = dialog.button(AppQMessageBox.StandardButton.Yes)
            noButton = dialog.button(AppQMessageBox.StandardButton.No)
            if yesButton is not None:
                yesButton.setText('前往设置' if isChinese else _('Go to Settings'))
            if noButton is not None:
                noButton.setText('取消' if isChinese else _('Cancel'))

            if dialog.exec() == AppQMessageBox.StandardButton.Yes:
                self.showSettingsPage()
        except Exception:
            # A presentation failure must never replace the original
            # connection error with a second exception from the GUI handler.
            logger.exception(
                'failed to display TUN backend mismatch dialog; original error: %s',
                message,
            )

    def showPage(self, pageId: str):
        """Navigate to a registered application page."""
        self.navigationView.setCurrentPage(pageId)

    def showLogPage(self):
        """Navigate directly to the unified logging page."""
        self.showPage('log')

    def showSettingsPage(self):
        """Navigate directly to application settings."""
        self.show()
        self.showPage('settings')

    def showSubscriptionPage(self):
        """Navigate directly to subscription management."""
        self.show()
        self.showPage('subscription')

    def updateSubsByUnique(self, unique: str, httpProxy: Union[str, None], **kwargs):
        """Forward a subscription update to the dedicated page controller."""
        self.subscriptionPage.updateSubsByUnique(unique, httpProxy, **kwargs)

    def appendNewItemByFactory(self, factory: CoreConfiguration | ServerProfile):
        """Forward a new server profile to the home page."""
        self.homePage.appendNewItemByFactory(factory)

    def appendNewItemsByFactories(self, factories):
        """Forward a batch of prepared profiles to the server table."""
        self.homePage.appendNewItemsByFactories(factories)

    def flushRow(self, row: int, item: ServerProfile):
        """Forward a server-row refresh to the home page."""
        self.homePage.flushRow(row, item)

    def showTabAndSpaces(self):
        """Enable whitespace markers in home-page editors."""
        self.homePage.showTabAndSpaces()

    def hideTabAndSpaces(self):
        """Disable whitespace markers in home-page editors."""
        self.homePage.hideTabAndSpaces()

    def getGuiTUNSettings(self, **kwargs):
        """Return the home page's TUN settings editor."""
        return self.homePage.getGuiTUNSettings(**kwargs)

    def checkForUpdates(self, **kwargs):
        """Forward update checks to the home page."""
        self.homePage.checkForUpdates(**kwargs)

    def resetNetworkState(self):
        """Clear the home page network state."""
        self.homePage.resetNetworkState()

    def setNetworkState(self, success: bool, **kwargs):
        """Update the home page network state."""
        self.homePage.setNetworkState(success, **kwargs)

    def prepareInitialGeometry(self):
        """Restore persisted geometry after composition and before first show."""
        savedGeometry = AppSettings.get('AppMainWindowGeometry')

        if savedGeometry is None:
            if not self._restoreLegacyWindowSize():
                self._applyDefaultWindowSize('no saved main-window geometry')
        else:
            try:
                restored = self.restoreInitialGeometry(savedGeometry)
            except Exception:
                # Any non-exit exceptions

                logger.exception('unexpected main-window geometry restore failure')

                restored = False

            if restored and self.size() == self.QT_FALLBACK_WINDOW_SIZE:
                self._applyDefaultWindowSize(
                    'saved main-window geometry restored to the Qt fallback size'
                )
            elif restored:
                logger.info(
                    f'restored main-window geometry: {self.geometry().getRect()}'
                )
            else:
                self._applyDefaultWindowSize('saved main-window geometry was invalid')

        self._restoreMainWindowState()

    def _applyDefaultWindowSize(self, reason: str):
        """Apply the canonical first-launch/recovery size and center it."""
        self.resize(self.DEFAULT_WINDOW_SIZE)

        logger.info(
            f'{reason}; using default main-window size '
            f'{self.DEFAULT_WINDOW_SIZE.toTuple()}'
        )

    def _restoreLegacyWindowSize(self) -> bool:
        """Restore one valid legacy client size without guessing its origin."""
        legacySize = AppSettings.get('ServerWidgetWindowSize')

        if legacySize is None:
            return False

        try:
            widthText, heightText = legacySize.split(',')
            width, height = int(widthText), int(heightText)

            if width <= 0 or height <= 0:
                raise ValueError('window dimensions must be positive')
        except (AttributeError, TypeError, ValueError):
            logger.warning(f'ignored invalid legacy main-window size: {legacySize!r}')

            return False

        self.resize(width, height)

        logger.info(f'migrated legacy main-window size: {(width, height)}')

        return True

    def _restoreMainWindowState(self):
        """Restore QMainWindow layout state independently from its geometry."""
        savedState = AppSettings.get('AppMainWindowState')

        if savedState is None:
            return

        try:
            restored = self.restoreState(savedState)
        except Exception:
            # Any non-exit exceptions

            logger.exception('unexpected main-window state restore failure')

            return

        if not restored:
            logger.warning('saved main-window state was invalid and was ignored')

    def showEvent(self, event):
        """Focus the window itself instead of an untouched child control."""
        super().showEvent(event)

        self.setFocus(QtCore.Qt.FocusReason.OtherFocusReason)

    def retranslate(self):
        """Refresh the application window title."""
        if SystemRuntime.isAdmin():
            self.setWindowTitle(f'{_(APPLICATION_NAME)} ({_(ADMINISTRATOR_NAME)})')
        else:
            self.setWindowTitle(_(APPLICATION_NAME))

    def cleanup(self):
        """Persist application-level and routing-editor window state."""
        if self._routingEditor is not None:
            self._routingEditor.cleanup()
        # Tray startup can construct MainWindow without ever presenting it. In
        # that case saveGeometry() describes Qt's native pre-show placeholder,
        # not a user decision, so preserve the last persisted window state.
        if not self.hasPreparedInitialGeometry():
            return

        AppSettings.set('AppMainWindowGeometry', self.saveGeometry())
        AppSettings.set('AppMainWindowState', self.saveState())
