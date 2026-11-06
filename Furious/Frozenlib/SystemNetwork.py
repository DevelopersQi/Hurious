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

"""Detect the active physical network adapter and its default route."""

from __future__ import annotations

from Furious.Frozenlib.Constants import *
from Furious.Frozenlib.Utility import runExternalCommand

import ipaddress
import logging
import re
import subprocess

__all__ = ['getPrimaryAdapterInfo']

logger = logging.getLogger(__name__)

_IPV4_PATTERN = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')


def _run(command: list[str]) -> str:
    """Run one bounded, read-only system network query."""
    try:
        result = runExternalCommand(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=4,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as ex:
        logger.debug('system network detection command failed: %s', ex)
        return ''

    encoding = 'mbcs' if PLATFORM == 'Windows' else 'utf-8'

    return result.stdout.decode(encoding, 'replace')


def _validIPv4(value: str) -> bool:
    """Return whether a value is a usable unicast IPv4 address."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False

    return (
        address.version == 4
        and not address.is_unspecified
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
    )


def _windowsDefaultRoute(output: str) -> tuple[str, str]:
    """Return the lowest-metric IPv4 default gateway and source interface IP."""
    routes = []

    for line in output.splitlines():
        fields = line.split()

        if len(fields) < 5 or fields[0:2] != ['0.0.0.0', '0.0.0.0']:
            continue

        gateway, interfaceIP = fields[2:4]

        try:
            metric = int(fields[4])
        except ValueError:
            metric = 2**31 - 1

        if _validIPv4(gateway) and _validIPv4(interfaceIP):
            routes.append((metric, gateway, interfaceIP))

    if not routes:
        return '', ''

    _metric, gateway, interfaceIP = min(routes)

    return gateway, interfaceIP


def _windowsAdapterName(output: str, interfaceIP: str) -> str:
    """Match an ipconfig adapter heading to the selected route source IP."""
    currentName = ''

    for line in output.splitlines():
        stripped = line.strip()

        if stripped and not line[:1].isspace() and ':' in stripped:
            heading = stripped.split(':', 1)[0]
            match = re.search(r'(?:adapter|适配器)\s*(.*?)\s*$', heading, re.I)

            if match:
                currentName = match.group(1).strip()

        if interfaceIP in _IPV4_PATTERN.findall(line):
            return currentName

    return ''


def _linuxDefaultRoute(output: str) -> tuple[str, str]:
    """Return the preferred Linux default gateway and interface."""
    routes = []

    for line in output.splitlines():
        fields = line.split()

        if not fields or fields[0] != 'default':
            continue

        gateway = ''
        interface = ''
        metric = 0

        for index, field in enumerate(fields[:-1]):
            if field == 'via':
                gateway = fields[index + 1]
            elif field == 'dev':
                interface = fields[index + 1]
            elif field == 'metric':
                try:
                    metric = int(fields[index + 1])
                except ValueError:
                    pass

        if interface and (not gateway or _validIPv4(gateway)):
            routes.append((metric, gateway, interface))

    if not routes:
        return '', ''

    _metric, gateway, interface = min(routes)

    return gateway, interface


def _linuxInterfaceIP(output: str) -> str:
    """Return the first global IPv4 address in ip -o output."""
    for line in output.splitlines():
        match = re.search(r'\binet\s+(\d{1,3}(?:\.\d{1,3}){3})/', line)

        if match and _validIPv4(match.group(1)):
            return match.group(1)

    return ''


def _macDefaultRoute(output: str) -> tuple[str, str]:
    """Return the macOS default gateway and interface."""
    gateway = re.search(r'^\s*gateway:\s*(\S+)', output, re.M)
    interface = re.search(r'^\s*interface:\s*(\S+)', output, re.M)

    return (
        gateway.group(1) if gateway else '',
        interface.group(1) if interface else '',
    )


def _macInterfaceIP(output: str) -> str:
    """Return the first non-loopback IPv4 address from ifconfig output."""
    for line in output.splitlines():
        match = re.search(r'\binet\s+(\d{1,3}(?:\.\d{1,3}){3})\b', line)

        if match and _validIPv4(match.group(1)):
            return match.group(1)

    return ''


def getPrimaryAdapterInfo() -> dict[str, str]:
    """Detect the active primary adapter, local IPv4 address, and gateway.

    The returned values describe the host's physical/default-route interface,
    not the virtual address assigned to a proxy TUN device. Empty values mean
    detection was unavailable and should not prevent the application starting.
    """
    result = {'name': '', 'ip': '', 'gateway': ''}

    try:
        if PLATFORM == 'Windows':
            routeOutput = _run(['route', 'print', '-4'])
            gateway, interfaceIP = _windowsDefaultRoute(routeOutput)

            if not gateway or not interfaceIP:
                return result

            result['gateway'] = gateway
            result['ip'] = interfaceIP
            result['name'] = _windowsAdapterName(
                _run(['ipconfig', '/all']),
                interfaceIP,
            )

        elif PLATFORM == 'Linux':
            gateway, interface = _linuxDefaultRoute(
                _run(['ip', '-4', 'route', 'show', 'default'])
            )

            if not interface:
                return result

            result['gateway'] = gateway
            result['name'] = interface
            result['ip'] = _linuxInterfaceIP(
                _run(['ip', '-o', '-4', 'addr', 'show', 'dev', interface, 'scope', 'global'])
            )

        elif PLATFORM == 'Darwin':
            gateway, interface = _macDefaultRoute(_run(['route', '-n', 'get', 'default']))

            if not interface:
                return result

            result['gateway'] = gateway
            result['name'] = interface
            result['ip'] = _macInterfaceIP(_run(['ifconfig', interface]))

    except Exception:
        # Network detection is best-effort and must never block TUN settings.
        logger.exception('failed to detect the primary network adapter')

    return result
