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

"""Build and load Xray-specific routing rules and profiles."""

from __future__ import annotations

from Furious.Frozenlib import AppSettings, registerAppSettings
from Furious.Repository import *

import json
import logging

logger = logging.getLogger(__name__)

__all__ = [
    'cleanRoutingRule',
    'customRoutingObjectFromSettings',
    'getApplicationRoutingRules',
    'saveApplicationRoutingRules',
    'applicationRoutingRulesObject',
    'xrayCoreBypassRoutingRule',
]

registerAppSettings('XrayApplicationRoutingRules', default='[]')

_PROTECTED_APPLICATION_PROCESSES = {
    'furious.exe', 'furious', 'xray.exe', 'xray',
    'hysteria.exe', 'hysteria', 'hysteria2.exe', 'hysteria2',
    'tun2socks.exe', 'tun2socks',
}


def _isProtectedApplicationProcess(process: str) -> bool:
    basename = process.replace(chr(92), '/').rsplit('/', 1)[-1].casefold()
    return basename in _PROTECTED_APPLICATION_PROCESSES



def cleanRoutingRule(rule: dict):
    """Remove empty match fields from an Xray routing rule."""
    if not isinstance(rule, dict):
        return None

    result = {
        'type': 'field',
        'outboundTag': str(rule.get('outboundTag', 'proxy')).strip() or 'proxy',
    }

    for key in [
        'domain',
        'ip',
        'sourceIP',
        'localIP',
        'user',
        'protocol',
        'inboundTag',
        'process',
    ]:
        value = rule.get(key, [])

        if isinstance(value, list):
            value = list(str(item).strip() for item in value if str(item).strip())

            if value:
                result[key] = value

    for key in [
        'port',
        'sourcePort',
        'localPort',
        'network',
        'vlessRoute',
        'balancerTag',
        'ruleTag',
    ]:
        value = str(rule.get(key, '')).strip()

        if value:
            result[key] = value

    return result if len(result) > 2 else None


def customRoutingObjectFromSettings(routing: str):
    """Load a named custom Xray routing object from persistent settings."""
    prefix = 'Custom:'

    if not isinstance(routing, str) or not routing.startswith(prefix):
        return None

    routingProfile = Storage.UserRoutings().get(routing[len(prefix) :])

    if not isinstance(routingProfile, dict) or not routingProfile.get('enabled', True):
        return None

    domainStrategy = routingProfile.get('domainStrategy', 'AsIs')

    if domainStrategy not in ['AsIs', 'IPIfNonMatch', 'IPOnDemand']:
        domainStrategy = 'AsIs'

    rules = list(
        filter(
            lambda rule: rule is not None,
            list(cleanRoutingRule(rule) for rule in routingProfile.get('rules', [])),
        )
    )

    return {
        'domainStrategy': domainStrategy,
        'domainMatcher': 'hybrid',
        'rules': rules,
    }


def getApplicationRoutingRules():
    """Load validated, persistent per-application Xray routing rules."""
    try:
        raw = AppSettings.get('XrayApplicationRoutingRules') or '[]'
        data = json.loads(raw)
    except Exception:
        # Preserve a safe empty policy when stored data is malformed.
        logger.exception('failed to restore Xray application routing rules')
        return []

    if not isinstance(data, list):
        return []

    rules = []
    seen = set()

    for item in data:
        if not isinstance(item, dict) or not item.get('enabled', True):
            continue

        process = item.get('process', '')
        outbound = item.get('outboundTag', 'proxy')

        if not isinstance(process, str):
            continue

        process = process.strip().replace(chr(92), '/')
        if not process or _isProtectedApplicationProcess(process) or process.casefold() in seen:
            continue

        if outbound not in ('proxy', 'direct'):
            continue

        # Xray process matching accepts an executable name or an absolute path.
        # Reject glob-like values because Xray treats them as literal matches.
        if any(token in process for token in ('*', '?', chr(10), chr(13))):
            continue

        seen.add(process.casefold())
        try:
            priority = int(item.get('priority', 100))
        except (TypeError, ValueError):
            priority = 100

        rules.append({
            'id': str(item.get('id') or ''),
            'name': str(item.get('name') or process),
            'process': process,
            'outboundTag': outbound,
            'priority': priority,
            'enabled': True,
        })

    return sorted(rules, key=lambda item: (item['priority'], item['name'].casefold()))


def saveApplicationRoutingRules(rules):
    """Validate and persist ordered application-routing rules."""
    if not isinstance(rules, list):
        raise TypeError('application routing rules must be a list')

    normalized = []
    seen = set()

    for index, item in enumerate(rules):
        if not isinstance(item, dict):
            raise ValueError(f'application rule {index + 1} must be an object')

        process = item.get('process', '')
        if not isinstance(process, str):
            raise ValueError(f'application rule {index + 1} has an invalid process')

        process = process.strip().replace(chr(92), '/')
        if not process or _isProtectedApplicationProcess(process) or any(token in process for token in ('*', '?', chr(10), chr(13))):
            raise ValueError(f'application rule {index + 1} needs a valid EXE path or process name')

        key = process.casefold()
        if key in seen:
            raise ValueError(f'duplicate application rule: {process}')
        seen.add(key)

        outbound = item.get('outboundTag', 'proxy')
        if outbound not in ('proxy', 'direct'):
            raise ValueError(f'application rule {index + 1} must use proxy or direct')

        try:
            priority = int(item.get('priority', (index + 1) * 10))
        except (TypeError, ValueError):
            raise ValueError(f'application rule {index + 1} has an invalid priority')

        normalized.append({
            'id': str(item.get('id') or f'app-{index + 1}'),
            'name': str(item.get('name') or process),
            'process': process,
            'outboundTag': outbound,
            'priority': priority,
            'enabled': bool(item.get('enabled', True)),
        })

    AppSettings.set(
        'XrayApplicationRoutingRules',
        json.dumps(normalized, ensure_ascii=False, separators=(',', ':')),
    )
    return getApplicationRoutingRules()


def applicationRoutingRulesObject():
    """Build highest-priority Xray process rules from the saved application policy."""
    return [
        {
            'type': 'field',
            'process': [rule['process']],
            'outboundTag': rule['outboundTag'],
        }
        for rule in getApplicationRoutingRules()
    ]


def xrayCoreBypassRoutingRule():
    """Keep Xray's own outbound sockets outside the TUN proxy-routing loop."""
    return {
        'type': 'field',
        'process': ['self/'],
        'outboundTag': 'direct',
        'ruleTag': 'Furious-Xray-Core-Bypass',
    }
