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

"""Prepare runtime configuration without coupling serialization to execution."""

from __future__ import annotations

from Furious.Interface import RuntimeExitReason, RuntimeStartError
from Furious.Models.Encoding import UJSONEncoder

import logging

__all__ = ['serializeRuntimeConfiguration']

logger = logging.getLogger(__name__)


def serializeRuntimeConfiguration(configuration, runtimeName: str, **kwargs) -> str:
    """Return validated JSON text or raise a structured preparation failure."""
    if isinstance(configuration, str):
        result = configuration
    else:
        serializer = getattr(configuration, 'toJSONString', None)

        try:
            result = (
                serializer(**kwargs)
                if callable(serializer)
                else UJSONEncoder.encode(configuration, **kwargs)
            )
        except Exception as ex:
            # Any non-exit exceptions

            logger.exception(f'failed to serialize configuration for {runtimeName}')

            raise RuntimeStartError(
                'Invalid server configuration',
                reason=RuntimeExitReason.InvalidConfiguration,
                details=str(ex),
            ) from ex

    if isinstance(result, str) and result:
        try:
            import ujson

            ujson.loads(result)
        except Exception as ex:
            # Any non-exit exceptions

            logger.error(
                f'configuration serializer for {runtimeName} returned invalid JSON'
            )

            raise RuntimeStartError(
                'Invalid server configuration',
                reason=RuntimeExitReason.InvalidConfiguration,
                details=str(ex),
            ) from ex

        return result

    diagnostic = ''
    serializationError = getattr(configuration, 'serializationError', None)

    if callable(serializationError):
        try:
            diagnostic = str(serializationError() or '')
        except Exception as ex:
            # Any non-exit exceptions

            # A diagnostic hook is still untrusted configuration behavior. Keep
            # its failure inside the same structured preparation boundary.
            logger.exception(
                f'failed to read serialization diagnostic for {runtimeName}'
            )

            diagnostic = str(ex)

    logger.error(
        f'configuration serializer for {runtimeName} returned no JSON'
        + (f': {diagnostic}' if diagnostic else '')
    )

    raise RuntimeStartError(
        'Invalid server configuration',
        reason=RuntimeExitReason.InvalidConfiguration,
        details=diagnostic,
    )
