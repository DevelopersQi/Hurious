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

"""Verify runtime configuration is valid JSON before a child process starts."""

from Furious.Interface import RuntimeExitReason, RuntimeStartError
from Furious.Plugins.Runtime import serializeRuntimeConfiguration

from unittest import TestCase


class RuntimeConfigurationSerializationTest(TestCase):
    """Reject malformed serialized configuration at the host boundary."""

    def testValidJsonTextIsPreservedExactly(self):
        """Do not rewrite valid user configuration while validating it."""
        configuration = '{ "server": "example.com", "auth": "secret" }'

        self.assertEqual(
            serializeRuntimeConfiguration(configuration, 'Hysteria2'),
            configuration,
        )

    def testMalformedJsonTextRaisesStructuredConfigurationError(self):
        """Report malformed raw JSON before launching the core process."""
        with self.assertRaises(RuntimeStartError) as raised:
            serializeRuntimeConfiguration(
                '{"server": "example.com",',
                'Hysteria2',
            )

        self.assertIs(
            raised.exception.reason,
            RuntimeExitReason.InvalidConfiguration,
        )
        self.assertIn('JSON', raised.exception.details.upper())

    def testMalformedSerializerOutputRaisesStructuredConfigurationError(self):
        """Validate plugin-produced JSON just like raw configuration text."""

        class BrokenConfiguration:
            @staticmethod
            def toJSONString(**kwargs):
                return '{"server": '

        with self.assertRaises(RuntimeStartError) as raised:
            serializeRuntimeConfiguration(BrokenConfiguration(), 'Hysteria2')

        self.assertIs(
            raised.exception.reason,
            RuntimeExitReason.InvalidConfiguration,
        )
        self.assertTrue(raised.exception.details)
