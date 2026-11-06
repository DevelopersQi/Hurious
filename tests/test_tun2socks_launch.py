from __future__ import annotations

import unittest
from unittest import mock

from Furious.Core.Tun2socks import startTun2socks


class Tun2socksLaunchArgumentsTest(unittest.TestCase):
    """Keep the call compatible with the pinned five-argument Python binding."""

    def test_optional_host_buffer_settings_are_not_forwarded_to_binding(self):
        queue = mock.Mock()
        binding = mock.Mock(__version__='2.5.2.3')

        with (
            mock.patch.dict('sys.modules', {'tun2socks': binding}),
            mock.patch(
                'Furious.Core.Tun2socks.ProcessOutputRedirector.launch',
                side_effect=lambda _queue, entrypoint, _redirect: entrypoint(),
            ),
        ):
            startTun2socks(
                queue,
                'Furious',
                '',
                'error',
                'socks5://127.0.0.1:1080',
                '',
                '1MB',
                '1MB',
                False,
            )

        binding.startFromArgs.assert_called_once_with(
            'Furious',
            '',
            'error',
            'socks5://127.0.0.1:1080',
            '',
        )


if __name__ == '__main__':
    unittest.main()
