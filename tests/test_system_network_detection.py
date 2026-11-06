"""Unit tests for platform-independent system network parsing."""

import unittest

from Furious.Frozenlib import SystemNetwork
from Furious.Qt.SystemNetworkInfo import SystemNetworkInfoWidget


class SystemNetworkParsingTests(unittest.TestCase):
    def test_shared_network_info_widget_is_importable(self):
        self.assertTrue(callable(SystemNetworkInfoWidget))

    def test_windows_default_route_uses_lowest_metric(self):
        output = """
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.20     35
          0.0.0.0          0.0.0.0      10.0.0.1       10.0.0.20        5
"""
        self.assertEqual(
            SystemNetwork._windowsDefaultRoute(output),
            ('10.0.0.1', '10.0.0.20'),
        )

    def test_windows_adapter_name_matches_interface_ip(self):
        output = """Windows IP Configuration

Ethernet adapter Ethernet:
   IPv4 Address. . . . . . . . . . . : 192.168.1.20(Preferred)

Wireless LAN adapter Wi-Fi:
   IPv4 Address. . . . . . . . . . . : 10.0.0.20(Preferred)
"""
        self.assertEqual(
            SystemNetwork._windowsAdapterName(output, '10.0.0.20'),
            'Wi-Fi',
        )

    def test_windows_adapter_name_supports_chinese_heading(self):
        output = """Windows IP 配置

以太网适配器 以太网:
   IPv4 地址. . . . . . . . . . . : 192.168.1.20(首选)
"""
        self.assertEqual(
            SystemNetwork._windowsAdapterName(output, '192.168.1.20'),
            '以太网',
        )

    def test_linux_default_route_and_interface(self):
        output = """default via 192.168.1.1 dev enp3s0 proto dhcp metric 100
default via 10.0.0.1 dev tun0 metric 500
"""
        self.assertEqual(
            SystemNetwork._linuxDefaultRoute(output),
            ('192.168.1.1', 'enp3s0'),
        )

    def test_linux_interface_address(self):
        output = "2: enp3s0 inet 192.168.1.20/24 brd 192.168.1.255 scope global dynamic"
        self.assertEqual(SystemNetwork._linuxInterfaceIP(output), '192.168.1.20')

    def test_macos_default_route_and_interface(self):
        output = """   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
"""
        self.assertEqual(
            SystemNetwork._macDefaultRoute(output),
            ('192.168.1.1', 'en0'),
        )

    def test_macos_interface_address(self):
        output = """en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST>
    inet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255
"""
        self.assertEqual(SystemNetwork._macInterfaceIP(output), '192.168.1.20')

    def test_invalid_or_non_routable_ipv4_is_rejected(self):
        for address in ('0.0.0.0', '127.0.0.1', '169.254.1.1', '224.0.0.1'):
            self.assertFalse(SystemNetwork._validIPv4(address))

        self.assertTrue(SystemNetwork._validIPv4('192.168.1.20'))


if __name__ == '__main__':
    unittest.main()
