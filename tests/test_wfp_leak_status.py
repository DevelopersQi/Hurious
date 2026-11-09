import unittest

from Furious.Service.WfpLeakStatus import (
    REQUIRED_LEAK_COVERAGE,
    WfpLeakEvent,
    WfpLeakSnapshot,
    WfpLeakState,
    assess_wfp_leak,
)


def _snapshot(**overrides):
    values = {
        "driver_healthy": True,
        "proxy_healthy": True,
        "telemetry_fresh": True,
        "coverage": REQUIRED_LEAK_COVERAGE,
    }
    values.update(overrides)
    return WfpLeakSnapshot(**values)


def _event():
    return WfpLeakEvent(
        timestamp=123.0,
        protocol="udp",
        address_family="ipv6",
        process_name="example.exe",
        process_id=4321,
        remote_address="2001:db8::1",
        remote_port=443,
        reason="flow bypassed proxy redirect",
    )


class WfpLeakStatusTests(unittest.TestCase):
    def test_protected_requires_fresh_complete_telemetry_and_healthy_components(self):
        result = assess_wfp_leak(_snapshot())

        self.assertIs(result.state, WfpLeakState.PROTECTED)
        self.assertTrue(result.is_protected)
        self.assertFalse(result.has_confirmed_leak)
        self.assertFalse(result.missing_coverage)

    def test_missing_udp_coverage_is_not_reported_as_protected(self):
        result = assess_wfp_leak(_snapshot(coverage=REQUIRED_LEAK_COVERAGE - {"udp"}))

        self.assertIs(result.state, WfpLeakState.COVERAGE_INCOMPLETE)
        self.assertEqual(result.missing_coverage, frozenset({"udp"}))
        self.assertFalse(result.is_protected)

    def test_stale_telemetry_is_not_reported_as_protected(self):
        result = assess_wfp_leak(_snapshot(telemetry_fresh=False))

        self.assertIs(result.state, WfpLeakState.TELEMETRY_STALE)
        self.assertFalse(result.is_protected)

    def test_unhealthy_driver_and_proxy_are_reported_separately(self):
        driver = assess_wfp_leak(_snapshot(driver_healthy=False))
        proxy = assess_wfp_leak(_snapshot(proxy_healthy=False))

        self.assertIs(driver.state, WfpLeakState.DRIVER_UNAVAILABLE)
        self.assertIs(proxy.state, WfpLeakState.PROXY_UNAVAILABLE)

    def test_confirmed_bypass_is_reported_as_exposed_without_active_kill_switch(self):
        result = assess_wfp_leak(_snapshot(bypass_events=(_event(),)))

        self.assertIs(result.state, WfpLeakState.LEAK_EXPOSED)
        self.assertTrue(result.has_confirmed_leak)
        self.assertEqual(result.bypass_events[0].process_name, "example.exe")

    def test_confirmed_bypass_is_reported_as_blocked_only_when_kill_switch_is_active(self):
        result = assess_wfp_leak(_snapshot(
            bypass_events=(_event(),),
            kill_switch_enabled=True,
            kill_switch_active=True,
        ))

        self.assertIs(result.state, WfpLeakState.LEAK_BLOCKED)
        self.assertTrue(result.has_confirmed_leak)

    def test_enabled_but_inactive_kill_switch_does_not_claim_leak_is_blocked(self):
        result = assess_wfp_leak(_snapshot(
            bypass_events=(_event(),),
            kill_switch_enabled=True,
            kill_switch_active=False,
        ))

        self.assertIs(result.state, WfpLeakState.LEAK_EXPOSED)

    def test_unknown_coverage_dimension_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsupported"):
            _snapshot(coverage=REQUIRED_LEAK_COVERAGE | {"icmp"})


if __name__ == "__main__":
    unittest.main()
