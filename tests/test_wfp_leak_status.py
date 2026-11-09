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


def test_protected_requires_fresh_complete_telemetry_and_healthy_components():
    result = assess_wfp_leak(_snapshot())

    assert result.state is WfpLeakState.PROTECTED
    assert result.is_protected
    assert not result.has_confirmed_leak
    assert not result.missing_coverage


def test_missing_udp_coverage_is_not_reported_as_protected():
    result = assess_wfp_leak(_snapshot(coverage=REQUIRED_LEAK_COVERAGE - {"udp"}))

    assert result.state is WfpLeakState.COVERAGE_INCOMPLETE
    assert result.missing_coverage == frozenset({"udp"})
    assert not result.is_protected


def test_stale_telemetry_is_not_reported_as_protected():
    result = assess_wfp_leak(_snapshot(telemetry_fresh=False))

    assert result.state is WfpLeakState.TELEMETRY_STALE
    assert not result.is_protected


def test_unhealthy_driver_and_proxy_are_reported_separately():
    driver = assess_wfp_leak(_snapshot(driver_healthy=False))
    proxy = assess_wfp_leak(_snapshot(proxy_healthy=False))

    assert driver.state is WfpLeakState.DRIVER_UNAVAILABLE
    assert proxy.state is WfpLeakState.PROXY_UNAVAILABLE


def test_confirmed_bypass_is_reported_as_exposed_without_active_kill_switch():
    result = assess_wfp_leak(_snapshot(bypass_events=(_event(),)))

    assert result.state is WfpLeakState.LEAK_EXPOSED
    assert result.has_confirmed_leak
    assert result.bypass_events[0].process_name == "example.exe"


def test_confirmed_bypass_is_reported_as_blocked_only_when_kill_switch_is_active():
    result = assess_wfp_leak(_snapshot(
        bypass_events=(_event(),),
        kill_switch_enabled=True,
        kill_switch_active=True,
    ))

    assert result.state is WfpLeakState.LEAK_BLOCKED
    assert result.has_confirmed_leak


def test_enabled_but_inactive_kill_switch_does_not_claim_leak_is_blocked():
    result = assess_wfp_leak(_snapshot(
        bypass_events=(_event(),),
        kill_switch_enabled=True,
        kill_switch_active=False,
    ))

    assert result.state is WfpLeakState.LEAK_EXPOSED


def test_unknown_coverage_dimension_is_rejected():
    try:
        _snapshot(coverage=REQUIRED_LEAK_COVERAGE | {"icmp"})
    except ValueError as error:
        assert "unsupported" in str(error)
    else:
        raise AssertionError("unknown coverage dimension must be rejected")
