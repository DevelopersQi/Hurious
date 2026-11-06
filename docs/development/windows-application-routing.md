# Windows application-level routing design

## Scope

This document records the implementation boundary for Windows 10 x64 application routing in Furious.

The first supported backend is **Xray-core Native TUN**. Hysteria2 Native TUN and Tun2socks must remain unavailable in the application-routing UI until the WFP data path, driver installation, recovery, and traffic tests are complete.

## Phase 1: Xray Native TUN

Xray's routing `process` matcher supports Windows process names and normalized absolute executable paths. Rules are evaluated top-to-bottom; the first matching rule selects its outbound. Process matching is case-sensitive. Name matching ignores the `.exe` suffix; absolute paths do not.

Furious stores application rules in `XrayApplicationRoutingRules` and emits them only when all of the following are true:

- The platform is Windows.
- TUN mode is enabled.
- The active Xray configuration contains a Xray TUN inbound.

The emitted order is:

1. `self/` -> `direct`, to keep Xray's own sockets out of its intercepted traffic path.
2. User application rules in saved priority order.
3. Existing domain/IP/protocol routing rules.

The editor supports running process names and manually selected EXE paths, force-proxy/force-direct actions, enable/disable, removal, and priority changes. Core process names are rejected both in the UI and in persistence validation.

This is a configuration-level guarantee only. It does not prove that the active Xray binary has the expected process finder behavior, that every Windows networking API is covered, or that DNS and IPv6 are leak-free. Those require Windows 10 x64 integration tests with packet capture.

## Phase 2: WFP classification and redirect service

### Components

- **WFP management service (user mode):** installs/removes a named provider, sublayer, filters, and callouts; owns policy IPC; monitors BFE and driver health.
- **WFP callout driver (kernel mode):** classifies ALE authorization events and tracks flow identity. It must not perform slow I/O or wait for the user-mode service inside classify callbacks.
- **Local transparent relay (user mode):** receives redirected TCP/UDP flows, retains original destination metadata, and forwards through the selected backend.
- **Backend adapters:** translate relay sessions to the active Hysteria2 or Tun2socks-compatible local ingress. A backend is eligible only after its TCP and UDP semantics are proven.
- **Policy store:** one versioned rule schema shared with Xray, including stable rule IDs, executable identity, action, enabled state, priority, and policy version.

### WFP layers

- `ALE_AUTH_CONNECT_V4/V6`: classify outbound TCP connect and first outbound UDP flow using application identity.
- `ALE_AUTH_RECV_ACCEPT_V4/V6`: classify inbound accepts and first inbound UDP flow where required.
- `ALE_FLOW_ESTABLISHED_V4/V6`: associate connection state; do not use this layer to authorize/block an established flow.
- `ALE_CONNECT_REDIRECT_V4/V6`: redirect eligible TCP/UDP connection requests to the local relay where the chosen transport supports it.
- Transport/datagram or network layers: only add callouts if packet-level handling is required and the ALE metadata/redirect model cannot meet the forwarding contract.

The callout must use the WFP redirect tracking APIs and detect self-redirection / previous redirection. Relay-originated sockets and the proxy-core executable must be excluded from reclassification. Filter weights and provider/sublayer ownership must be explicit to coexist with Windows Firewall and other WFP providers.

### Rule decision

1. Identify the originating application using WFP's application ID, not a transient PID alone.
2. Normalize and compare executable identity; account for path replacement and process restart.
3. Apply explicit application rules by priority.
4. If no app rule matches, continue to the backend's existing destination/domain policy.
5. For force-direct, bypass the proxy relay and use the original destination.
6. For force-proxy, redirect to the local relay and preserve the original destination.
7. If classification or relay setup fails, apply an explicit configured failure policy. The initial secure default should be fail-closed for flows that the user explicitly marked force-proxy; never silently downgrade them to direct.

### DNS and protocol requirements

- Cover IPv4 and IPv6 independently at ALE and redirect layers.
- Cover TCP and UDP, including UDP DNS and TCP DNS fallback.
- Preserve the original destination and support DNS response correlation.
- Prevent DNS requests from bypassing the selected application policy. Document the limitation that Windows DNS Client service may issue resolver traffic under a service process identity rather than the requesting application's identity.
- Treat DoT, DoH, and QUIC as application traffic, not as classic port-53 DNS.
- Exclude relay and core sockets, including IPv4-mapped IPv6 and loopback paths, from interception.
- Handle fragmented packets, ICMP errors, MTU, connection teardown, suspend/resume, network changes, and IPv6 link-local traffic.

## Test and release gates

No Hysteria2/Tun2socks application-routing switch may be shown until all gates pass on clean Windows 10 x64 VMs:

1. Driver signing, install, upgrade, rollback, uninstall, and reboot recovery.
2. WFP provider/filter cleanup after forced termination and service crash.
3. Per-process TCP and UDP force-proxy/force-direct tests.
4. IPv4 and IPv6 parity tests.
5. DNS UDP/TCP, DoT, DoH, and QUIC behavior tests.
6. Packet capture on physical and TUN interfaces proving no unintended direct egress for force-proxy rules.
7. Core and relay loop tests, including multiple proxy providers and redirect-state tracking.
8. Windows Firewall coexistence and third-party VPN coexistence.
9. Performance, high connection churn, memory pressure, and long-duration stability.

A successful Python unit test or Xray JSON validation is not a substitute for these tests.

## References

- Microsoft: Windows Filtering Platform overview — https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform
- Microsoft: Application Layer Enforcement — https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-
- Microsoft: ALE layers — https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers
- Microsoft: Proxied connections tracking — https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- Xray: Routing — https://xtls.github.io/en/config/routing
