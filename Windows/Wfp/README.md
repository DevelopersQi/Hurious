# Furious Windows Filtering Platform (WFP)

This directory contains the Windows-only WFP implementation. It is intentionally
separate from the Python UI and proxy-core process lifecycle.

## Components

- `service/`: elevated user-mode service. Owns provider/sublayer/filter lifecycle,
  SCM driver startup, authenticated IPC and policy validation.
- `driver/`: WDK kernel callout driver. Performs bounded, non-blocking classification
  only; it must never perform file, registry, network or user-mode IPC in classify callbacks.
- `include/`: stable policy and control-plane ABI shared by the service and driver.
- `broker/`: native TCP redirect metadata, SOCKS5 CONNECT and bidirectional relay primitives.
- `tests/`: Windows integration tests and packet-capture test plans.

## Safety gates

The service now starts the adjacent callout driver through SCM, verifies the
driver ABI/callout registration, and transactionally installs IPv4/IPv6 ALE
connect-redirect filters. The driver redirects only applications with an installed Proxy policy filter
and a valid endpoint. Direct rules remain direct. Proxy filters fail closed if
the endpoint is missing or a redirect operation fails. The service hosts a native TCP broker and exposes it through authenticated IPC.
The broker can obtain original-destination context, preserve WFP redirect records,
connect to a loopback SOCKS5 inbound, and relay TCP streams. The Python lifecycle
starts/stops the broker, but does not yet publish the broker PID/ports and current
core exclusions as a complete SET_ENDPOINT_CONFIG transaction. This remains a
staged integration and is not yet an end-to-end transparent proxy. Validate driver signing, SCM startup,
filter rollback and unload behavior in a disposable Windows 10 x64 VM before
enabling endpoint redirection.

The current classify path requires process-ID metadata but correctly treats
redirect-record metadata as optional for a first-time connection. It queries
redirect state only when a redirect-record handle is present. IPv4 loopback
(127.0.0.0/8), IPv6 loopback (::1), and IPv4-mapped IPv6 loopback
(::ffff:127.0.0.0/104) destinations are passed through unchanged so local IPC
and developer services are not captured by the transparent proxy.
Endpoint ABI v2 now supports the mandatory local redirect-target PID plus up
to eight auxiliary process exclusions. The kernel validates and enforces the
supplied list. Backend lifecycle wiring to populate and refresh Xray/Hysteria2
PIDs is still pending; this ABI support alone does not make those exclusions
active.

The native TCP broker is hosted by the elevated WFP service. Its authenticated
IPC start command returns the actual service PID and dynamically bound IPv4/IPv6
listener ports. ConnectionManager starts and stops the broker with the proxy
runtime. Endpoint activation remains gated on synchronizing the live broker PID,
listener ports, selected backend and core PID exclusions into SET_ENDPOINT_CONFIG.

A production redirect path additionally requires:
- ALE application identity based on the WFP application ID (not PID alone);
- backend endpoint discovery and safe SET/CLEAR endpoint configuration;
- proxy-side WSAIoctl redirect-context and redirect-record propagation;
- backend lifecycle-driven relay/core PID exclusions and restart-safe refresh;
- original-destination preservation and full relay behavior;
- TCP and UDP behavior verified independently;
- IPv4 and IPv6 parity;
- DNS, QUIC, suspend/resume and network-change tests;
- signed package, rollback and uninstall verification.

Hysteria2 and Tun2socks must not advertise application-level routing until their
backend adapters pass the full Windows integration gate. Xray's existing native-TUN
process routing remains independent and must not be silently replaced by WFP.

## Build environment

Use Visual Studio 2022 with the matching Windows 10 SDK and Windows Driver Kit.
Build and test the driver on a disposable Windows 10 x64 VM with test signing.
Never install an experimental callout driver on a production workstation.
