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
The broker obtains original-destination context, preserves WFP redirect records,
connects to a loopback SOCKS5 no-auth inbound, and relays TCP streams. Authenticated
SOCKS inbounds are rejected until username/password negotiation is implemented.
ConnectionManager
starts/stops the broker and publishes its real PID, dynamically bound TCP ports,
selected Xray/Hysteria2 backend and current core PID exclusions through
SET_ENDPOINT_CONFIG. The end-to-end path still requires Windows 10 x64 runtime
validation and a signed driver package. Validate driver signing, SCM startup,
filter rollback and unload behavior in a disposable Windows 10 x64 VM before
enabling endpoint redirection.

The current classify path requires process-ID metadata but correctly treats
redirect-record metadata as optional for a first-time connection. It queries
redirect state only when a redirect-record handle is present. IPv4 loopback
(127.0.0.0/8), IPv6 loopback (::1), and IPv4-mapped IPv6 loopback
(::ffff:127.0.0.0/104) destinations are passed through unchanged so local IPC
and developer services are not captured by the transparent proxy.
Endpoint ABI v2 supports the mandatory local redirect-target PID plus up to
eight auxiliary process exclusions. ConnectionManager refreshes the exclusion
snapshot on proxy-core lifecycle changes and clears endpoint state before
stopping a changed core. The service fails closed for Proxy-selected applications
when a valid endpoint is unavailable.

The native TCP broker is hosted by the elevated WFP service. Its authenticated
IPC start command returns the actual service PID and dynamically bound IPv4/IPv6
listener ports. ConnectionManager starts and stops the broker with the proxy
runtime, then sends those values and the current core PID snapshot to
SET_ENDPOINT_CONFIG. Only TCP application filters are installed; UDP remains
disabled until a dedicated UDP relay exists.

WFP application routing is used only when system TUN mode is disabled. In
full-tunnel mode, WFP Direct permits cannot bypass the installed TUN default
route; Xray Native TUN continues to use its own process-routing rules. The
current WFP UI accepts full executable paths and applies Proxy/Direct policy
through the active Xray or Hysteria2 SOCKS inbound. Only TCP is supported.

A production redirect path additionally requires:
- finish UI translation and validate policy changes/rollback for Proxy/Direct rules;
- service/driver installation, endpoint activation and rollback verified on
  Windows 10 x64;
- restart, crash, PID reuse and stale endpoint recovery verified;
- TCP behavior verified independently on IPv4 and IPv6;
- a dedicated UDP relay and UDP behavior verified before enabling UDP filters;
- IPv4 and IPv6 parity;
- DNS, QUIC, suspend/resume and network-change tests;
- signed package, rollback and uninstall verification.

Hysteria2 supports WFP TCP application routing only when system TUN mode is
disabled. Hysteria2 Native TUN and Tun2socks full-tunnel modes do not use WFP
Direct/Proxy application rules yet. Xray's existing native-TUN process routing
remains independent and must not be silently replaced by WFP.

## Build environment

Use Visual Studio 2022 with the matching Windows 10 SDK and Windows Driver Kit.
Build and test the driver on a disposable Windows 10 x64 VM with test signing.
Never install an experimental callout driver on a production workstation.
