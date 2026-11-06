# Furious Windows Filtering Platform (WFP)

This directory contains the Windows-only WFP implementation. It is intentionally
separate from the Python UI and proxy-core process lifecycle.

## Components

- `service/`: elevated user-mode service. Owns provider/sublayer/filter lifecycle,
  SCM driver startup, authenticated IPC and policy validation.
- `driver/`: WDK kernel callout driver. Performs bounded, non-blocking classification
  only; it must never perform file, registry, network or user-mode IPC in classify callbacks.
- `include/`: stable policy and control-plane ABI shared by the service and driver.
- `tests/`: Windows integration tests and packet-capture test plans.

## Safety gates

The service now starts the adjacent callout driver through SCM, verifies the
driver ABI/callout registration, and transactionally installs IPv4/IPv6 ALE
connect-redirect filters. The driver still passes traffic through until a live
backend endpoint is configured. The current service does not yet configure a
backend endpoint or provide the proxy-side redirect-context relay, so this is
not yet an end-to-end transparent proxy. Validate driver signing, SCM startup,
filter rollback and unload behavior in a disposable Windows 10 x64 VM before
enabling endpoint redirection.

A production redirect path additionally requires:
- ALE application identity based on the WFP application ID (not PID alone);
- backend endpoint discovery and safe SET/CLEAR endpoint configuration;
- proxy-side WSAIoctl redirect-context and redirect-record propagation;
- redirect-state tracking and explicit relay/core exclusions;
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
