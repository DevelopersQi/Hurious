# Furious Windows Filtering Platform (WFP)

This directory contains the Windows-only WFP implementation. It is intentionally
separate from the Python UI and proxy-core process lifecycle.

## Components

- `service/`: elevated user-mode service. Owns provider/sublayer/filter lifecycle,
  authenticated IPC, policy validation, health monitoring and crash recovery.
- `driver/`: WDK kernel callout driver. Performs bounded, non-blocking classification
  only; it must never perform file, registry, network or user-mode IPC in classify callbacks.
- `include/`: stable policy and control-plane ABI shared by the service and driver.
- `tests/`: Windows integration tests and packet-capture test plans.

## Safety gates

The first driver increment must be pass-through only. Do not install redirecting or
blocking filters until the service/driver ABI, unload cleanup, boot recovery and
Windows 10 x64 test-signing workflow have been verified.

A production redirect path additionally requires:
- ALE application identity based on the WFP application ID (not PID alone);
- redirect-state tracking and explicit relay/core exclusions;
- original-destination preservation;
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
