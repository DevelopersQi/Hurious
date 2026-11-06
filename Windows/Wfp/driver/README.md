# WFP callout driver bootstrap

`FuriousWfpCallout.c` is a minimal WDK callout-registration bootstrap for the IPv4 and IPv6
`ALE_CONNECT_REDIRECT` layers. The classify callback now validates endpoint configuration, excludes the configured
proxy PID, checks WFP redirect state, and rewrites eligible IPv4/IPv6 TCP/UDP
connect requests to loopback while preserving the original destination in the
WFP-owned redirect context. The service still does not install a WFP filter,
so this classify path is not yet reachable for ordinary traffic.

The source includes the kernel and NDIS headers before FWPS headers, matching the WDK WFP callout sample header dependencies. The project does not redefine compiler-reserved kernel macros.

The redirect callback is a code path only; until the service installs matching
management-plane and runtime filters, it does not intercept normal traffic. This
is a driver binary build target, not a complete installable driver package. The project currently has no INF/CAT, production signing,
installer/service registration, or tested Windows 10 x64 installation flow.

## Reproducible CI build

The root `packages.config` pins the Windows SDK and WDK NuGet packages to
10.0.28000.2526. `Directory.Build.props` imports the x64 WDK build integration.
The `windows-wfp-driver-build` workflow job builds the Release x64 `.sys`
against the Windows 10 target and uploads the unsigned binary as a short-lived
CI artifact.

A successful compiler run proves only that the driver source builds. It does
not prove that the driver loads, registers with the kernel WFP runtime, survives
Driver Verifier, or correctly handles real network traffic. Those checks require
a disposable Windows 10 x64 VM, test-signing configuration, installation and
rollback tests. Do not deploy this bootstrap driver to a production system.
