# WFP callout driver

`FuriousWfpCallout.c` implements the kernel callout callbacks for IPv4 and IPv6
`ALE_CONNECT_REDIRECT`. The service management plane installs the matching
WFP provider, sublayer, callout objects, and redirect filters transactionally.
The driver classify path validates endpoint configuration, excludes the
configured local redirect-target PID, checks WFP redirect state, and rewrites
eligible IPv4/IPv6 TCP/UDP connect requests to loopback while preserving the
original destination in the WFP-owned redirect context.

Loopback passthrough covers IPv4 127/8, IPv6 ::1, and IPv4-mapped IPv6
addresses in ::ffff:127/104. This is necessary because applications can reach
the same local endpoint using either native IPv4 or an IPv4-mapped IPv6
destination.

The current PID exclusion is intentionally limited to the local redirect
target (the future broker). It does not yet exclude Xray/Hysteria2 core
processes, and application routing policies are compiled in user mode but are
not yet enforced by the kernel classify path. Therefore this is not yet an
end-to-end transparent proxy.

The source includes the kernel and NDIS headers before FWPS headers, matching
the WDK WFP callout sample header dependencies. The project does not redefine
compiler-reserved kernel macros.

This is a driver binary build target, not a complete installable driver
package. The project currently has no INF/CAT, production signing, installer
package, or tested Windows 10 x64 installation flow.

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
