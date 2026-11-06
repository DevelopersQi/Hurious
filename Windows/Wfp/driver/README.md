# WFP callout driver bootstrap

`FuriousWfpCallout.c` is a minimal WDK callout-registration bootstrap for
`FWPM_LAYER_ALE_AUTH_CONNECT_V4`. It intentionally does not install a WFP filter,
block traffic, redirect sockets, or communicate with a user-mode process.

The classify callback returns `FWP_ACTION_CONTINUE`, preserving normal Windows
filter evaluation. This is a driver binary build target, not a complete installable
driver package. The project currently has no INF/CAT, production signing,
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
