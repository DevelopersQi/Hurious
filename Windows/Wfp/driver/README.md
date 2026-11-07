# WFP callout driver

`FuriousWfpCallout.c` implements the kernel callout callbacks for IPv4 and IPv6
`ALE_CONNECT_REDIRECT`. The service management plane installs the matching
WFP provider, sublayer, callout objects, and redirect filters transactionally.
The driver classify path validates endpoint configuration, excludes the
configured local redirect-target PID plus up to eight explicitly supplied
auxiliary process IDs, checks WFP redirect state, and rewrites
eligible IPv4/IPv6 TCP/UDP connect requests to loopback while preserving the
original destination in the WFP-owned redirect context.

Loopback passthrough covers IPv4 127/8, IPv6 ::1, and IPv4-mapped IPv6
addresses in ::ffff:127/104. This is necessary because applications can reach
the same local endpoint using either native IPv4 or an IPv4-mapped IPv6
destination.

The endpoint ABI v2 carries a bounded list of up to eight auxiliary process
IDs in addition to the mandatory local redirect-target PID. The kernel validates
that entries are nonzero, unique, do not duplicate the redirect-target PID, and
that unused slots are zero. The service/backend lifecycle does not yet populate
or refresh this list when Xray/Hysteria2 start, stop, or restart. Application
routing policies are compiled in user mode but are not yet enforced by the
kernel classify path. Therefore this is not yet an
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
The `Quick validation` workflow builds the Release x64 `.sys` against the
Windows 10 target, signs a copy with an ephemeral self-created test certificate,
verifies the embedded Authenticode signature and signer thumbprint, and uploads
a short-lived `furious-wfp-driver-windows10-x64-test-signed` artifact. The
artifact contains the signed `.sys`, public `.cer`, SHA-256 manifest, and
test-only instructions. It does not contain an INF/CAT or installer, and it
does not install or start the driver.

The certificate is not chained to a Microsoft production root. Loading the
test driver requires a compatible disposable Windows 10 x64 test machine with
TESTSIGNING enabled and the public certificate trusted in the appropriate
stores; Secure Boot policy may prevent enabling TESTSIGNING. This test artifact
is not a retail driver package and must never be presented as production-signed.

A successful compiler run proves only that the driver source builds. It does
not prove that the driver loads, registers with the kernel WFP runtime, survives
Driver Verifier, or correctly handles real network traffic. Those checks require
a disposable Windows 10 x64 VM, test-signing configuration, installation and
rollback tests. Do not deploy this bootstrap driver to a production system.


## UDP and flow-identity limitations (must remain gated)

The current driver registers only `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4` and
`FWPS_LAYER_ALE_CONNECT_REDIRECT_V6`. It does **not** register
`ALE_FLOW_ESTABLISHED` callouts, does not call `FwpsFlowAssociateContext`,
and does not attach per-flow state. Consequently:

- UDP redirection at this layer applies only to connection-oriented UDP socket
  operations that pass through ALE connect redirection. It is **not** a
  transparent interception mechanism for arbitrary unconnected
  `sendto()/WSASendTo()` destinations.
- The broker's UDP relay/registry tests prove SOCKS5 UDP association behavior;
  they do not prove that arbitrary Windows UDP traffic is captured by this
  driver or that WFP flow identity is carried into the broker.
- The current `FuriousFlowDelete` callback intentionally has no per-flow
  resource to release. It must not be treated as evidence that flow lifetime
  tracking is implemented.
- Source-address/port tuples alone are not a durable flow identity. A future
  flow-context design must include the WFP flow handle, address family, protocol,
  compartment/interface/scope information where relevant, and a generation-safe
  redirect record. It must define cleanup for flow deletion, process exit,
  service stop, network change, and PID/tuple reuse.
- Do not enable UDP endpoint configuration or install UDP application filters
  until the driver and broker share a tested flow-identity contract and the
  unconnected UDP path is explicitly covered (or explicitly excluded in product
  behavior and UI).

A successful WDK build and the current SOCKS5 UDP unit/integration tests do not
change these limitations. Real Windows 10 x64 packet-capture tests are still
required before enabling any production redirect gate.
