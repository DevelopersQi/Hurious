Furious WFP test package
========================

This folder contains the Windows 10 x64 WFP user-mode service, matching
kernel callout driver, self-signed test certificate, and elevated install
and uninstall scripts.

TEST-ONLY: the certificate is not chained to a Microsoft production root.
Installation requires Windows 10 x64 test-signing mode. The installer
requests TESTSIGNING and a reboot when needed. Secure Boot policy may reject
that change. It never disables Secure Boot or Memory Integrity.

Run Install-WfpTest.ps1 from the extracted package. The script self-elevates,
installs the certificate into LocalMachine Root and TrustedPublisher, copies
the service and driver to Program Files, and registers the service. If a
reboot is required, the service is configured to start after the next boot.
Run Uninstall-WfpTest.ps1 to remove the service, driver service entry, and
test certificate. TESTSIGNING is deliberately left unchanged because it is
a system-wide setting that may be used by other test drivers.

WFP application routing in this test build enables TCP and experimental UDP
filters. UDP is limited to connected socket operations reaching ALE connect
redirection; arbitrary unconnected sendto/WSASendTo capture is not guaranteed.
Real Windows 10 driver load/unload, rollback, IPv4/IPv6 traffic, crash recovery,
Driver Verifier, and actual proxy traffic validation are still required.

SHA-256 manifests are provided for the driver and service binaries.
