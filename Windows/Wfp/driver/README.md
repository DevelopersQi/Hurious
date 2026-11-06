# WFP callout driver bootstrap

`FuriousWfpCallout.c` is a minimal WDK callout-registration bootstrap for
`FWPM_LAYER_ALE_AUTH_CONNECT_V4`. It intentionally does not install a WFP filter,
block traffic, redirect sockets, or communicate with a user-mode process.

The classify callback returns `FWP_ACTION_CONTINUE`, preserving normal Windows
filter evaluation. This source is not a complete driver package: a WDK project,
INF/CAT, signing configuration, service registration and Windows 10 x64 test
installation are still required.

Do not deploy this bootstrap driver to a production system.
