# WFP management service

The Windows service executable owns the Furious provider and sublayer in the local
BFE engine. It reports SCM lifecycle state, handles STOP/SHUTDOWN, and attempts
transactional cleanup on normal shutdown.

## Local control channel

The service exposes only the versioned local named pipe
`\\\\.\\pipe\\FuriousWfpService.v2`. Its DACL grants access only to
LocalSystem and the built-in Administrators group, and remote pipe clients are
rejected. Before dispatch, the server impersonates the pipe client, opens the
thread token, and verifies that the caller is LocalSystem or a member of
Administrators. It always attempts to revert impersonation before dispatch.

The server uses message-mode framing, a fixed 512 KiB request bound, and the
shared protocol validator. STATUS validates an empty request. SET_POLICY accepts
a bounded ABI-v1 policy payload, validates its header, generation, backend,
rules, priorities and executable paths, resolves enabled paths to WFP App IDs,
and transactionally replaces the application-specific IPv4/IPv6 TCP filters.
Direct rules install terminating permit filters; Proxy rules install terminating
callout filters. CLEAR_POLICY removes those application filters and empties the
in-memory snapshot. Policy generations must increase monotonically; clearing
does not reset the generation counter.

## Current implementation boundary

SET_POLICY resolves enabled executable paths to WFP application IDs,
sorts rules by ascending numeric priority, rejects duplicate App IDs, and
transactionally replaces per-application TCP filters for IPv4 and IPv6. Direct
rules install terminating permit filters; Proxy rules install terminating
callout filters. CLEAR_POLICY removes those filters and clears the in-memory
snapshots. UDP filters are deliberately withheld until a dedicated UDP relay
has been implemented and tested.

The service clears endpoint configuration at startup. Proxy-action filters fail
closed when no valid endpoint is configured; direct-action filters remain
direct. This avoids silently bypassing the proxy for applications explicitly
selected for Proxy, but also means Proxy rules must not be activated until the
TCP broker endpoint is ready.

The driver endpoint ABI is version 2 and supports up to eight auxiliary process
IDs in addition to the local redirect-target PID. The service-hosted TCP broker
PID is returned by IPC and can occupy the mandatory ProxyProcessId field.
Xray/Hysteria2 core PIDs are available in the Python runtime snapshot, but are
not yet atomically synchronized into endpoint configuration on every
start/stop/restart.

Before enabling traffic filters or redirect:
- resolve each executable path to a canonical WFP application ID;
- verify provider, sublayer and callout ownership before reusing objects;
- package a correctly signed driver beside the service executable and validate
  SCM start/stop behavior under the actual service account;
- connect live backend endpoint discovery and restart-safe Broker/core process
  exclusion refresh to SET_ENDPOINT_CONFIG; clear it whenever the backend exits
  or changes;
- implement the proxy-side WSAIoctl redirect-context/redirect-record relay path;
- implement TCP and UDP separately, with IPv4 and IPv6 parity;
- reconcile stale filters after crashes and ensure safe rollback;
- test allowed and denied client tokens, impersonation failures, malformed
  frames, stop during connect/read, and BFE unavailable;
- validate the full path in a disposable Windows 10 x64 VM.

Do not expose a network listener or install experimental callout drivers on
production machines during development.
