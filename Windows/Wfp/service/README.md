# WFP management service

The Windows service executable owns the Furious provider and sublayer in the local
BFE engine. It reports SCM lifecycle state, handles STOP/SHUTDOWN, and attempts
transactional cleanup on normal shutdown.

## Local control channel

The service exposes only the versioned local named pipe
`\\\\.\\pipe\\FuriousWfpService.v1`. Its DACL grants access only to
LocalSystem and the built-in Administrators group, and remote pipe clients are
rejected. Before dispatch, the server impersonates the pipe client, opens the
thread token, and verifies that the caller is LocalSystem or a member of
Administrators. It always attempts to revert impersonation before dispatch.

The server uses message-mode framing, a fixed 64 KiB request bound, and the
shared protocol validator. STATUS validates an empty request. SET_POLICY accepts
a bounded ABI-v1 policy payload, validates its header, generation, backend,
rules, priorities and executable paths, then atomically replaces the in-memory
policy snapshot. CLEAR_POLICY empties the snapshot. Policy generations must
increase monotonically; clearing does not reset the generation counter.

## Current implementation boundary

Policy data is now accepted and stored by the service, but it is **not yet
compiled into WFP application-ID filters**, and no traffic is blocked or
redirected. The driver remains a pass-through ALE callout and is not loaded by
the service. Do not treat policy acceptance as application routing being active.

Before enabling traffic filters or redirect:
- resolve each executable path to a canonical WFP application ID;
- verify provider, sublayer and callout ownership before reusing objects;
- load and negotiate the driver ABI and register matching management callouts;
- implement redirect-state tracking, original-destination preservation and
  explicit proxy/core exclusions;
- implement TCP and UDP separately, with IPv4 and IPv6 parity;
- reconcile stale filters after crashes and ensure safe rollback;
- test allowed and denied client tokens, impersonation failures, malformed
  frames, stop during connect/read, and BFE unavailable;
- validate the full path in a disposable Windows 10 x64 VM.

Do not expose a network listener or install experimental callout drivers on
production machines during development.
