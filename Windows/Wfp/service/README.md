# WFP management service

The Windows service executable owns the Furious provider and sublayer in the local
BFE engine. It reports SCM lifecycle state, handles STOP/SHUTDOWN, and attempts
transactional cleanup on normal shutdown.

The shared `include/WfpControlProtocol.h` defines a pointer-free, versioned IPC
message header and bounded request validator. It is a protocol contract only:
there is not yet a named-pipe server, client authentication, command dispatch or
policy application. A future transport must use a restrictive local pipe ACL,
verify the connecting process token, enforce message framing and reject malformed
or oversized payloads before dispatch.

This is an early lifecycle implementation, not a production-ready privileged
service. Before release it still needs:
- an installer that creates the service with least-privilege service ACLs;
- crash recovery and stale-filter reconciliation after abnormal termination;
- authenticated local IPC and strict, versioned request dispatch;
- driver presence/ABI negotiation and health monitoring;
- integration tests for BFE unavailable, access denied, partial startup and cleanup errors.

Do not expose a network listener. Do not install it on production machines during
development. No traffic filters are added by this milestone.
