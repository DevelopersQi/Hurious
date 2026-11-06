# WFP management service

The Windows service executable owns the Furious provider and sublayer in the local
BFE engine. It reports SCM lifecycle state, handles STOP/SHUTDOWN, and attempts
transactional cleanup on normal shutdown.

This is an early lifecycle implementation, not a production-ready privileged
service. Before release it still needs:
- an installer that creates the service with least-privilege service ACLs;
- crash recovery and stale-filter reconciliation after abnormal termination;
- authenticated local IPC and strict, versioned request validation;
- driver presence/ABI negotiation and health monitoring;
- integration tests for BFE unavailable, access denied, partial startup and cleanup errors.

Do not expose a network listener. Do not install it on production machines during
development. No traffic filters are added by this milestone.
