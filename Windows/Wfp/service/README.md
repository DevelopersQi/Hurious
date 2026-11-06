# WFP management service

The Windows service executable owns the Furious provider and sublayer in the local
BFE engine. It reports SCM lifecycle state, handles STOP/SHUTDOWN, and attempts
transactional cleanup on normal shutdown.

## Local control channel

The service exposes only the versioned local named pipe
`\\\\.\\pipe\\FuriousWfpService.v1`. Its DACL grants access only to
LocalSystem and the built-in Administrators group, and remote pipe clients are
rejected. Before reading a request, the server impersonates the pipe client,
opens the thread token, and verifies that the caller is LocalSystem or a member
of Administrators. It always attempts to revert impersonation before dispatch.

The server uses message-mode framing, a fixed 64 KiB request bound, and the
shared protocol validator. STATUS is currently the only implemented operation.
SET_POLICY and CLEAR_POLICY return ERROR_NOT_SUPPORTED; no policy is installed
and no traffic is redirected. The server's worker polls nonblocking reads so a
connected but idle local client cannot indefinitely block service shutdown.

This is an initial authenticated control-channel implementation, not a
production-ready privileged service. The current automated tests compile the
Windows x64 service and exercise protocol validation and command dispatch; they
do not yet perform end-to-end named-pipe token/ACL integration tests. Before
release it still needs:
- an installer that creates the service with least-privilege service ACLs;
- integration tests for allowed and denied client tokens, impersonation failure,
  malformed frames, stop during connect/read, and BFE unavailable;
- crash recovery and stale-filter reconciliation after abnormal termination;
- driver presence/ABI negotiation and health monitoring;
- strict policy payload validation before any future policy mutation;
- driver package signing, installation, rollback and Windows 10 x64 VM tests.

Do not expose a network listener. Do not install it on production machines during
development. No WFP traffic filters are added by this milestone.
