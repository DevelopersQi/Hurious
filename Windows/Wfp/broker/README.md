# WFP TCP broker primitives

This directory contains the native TCP redirect primitives and the service-hosted
long-running broker.

## Implemented primitives

- Query the opaque WFP redirect-record chain from an accepted redirected socket.
- Query and strictly validate the 64-byte Furious redirect context.
- Recover the original IPv4/IPv6 destination without string parsing.
- Re-apply the opaque redirect-record chain to a new socket before connect.
- Negotiate a no-auth SOCKS5 session and issue a binary IPv4/IPv6 CONNECT.
- Relay TCP data in both directions with half-close support and an idle timeout.
- Bind IPv4 and IPv6 loopback listeners on dynamically assigned ports, keeping an available family active if the other is disabled by the host.
- Bound queued and active sessions, with worker threads and coordinated shutdown.
- Restrict the local SOCKS upstream to loopback addresses and bound handshake waits.

The code deliberately never opens a direct socket to the original destination.
The only upstream connection it creates is to the configured local SOCKS5
inbound, so traffic continues through the selected Xray/Hysteria2 backend.

## Important integration boundary

The broker listener is hosted by the elevated WFP service and controlled through
authenticated IPC. ConnectionManager starts and stops it with the proxy runtime,
then publishes its actual PID, dynamically bound listener ports, selected backend
and current core PID exclusions through SET_ENDPOINT_CONFIG. The full redirect
path still requires Windows integration tests and a signed driver package.

The redirect-record blob is opaque and is copied without interpretation. The
context is Furious-owned ABI data and is validated before its address and port
are used. No redirect endpoint or listener is enabled by this library alone.
