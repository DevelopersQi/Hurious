# WFP TCP broker primitives

This directory contains the native TCP redirect primitives used by the future
long-running broker service.

## Implemented primitives

- Query the opaque WFP redirect-record chain from an accepted redirected socket.
- Query and strictly validate the 64-byte Furious redirect context.
- Recover the original IPv4/IPv6 destination without string parsing.
- Re-apply the opaque redirect-record chain to a new socket before connect.
- Negotiate a no-auth SOCKS5 session and issue a binary IPv4/IPv6 CONNECT.
- Relay TCP data in both directions with half-close support and an idle timeout.

The code deliberately never opens a direct socket to the original destination.
The only upstream connection it creates is to the configured local SOCKS5
inbound, so traffic continues through the selected Xray/Hysteria2 backend.

## Important integration boundary

These primitives are not yet a complete broker service. A subsequent layer
must own IPv4/IPv6 listeners, bounded concurrent sessions, graceful shutdown,
backend inbound discovery, and publication of the real broker PID and listener
ports to the WFP service. Until that layer exists and passes Windows tests,
the SET_ENDPOINT_CONFIG command must remain disabled.

The redirect-record blob is opaque and is copied without interpretation. The
context is Furious-owned ABI data and is validated before its address and port
are used. No redirect endpoint or listener is enabled by this library alone.
