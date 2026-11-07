# WFP TCP broker primitives

This directory contains the native TCP redirect primitives and the service-hosted
long-running broker.

## Implemented primitives

- Query the opaque WFP redirect-record chain from an accepted redirected socket.
- Query and strictly validate the 64-byte Furious redirect context.
- Recover the original IPv4/IPv6 destination without string parsing.
- Re-apply the opaque redirect-record chain to a new socket before connect.
- Negotiate a no-auth SOCKS5 session and issue a binary IPv4/IPv6 CONNECT.
- Reject authenticated Xray/Hysteria2 SOCKS inbounds; username/password negotiation is not implemented yet.
- Relay TCP data in both directions with half-close support and an idle timeout.
- Bind IPv4 and IPv6 loopback listeners on dynamically assigned ports, keeping an available family active if the other is disabled by the host.
- Bound queued and active sessions, with worker threads and coordinated shutdown.
- Restrict the local SOCKS upstream to loopback addresses and bound handshake waits.

The code deliberately never opens a direct socket to the original destination.
The only upstream connection it creates is to the configured local SOCKS5
inbound, so traffic continues through the selected Xray/Hysteria2 backend.
Hysteria2 requires an explicit `socks5.listen` endpoint in its client config.

## Important integration boundary

The broker listener is hosted by the elevated WFP service and controlled through
authenticated IPC. ConnectionManager starts and stops it with the proxy runtime,
then publishes its actual PID, dynamically bound listener ports, selected backend
and current core PID exclusions through SET_ENDPOINT_CONFIG. The full redirect
path still requires Windows integration tests and a signed driver package.

The redirect-record blob is opaque and is copied without interpretation. The
context is Furious-owned ABI data and is validated before its address and port
are used. No redirect endpoint or listener is enabled by this library alone.


## UDP relay preparation (parser only)

- Parse SOCKS5 UDP datagrams with strict RSV, FRAG, ATYP, address-length and nonzero-port validation.
- Expose a non-owning payload/address view for IPv4, IPv6 and domain targets; the caller retains buffer ownership.
- Reject fragmented datagrams until bounded fragment reassembly is implemented.
- This parser is not a UDP relay: it performs no DNS resolution, socket forwarding, association management, or WFP UDP redirection. UDP remains disabled at the IPC boundary.


## UDP association resource guard (not yet wired to sockets)

- Maintain a bounded registry of SOCKS5 UDP associations with unique IDs.
- Enforce a global association ceiling and a per-control-peer-IP ceiling; the per-peer key ignores ephemeral TCP ports.
- Reclaim idle associations through an explicit monotonic-clock sweep, and remove an association immediately when its control session closes.
- Enforce per-association datagram-size limits through the existing association state guard.
- This manager is currently a tested policy primitive only. It is not yet connected to TCP control-session handling or UDP sockets, and UDP remains disabled at the IPC/WFP boundary.


## UDP socket ownership primitive

- Each future association can own a dedicated IPv4 or IPv6 UDP socket, bound to the matching wildcard address and an OS-assigned ephemeral port.
- Socket ownership is RAII-based; close is idempotent and failure paths close partially initialized sockets.
- Sockets are nonblocking, use exclusive address binding, and request bounded 64 KiB send/receive buffers.
- The hosting service owns Winsock initialization. The socket wrapper intentionally does not call WSAStartup or WSACleanup.
- This is a socket lifecycle primitive only: no datagram receive/send loop, DNS resolution, remote endpoint forwarding, or WFP UDP filter is enabled yet.


The association registry is internally synchronized so control-session workers and a periodic expiry sweep can safely share it. Validated client datagrams and accepted relay responses refresh the same monotonic idle timer; stale associations are removed on access or by the sweep.


## WFP non-TCP redirect-record handling

- Windows delivers the redirect record for a non-TCP flow on the flow-creating datagram as an ancillary `IP_CONNECTION_REDIRECT_RECORD` control message.
- The broker resolves the Winsock `WSARecvMsg` and `WSASendMsg` extension functions, extracts and bounds both first-packet redirect records and callout context, and can attach both to the corresponding outbound UDP message.
- Subsequent datagrams are allowed to omit the record; duplicate, malformed, empty, and oversized records are rejected.
- This is the ancillary-data protocol layer only. It does not yet create UDP flow mappings, forward payloads to Xray/Hysteria2, or enable UDP WFP filters.


The receive helper now captures the source endpoint, payload, redirect-record ancillary data, and redirect-context ancillary data from a single `WSARecvMsg` operation. It rejects truncated payload/control data and malformed metadata before exposing a packet to the relay layer. Loopback tests cover receive, source capture, extension resolution, and nonblocking `WSAEWOULDBLOCK`.


The UDP ancillary context decoder validates the shared redirect ABI, exact structure size, magic/version, reserved fields, original endpoint fields, policy generation, and UDP protocol before exposing original destination and originating process metadata. TCP-tagged, malformed, or truncated contexts are rejected.


## WFP UDP flow table

- Create a flow only from the first redirected datagram carrying a non-empty WFP redirect record and a valid UDP redirect context.
- Key the flow by the client's local source endpoint (IPv4 or IPv6, including IPv6 scope ID); retain the validated original destination, process ID, policy generation, and redirect record.
- Reject invalid/non-unicast source and target endpoints, source-endpoint identity conflicts, missing metadata, and malformed context.
- Enforce global and per-process flow ceilings with a synchronized registry and monotonic idle expiry.
- Later datagrams can resolve the existing flow by source endpoint; the table does not yet forward packets or open upstream proxy sockets.


The SOCKS5 UDP ASSOCIATE reply parser now validates the upstream relay's IPv4, IPv6, or domain endpoint, nonzero port, reply status, reserved byte, and exact message length. It returns a non-owning address view for the upcoming upstream association client.


## Upstream SOCKS5 UDP association client

- Opens a loopback-only TCP control connection to the selected local SOCKS5 core.
- Negotiates no-auth SOCKS5 and sends UDP ASSOCIATE with the broker-owned UDP socket's loopback address and ephemeral port.
- Parses the server relay endpoint and substitutes the local SOCKS server address when the server reports an unspecified bind address.
- Rejects non-loopback relay endpoints and address-family mismatches to prevent accidental external relay targets.
- Keeps the TCP control socket open for the UDP association lifetime, supports cancellation registration, and detects peer closure without blocking.
- A fake local SOCKS5 server test validates the handshake, advertised UDP port, relay endpoint selection, and control-channel teardown.


## Per-flow SOCKS5 UDP bridge (implemented, not activated)

- A flow bridge owns one wildcard-bound ephemeral UDP socket and one loopback-only upstream SOCKS5 UDP ASSOCIATE control connection.
- Each client payload is wrapped with the original destination address and port from the validated WFP redirect context, then sent only to the negotiated relay endpoint.
- Relay responses are accepted only from that exact relay endpoint and only when the SOCKS5 response source address/port matches the original WFP destination.
- The original client endpoint and opaque WFP redirect record/context are retained so the response can be sent back with the correct source identity through the redirected ingress socket.
- IPv4/IPv6 endpoints are validated; unspecified, multicast and invalid source endpoints are rejected. IPv6 WFP ancillary metadata uses the IPv6 protocol level.
- Local fake-SOCKS tests cover association handshake, payload forwarding, mismatched response destination rejection, and deterministic control/socket teardown.
- The bridge is a tested primitive only. It is not yet hosted by a UDP broker listener or connected to the WFP flow table/IPC endpoint. UDP filters remain disabled.
