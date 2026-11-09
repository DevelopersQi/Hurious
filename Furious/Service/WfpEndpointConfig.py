"""Build validated WFP endpoint payloads from live broker/runtime state."""

# EXPERIMENTAL: enable WFP UDP application filters for Windows 10 x64
# real-machine validation. Scope is connected UDP sockets handled by ALE
# connect redirection; arbitrary unconnected sendto() capture is not guaranteed.
# Disable this gate again if the end-to-end packet/return-path test fails.
UDP_WFP_REDIRECT_END_TO_END_VERIFIED = True

from Furious.Service.WfpIpcClient import (
    REDIRECT_FLAG_IPV4,
    REDIRECT_FLAG_IPV6,
    REDIRECT_FLAG_TCP,
    REDIRECT_FLAG_UDP,
    pack_endpoint_config,
)


def build_endpoint_config(
    snapshot,
    backend,
    broker_process_id,
    tcp_port_v4,
    tcp_port_v6,
    udp_port_v4=0,
    udp_port_v6=0,
):
    """Serialize a broker endpoint with the current immutable runtime snapshot."""
    excluded_process_ids = tuple(snapshot.excluded_process_ids)
    if not excluded_process_ids:
        raise ValueError("at least one live proxy-core PID must be excluded")

    flags = REDIRECT_FLAG_TCP
    if int(tcp_port_v4):
        flags |= REDIRECT_FLAG_IPV4
    if int(tcp_port_v6):
        flags |= REDIRECT_FLAG_IPV6
    if not flags & (REDIRECT_FLAG_IPV4 | REDIRECT_FLAG_IPV6):
        raise ValueError("the broker must expose at least one TCP listener")

    if int(udp_port_v4) or int(udp_port_v6):
        if bool(tcp_port_v4) != bool(udp_port_v4) or bool(tcp_port_v6) != bool(udp_port_v6):
            raise ValueError("UDP listener families must match the configured TCP families")
        flags |= REDIRECT_FLAG_UDP

    return pack_endpoint_config(
        backend=backend,
        flags=flags,
        proxy_process_id=broker_process_id,
        policy_generation=snapshot.generation,
        tcp_port_v4=tcp_port_v4,
        udp_port_v4=udp_port_v4,
        tcp_port_v6=tcp_port_v6,
        udp_port_v6=udp_port_v6,
        excluded_process_ids=excluded_process_ids,
    )
