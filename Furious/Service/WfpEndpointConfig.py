"""Build validated WFP endpoint payloads from live broker/runtime state."""

from Furious.Service.WfpIpcClient import (
    REDIRECT_FLAG_IPV4,
    REDIRECT_FLAG_IPV6,
    REDIRECT_FLAG_TCP,
    pack_endpoint_config,
)


def build_endpoint_config(
    snapshot,
    backend,
    broker_process_id,
    tcp_port_v4,
    tcp_port_v6,
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

    return pack_endpoint_config(
        backend=backend,
        flags=flags,
        proxy_process_id=broker_process_id,
        policy_generation=snapshot.generation,
        tcp_port_v4=tcp_port_v4,
        tcp_port_v6=tcp_port_v6,
        excluded_process_ids=excluded_process_ids,
    )
