"""Network helpers shared by the edge tokenizer and the graph scorer."""

import ipaddress
from typing import Union

INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]


def is_internal(address: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """True for RFC 1918 and IPv6 unique-local addresses, i.e. hosts inside the organization.

    `ipaddress.is_private` is deliberately not used: it also covers documentation, loopback and other reserved ranges
    (for example 203.0.113.0/24), which are not the organization's own hosts and must not be pseudonymized as if they were.
    """
    try:
        addr = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(addr in net for net in INTERNAL_NETWORKS if net.version == addr.version)
